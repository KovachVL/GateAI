package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/KovachVL/GateAI/internal/codeview"
	"github.com/KovachVL/GateAI/internal/finding"
	"github.com/KovachVL/GateAI/internal/verdict"
)

type readFileInput struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

type searchInput struct {
	Pattern string `json:"pattern"`
	Glob    string `json:"glob"`
}

type symbolInput struct {
	Symbol string `json:"symbol"`
}

type verdictInput struct {
	Verdict          string   `json:"verdict"`
	Confidence       float64  `json:"confidence"`
	AdjustedSeverity string   `json:"adjusted_severity"`
	Reasoning        string   `json:"reasoning"`
	Evidence         []string `json:"evidence"`
	Reachable        bool     `json:"reachable"`
	ExploitSketch    string   `json:"exploit_sketch"`
	SuggestedFix     string   `json:"suggested_fix"`
}

type capture struct {
	verdict *verdictInput
	calls   int
}

type handler func(ctx context.Context, raw json.RawMessage) string

type toolset struct {
	defs     []anthropic.BetaToolUnionParam
	handlers map[string]handler
	capture  *capture
}

func (ts *toolset) dispatch(ctx context.Context, name string, raw json.RawMessage) string {
	h, ok := ts.handlers[name]
	if !ok {
		return fmt.Sprintf("error: unknown tool %q", name)
	}
	return h(ctx, raw)
}

func schema(props map[string]any, required ...string) anthropic.BetaToolInputSchemaParam {
	return anthropic.BetaToolInputSchemaParam{
		Properties:  props,
		Required:    required,
		ExtraFields: map[string]any{"additionalProperties": false},
	}
}

func str(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func integer(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func def(name, description string, s anthropic.BetaToolInputSchemaParam, strict bool) anthropic.BetaToolUnionParam {
	p := &anthropic.BetaToolParam{
		Name:        name,
		Description: anthropic.String(description),
		InputSchema: s,
	}
	if strict {
		p.Strict = anthropic.Bool(true)
	}
	return anthropic.BetaToolUnionParam{OfTool: p}
}

func decode[T any](raw json.RawMessage) (T, error) {
	var v T
	err := json.Unmarshal(raw, &v)
	return v, err
}

func buildToolset(view *codeview.View) *toolset {
	cap := &capture{}

	ts := &toolset{
		capture:  cap,
		handlers: map[string]handler{},
	}

	ts.defs = append(ts.defs, def("read_file",
		"Read a range of lines from a file in the repository, with line numbers. Use this to see the code around a finding and the code on a call path.",
		schema(map[string]any{
			"path":       str("Repository-relative path to read."),
			"start_line": integer("First line to read (1-based). Use 1 to start at the top."),
			"end_line":   integer("Last line to read. Max 400 lines per call. Use 0 for start_line+399."),
		}, "path", "start_line", "end_line"), true))
	ts.handlers["read_file"] = func(ctx context.Context, raw json.RawMessage) string {
		in, err := decode[readFileInput](raw)
		if err != nil {
			return "error: " + err.Error()
		}
		out, err := view.ReadFile(in.Path, in.StartLine, in.EndLine)
		if err != nil {
			return "error: " + err.Error()
		}
		return wrapUntrusted(out)
	}

	ts.defs = append(ts.defs, def("search_code",
		"Search the repository with an RE2 regular expression. Returns up to 60 matches as file:line plus the matching line. Use it to find call sites, imports, configuration and sanitizers.",
		schema(map[string]any{
			"pattern": str("RE2 regular expression."),
			"glob":    str("Shell glob restricting which files are searched, e.g. '*.go'. Empty string searches everything."),
		}, "pattern", "glob"), true))
	ts.handlers["search_code"] = func(ctx context.Context, raw json.RawMessage) string {
		in, err := decode[searchInput](raw)
		if err != nil {
			return "error: " + err.Error()
		}
		ms, err := view.Search(in.Pattern, in.Glob)
		if err != nil {
			return "error: " + err.Error()
		}
		return wrapUntrusted(formatMatches(ms, "no matches"))
	}

	symSchema := schema(map[string]any{
		"symbol": str("Function, method or type name. Qualified names like 'pkg/mod.Parse' are accepted; only the final identifier is used."),
	}, "symbol")

	ts.defs = append(ts.defs, def("find_definition",
		"Find where a function, method, class or type is declared. Pattern-based and language-agnostic, so expect some false positives.",
		symSchema, true))
	ts.handlers["find_definition"] = func(ctx context.Context, raw json.RawMessage) string {
		in, err := decode[symbolInput](raw)
		if err != nil {
			return "error: " + err.Error()
		}
		ms, err := view.FindDefinition(in.Symbol)
		if err != nil {
			return "error: " + err.Error()
		}
		return wrapUntrusted(formatMatches(ms, "no definition found"))
	}

	ts.defs = append(ts.defs, def("find_callers",
		"Find call sites of a function or method. This is a text search, so it misses dynamic dispatch, reflection and framework-routed calls — absence of results is not proof the code is unreachable.",
		symSchema, true))
	ts.handlers["find_callers"] = func(ctx context.Context, raw json.RawMessage) string {
		in, err := decode[symbolInput](raw)
		if err != nil {
			return "error: " + err.Error()
		}
		ms, err := view.FindCallers(in.Symbol)
		if err != nil {
			return "error: " + err.Error()
		}
		return wrapUntrusted(formatMatches(ms, "no call sites found by text search"))
	}

	ts.defs = append(ts.defs, def("list_entrypoints",
		"List candidate attacker-reachable entry points: main functions, HTTP route registrations, framework handlers, CLI argument reads, serverless handlers.",
		schema(map[string]any{}), true))
	ts.handlers["list_entrypoints"] = func(ctx context.Context, raw json.RawMessage) string {
		ms, err := view.Entrypoints()
		if err != nil {
			return "error: " + err.Error()
		}
		return wrapUntrusted(formatMatches(ms, "no entry points detected"))
	}

	ts.defs = append(ts.defs, def("submit_verdict",
		"Submit your final triage decision. Call this exactly once, after you have investigated with the other tools.",
		schema(map[string]any{
			"verdict": map[string]any{
				"type":        "string",
				"enum":        []string{"exploitable", "not_exploitable", "needs_human"},
				"description": "exploitable: attacker-controlled input reaches the sink on a reachable path with no adequate mitigation. not_exploitable: you verified it cannot be triggered. needs_human: you could not verify either way.",
			},
			"confidence": map[string]any{
				"type":        "number",
				"description": "Between 0.0 and 1.0 inclusive. Below 0.7 means you are guessing; prefer needs_human.",
			},
			"adjusted_severity": map[string]any{
				"type":        "string",
				"enum":        []string{"critical", "high", "medium", "low", "info"},
				"description": "Severity given what you found in this codebase, which may differ from the scanner's.",
			},
			"reasoning": str("Why. Reference the specific code you read. Two to six sentences of plain prose — no markup, no tags."),
			"evidence": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Locations backing your reasoning, each as 'path/to/file.ext:line'. Every load-bearing claim needs one. An empty list forces the verdict to needs_human.",
			},
			"reachable":      map[string]any{"type": "boolean", "description": "Whether you traced a path from an attacker-controlled entry point to this code."},
			"exploit_sketch": str("If exploitable: what an attacker sends and what happens. Empty string otherwise."),
			"suggested_fix":  str("Concrete fix, ideally the changed line or the version to upgrade to. Empty string if none."),
		}, "verdict", "confidence", "adjusted_severity", "reasoning", "evidence", "reachable", "exploit_sketch", "suggested_fix"), true))
	ts.handlers["submit_verdict"] = func(ctx context.Context, raw json.RawMessage) string {
		cap.calls++
		if cap.verdict != nil {
			return "a verdict was already submitted for this finding; the first one stands"
		}
		in, err := decode[verdictInput](raw)
		if err != nil {
			return "error: could not parse the verdict: " + err.Error()
		}
		cap.verdict = &in
		return "verdict recorded"
	}

	return ts
}

func wrapUntrusted(s string) string {
	return "===== BEGIN UNTRUSTED REPOSITORY CONTENT =====\n" + s +
		"\n===== END UNTRUSTED REPOSITORY CONTENT ====="
}

func formatMatches(ms []codeview.Match, empty string) string {
	if len(ms) == 0 {
		return empty
	}
	var b strings.Builder
	for _, m := range ms {
		fmt.Fprintf(&b, "%s:%d: %s\n", m.File, m.Line, m.Text)
	}
	if len(ms) >= 60 {
		b.WriteString("(results truncated at 60 matches — narrow the pattern or glob)\n")
	}
	return b.String()
}

func toVerdict(in *verdictInput, f *finding.Finding) verdict.Verdict {
	v := verdict.Verdict{
		FindingID:        f.ID,
		Kind:             verdict.Kind(in.Verdict),
		Confidence:       in.Confidence,
		AdjustedSeverity: finding.Severity(in.AdjustedSeverity).Normalize(),
		Reasoning:        in.Reasoning,
		Evidence:         in.Evidence,
		ExploitSketch:    in.ExploitSketch,
		SuggestedFix:     in.SuggestedFix,
		Finding:          f,
	}
	reachable := in.Reachable
	v.Reachable = &reachable
	return v
}

var (
	paramBlockRe = regexp.MustCompile(`(?s)<\s*parameter\s+name\s*=\s*"([a-z_]+)"\s*>(.*?)(?:<\s*/\s*parameter\s*>|$)`)
	strayTagRe   = regexp.MustCompile(`(?s)<\s*/?\s*(?:antml|parameter|invoke|function_calls|reasoning|evidence|exploit_sketch|suggested_fix|verdict)[^>]{0,120}>`)
)

func isPlaceholder(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "n/a", "na", "none", "null", "-":
		return true
	}
	return false
}

func repairVerdict(in *verdictInput) bool {
	repaired := false

	assign := func(field, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		switch field {
		case "reasoning":
			if isPlaceholder(in.Reasoning) {
				in.Reasoning = value
				repaired = true
			}
		case "exploit_sketch":
			if isPlaceholder(in.ExploitSketch) {
				in.ExploitSketch = value
				repaired = true
			}
		case "suggested_fix":
			if isPlaceholder(in.SuggestedFix) {
				in.SuggestedFix = value
				repaired = true
			}
		}
	}

	extract := func(s *string) {
		for _, m := range paramBlockRe.FindAllStringSubmatch(*s, -1) {
			assign(m[1], m[2])
		}
		if paramBlockRe.MatchString(*s) {
			*s = paramBlockRe.ReplaceAllString(*s, "")
			repaired = true
		}
	}

	extract(&in.Reasoning)
	extract(&in.ExploitSketch)
	extract(&in.SuggestedFix)

	clean := func(s *string) {
		if strayTagRe.MatchString(*s) {
			*s = strayTagRe.ReplaceAllString(*s, "")
			repaired = true
		}
		*s = strings.TrimSpace(*s)
	}
	clean(&in.Reasoning)
	clean(&in.ExploitSketch)
	clean(&in.SuggestedFix)

	for i, e := range in.Evidence {
		before := e
		e = strayTagRe.ReplaceAllString(e, "")
		in.Evidence[i] = strings.TrimSpace(e)
		if in.Evidence[i] != before {
			repaired = true
		}
	}

	if isPlaceholder(in.ExploitSketch) {
		in.ExploitSketch = ""
	}
	if isPlaceholder(in.SuggestedFix) {
		in.SuggestedFix = ""
	}
	return repaired
}
