package triage

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/KovachVL/GateAI/internal/codeview"
)

var unsupportedInStrictSchemas = []string{
	"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
	"minLength", "maxLength", "pattern", "minItems", "maxItems", "uniqueItems",
}

func TestToolSchemasAreStrictCompatible(t *testing.T) {
	view, err := codeview.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := buildToolset(view)

	if len(ts.defs) != len(ts.handlers) {
		t.Errorf("%d tool definitions but %d handlers", len(ts.defs), len(ts.handlers))
	}

	for _, d := range ts.defs {
		tool := d.OfTool
		if tool == nil {
			t.Fatal("tool definition is not a custom tool")
		}
		if !tool.Strict.Valid() || !tool.Strict.Value {
			t.Errorf("%s: strict is not set; the API will not enforce the schema", tool.Name)
		}
		if ts.handlers[tool.Name] == nil {
			t.Errorf("%s: declared to the model but has no handler", tool.Name)
		}

		raw, err := json.Marshal(tool.InputSchema.Properties)
		if err != nil {
			t.Fatalf("%s: %v", tool.Name, err)
		}
		var props map[string]any
		if err := json.Unmarshal(raw, &props); err != nil {
			t.Fatalf("%s: %v", tool.Name, err)
		}

		for prop, spec := range props {
			m, ok := spec.(map[string]any)
			if !ok {
				continue
			}
			for _, bad := range unsupportedInStrictSchemas {
				if _, present := m[bad]; present {
					t.Errorf("%s.%s uses %q, which strict schemas reject with a 400",
						tool.Name, prop, bad)
				}
			}
		}

		for _, req := range tool.InputSchema.Required {
			if _, ok := props[req]; !ok {
				t.Errorf("%s: %q is required but not declared as a property", tool.Name, req)
			}
		}
	}
}

func TestVerdictToolCoversEveryField(t *testing.T) {
	view, err := codeview.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := buildToolset(view)

	var submit *struct {
		props    map[string]any
		required []string
	}
	for _, d := range ts.defs {
		if d.OfTool != nil && d.OfTool.Name == "submit_verdict" {
			raw, _ := json.Marshal(d.OfTool.InputSchema.Properties)
			var p map[string]any
			_ = json.Unmarshal(raw, &p)
			submit = &struct {
				props    map[string]any
				required []string
			}{p, d.OfTool.InputSchema.Required}
		}
	}
	if submit == nil {
		t.Fatal("submit_verdict tool is missing")
	}

	// Every field the Go struct decodes must be declared, or the model has no
	// way to supply it and the verdict silently loses information.
	for _, field := range []string{
		"verdict", "confidence", "adjusted_severity", "reasoning",
		"evidence", "reachable", "exploit_sketch", "suggested_fix",
	} {
		if _, ok := submit.props[field]; !ok {
			t.Errorf("submit_verdict is missing the %q property", field)
		}
	}
	if len(submit.required) != len(submit.props) {
		t.Errorf("submit_verdict: %d properties but %d required; strict mode is safest when every field is required",
			len(submit.props), len(submit.required))
	}
}

func TestEvidenceCleaning(t *testing.T) {
	in := []string{
		"internal/collector/collector.go:38",
		"internal/collector/collector.go:38",
		"  go.mod:3  ",
		".gateai/report.json:70",
		"search_code results showing no usage",
		"",
	}
	got := cleanEvidence(in)

	for _, e := range got {
		if e == ".gateai/report.json:70" {
			t.Error("a citation of our own report survived cleaning")
		}
	}
	if len(got) != 3 {
		t.Errorf("cleanEvidence = %q, want 3 entries (dedup + trim + state-dir drop)", got)
	}
	if n := countLocations(got); n != 2 {
		t.Errorf("countLocations = %d, want 2; prose must not count as a location", n)
	}
	if countLocations([]string{"just some prose about the code"}) != 0 {
		t.Error("prose counted as a verifiable location")
	}
}

// Payloads observed in real runs: the model wrote a text-format function call
// inside a string field, so suggested_fix arrived as "n/a" and the real text
// was buried in reasoning.
func TestRepairVerdictRecoversLeakedFields(t *testing.T) {
	in := &verdictInput{
		Verdict:          "not_exploitable",
		Reasoning:        `The args come from CLI flags, not a network service.</reasoning>` + "\n" + `<parameter name="suggested_fix">If this tool is ever exposed as a service, validate Target.Root against an allowlist.`,
		SuggestedFix:     "n/a",
		ExploitSketch:    "</antmlःparameter>\n",
		Evidence:         []string{"cmd/gateai/main.go:22", "</parameter>"},
		AdjustedSeverity: "low",
	}

	if !repairVerdict(in) {
		t.Fatal("repairVerdict reported nothing to repair")
	}

	if strings.Contains(in.Reasoning, "<") || strings.Contains(in.Reasoning, "parameter name") {
		t.Errorf("markup survived in reasoning: %q", in.Reasoning)
	}
	if !strings.HasPrefix(in.Reasoning, "The args come from CLI flags") {
		t.Errorf("reasoning lost its real content: %q", in.Reasoning)
	}
	if !strings.Contains(in.SuggestedFix, "validate Target.Root") {
		t.Errorf("suggested_fix was not recovered from the leaked block: %q", in.SuggestedFix)
	}
	if in.ExploitSketch != "" {
		t.Errorf("exploit_sketch should be empty after stripping a stray tag, got %q", in.ExploitSketch)
	}
	if in.Evidence[1] != "" {
		t.Errorf("stray tag survived in evidence: %q", in.Evidence[1])
	}
}

func TestRepairVerdictLeavesCleanVerdictsAlone(t *testing.T) {
	in := &verdictInput{
		Verdict:      "not_exploitable",
		Reasoning:    "The vulnerable os.Root API is never called; 5 < 7 in the loop bound is unrelated.",
		SuggestedFix: "Upgrade the toolchain when convenient.",
		Evidence:     []string{"go.mod:3"},
	}
	before := *in
	if repairVerdict(in) {
		t.Error("a clean verdict was reported as repaired")
	}
	if in.Reasoning != before.Reasoning || in.SuggestedFix != before.SuggestedFix {
		t.Errorf("repair mutated a clean verdict: %+v", in)
	}
}

// Real runs cite evidence as "path:line - why it matters". Treating that as
// unverifiable downgraded a correct verdict to needs_human.
func TestEvidenceAcceptsAnnotatedLocations(t *testing.T) {
	annotated := []string{
		"internal/triage/tools_test.go:175 - only a string literal in test fixture data",
		"cmd/gateai/main.go:110 - unrelated custom field, not os.Root",
		"go.mod:3",
	}
	if n := countLocations(annotated); n != 3 {
		t.Errorf("countLocations = %d, want 3; annotated locations must still count", n)
	}

	if countLocations([]string{"search_code: no matches for ECHConfig"}) != 0 {
		t.Error("a tool name followed by prose was accepted as a location")
	}
	if countLocations([]string{"the code in collector.go looks fine"}) != 0 {
		t.Error("prose mentioning a file was accepted as a location")
	}

	got := cleanEvidence([]string{".gateai/report.json:70 - previous run said so", "go.mod:3"})
	for _, e := range got {
		if strings.HasPrefix(e, ".gateai/") {
			t.Errorf("annotated citation of our own report survived: %q", e)
		}
	}
}
