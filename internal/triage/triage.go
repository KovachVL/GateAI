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

type Options struct {
	Model         string
	Effort        string
	MaxTokens     int64
	MaxIterations int

	MinConfidence float64

	Skeptic bool
}

func (o Options) withDefaults() Options {
	if o.Model == "" {
		o.Model = "claude-sonnet-5"
	}
	if o.MaxTokens == 0 {
		o.MaxTokens = 16000
	}
	if o.MaxIterations == 0 {
		o.MaxIterations = 14
	}
	if o.MinConfidence == 0 {
		o.MinConfidence = 0.7
	}
	return o
}

type Triager struct {
	client *anthropic.Client
	view   *codeview.View
	opts   Options
}

func New(client *anthropic.Client, view *codeview.View, opts Options) *Triager {
	return &Triager{client: client, view: view, opts: opts.withDefaults()}
}

func (t *Triager) Options() Options { return t.opts }

type usage struct {
	in  int64
	out int64
}

func (u *usage) add(x anthropic.BetaUsage) {
	u.in += x.InputTokens + x.CacheReadInputTokens + x.CacheCreationInputTokens
	u.out += x.OutputTokens
}

type runResult struct {
	capture  *capture
	usage    usage
	lastText string
	stopped  string
}

func (t *Triager) runLoop(ctx context.Context, layer finding.Layer, userMessage string) (runResult, error) {
	ts := buildToolset(t.view)
	res := runResult{capture: ts.capture}

	params := t.baseParams(layer)
	params.Tools = ts.defs
	messages := []anthropic.BetaMessageParam{
		anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(userMessage)),
	}

	for i := 0; i < t.opts.MaxIterations; i++ {
		params.Messages = messages
		msg, err := t.client.Beta.Messages.New(ctx, params)
		if err != nil {
			return res, err
		}
		res.usage.add(msg.Usage)

		if txt := textOf(msg); txt != "" {
			res.lastText = txt
		}

		if msg.StopReason == anthropic.BetaStopReasonRefusal {
			res.stopped = "the model declined to analyse this finding"
			return res, nil
		}

		messages = append(messages, msg.ToParam())

		var results []anthropic.BetaContentBlockParamUnion
		for _, block := range msg.Content {
			tu, ok := block.AsAny().(anthropic.BetaToolUseBlock)
			if !ok {
				continue
			}
			out := ts.dispatch(ctx, tu.Name, json.RawMessage(tu.JSON.Input.Raw()))
			results = append(results, anthropic.NewBetaToolResultBlock(tu.ID, out, false))
		}

		if ts.capture.verdict != nil {
			return res, nil
		}
		if len(results) == 0 {
			res.stopped = "the model stopped without submitting a verdict"
			return res, nil
		}
		messages = append(messages, anthropic.NewBetaUserMessage(results...))
	}

	res.stopped = fmt.Sprintf("iteration limit of %d reached", t.opts.MaxIterations)
	return res, nil
}

func (t *Triager) Run(ctx context.Context, f *finding.Finding) (verdict.Verdict, error) {
	res, err := t.runLoop(ctx, f.Layer, buildUserMessage(f))
	if err != nil {
		return verdict.Verdict{}, fmt.Errorf("triage %s: %w", f.ID, err)
	}

	v := t.finalize(res, f)

	if t.opts.Skeptic && v.Kind == verdict.NotExploitable {
		v = t.challenge(ctx, f, v)
	}
	return v, nil
}

func (t *Triager) baseParams(layer finding.Layer) anthropic.BetaMessageNewParams {
	return anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(t.opts.Model),
		MaxTokens: t.opts.MaxTokens,
		System: []anthropic.BetaTextBlockParam{{
			Text:         buildSystem(layer),
			CacheControl: anthropic.NewBetaCacheControlEphemeralParam(),
		}},
		OutputConfig: anthropic.BetaOutputConfigParam{
			Effort: anthropic.BetaOutputConfigEffort(t.opts.Effort),
		},
	}
}

func (t *Triager) finalize(res runResult, f *finding.Finding) verdict.Verdict {
	if res.capture.verdict == nil {
		reason := res.stopped
		if reason == "" {
			reason = "no verdict was submitted"
		}
		if res.lastText != "" {
			reason += ". Last text: " + truncate(res.lastText, 400)
		}
		return verdict.Verdict{
			FindingID:        f.ID,
			Kind:             verdict.NeedsHuman,
			AdjustedSeverity: f.RawSeverity,
			Reasoning:        reason,
			Model:            t.opts.Model,
			InTokens:         res.usage.in,
			OutTokens:        res.usage.out,
			Finding:          f,
		}
	}

	repaired := repairVerdict(res.capture.verdict)

	v := toVerdict(res.capture.verdict, f)
	v.Model = t.opts.Model
	v.InTokens = res.usage.in
	v.OutTokens = res.usage.out
	v.Repaired = repaired

	v.Evidence = cleanEvidence(v.Evidence)

	switch {
	case countLocations(v.Evidence) == 0 && v.Kind != verdict.NeedsHuman:
		v.Kind = verdict.NeedsHuman
		v.Reasoning = "[downgraded: verdict cited no verifiable file:line evidence] " + v.Reasoning
	case v.Confidence < t.opts.MinConfidence && v.Kind != verdict.NeedsHuman:
		v.Kind = verdict.NeedsHuman
		v.Reasoning = fmt.Sprintf("[downgraded: confidence %.2f below threshold %.2f] %s",
			v.Confidence, t.opts.MinConfidence, v.Reasoning)
	}
	return v
}

const skepticPrompt = `A first-pass triage concluded that the finding below is NOT exploitable. Your job is to try to refute that conclusion.

Look specifically for what the first pass would have missed: an indirect or dynamically dispatched call path, a framework route that never appears as a literal call, reflection or code generation, a second call site of the same function, a sanitizer that is incomplete for this sink, a non-default configuration in which the guard is absent, or a caller in a different module.

Then call submit_verdict:
- If you found a plausible path the first pass missed, return needs_human (or exploitable if you can actually demonstrate it) and cite what you found.
- If you looked and the original conclusion holds up, return not_exploitable and say what you checked.

Do not simply agree because the reasoning sounds plausible. Being wrong in the dismissive direction means a real vulnerability ships.`

func (t *Triager) challenge(ctx context.Context, f *finding.Finding, first verdict.Verdict) verdict.Verdict {
	var b strings.Builder
	b.WriteString(buildUserMessage(f))
	b.WriteString("\n\n---\n\nFirst-pass conclusion: not_exploitable (confidence ")
	fmt.Fprintf(&b, "%.2f)\nReasoning: %s\nEvidence: %s\n\n", first.Confidence,
		first.Reasoning, strings.Join(first.Evidence, "; "))
	b.WriteString(skepticPrompt)

	res, err := t.runLoop(ctx, f.Layer, b.String())
	first.InTokens += res.usage.in
	first.OutTokens += res.usage.out

	if err != nil || res.capture.verdict == nil {
		first.Kind = verdict.NeedsHuman
		first.Reasoning = "[skeptic pass did not complete] " + first.Reasoning
		return first
	}

	second := toVerdict(res.capture.verdict, f)
	second.Model = t.opts.Model
	second.InTokens = first.InTokens
	second.OutTokens = first.OutTokens

	if second.Kind == verdict.NotExploitable {
		first.Reasoning += " [skeptic pass agreed: " + truncate(second.Reasoning, 300) + "]"
		first.Evidence = cleanEvidence(append(first.Evidence, second.Evidence...))
		return first
	}

	if second.Kind != verdict.Exploitable {
		second.Kind = verdict.NeedsHuman
	}
	second.Reasoning = "[skeptic pass refuted the first-pass dismissal] " + second.Reasoning +
		" || first pass said: " + truncate(first.Reasoning, 300)
	return second
}

func textOf(msg *anthropic.BetaMessage) string {
	if msg == nil {
		return ""
	}
	var b strings.Builder
	for _, block := range msg.Content {
		if t, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			b.WriteString(t.Text)
		}
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

var locationRe = regexp.MustCompile(`^([^\s:]+:\d+(?:-\d+)?)(?:\s|$)`)

func locationOf(s string) (string, bool) {
	m := locationRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", false
	}
	return m[1], true
}

func isLocation(s string) bool {
	_, ok := locationOf(s)
	return ok
}

func countLocations(evidence []string) int {
	n := 0
	for _, e := range evidence {
		if isLocation(e) {
			n++
		}
	}
	return n
}

func cleanEvidence(evidence []string) []string {
	seen := make(map[string]bool, len(evidence))
	out := make([]string, 0, len(evidence))
	for _, e := range evidence {
		e = strings.TrimSpace(e)
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		if loc, ok := locationOf(e); ok && strings.HasPrefix(loc, codeview.StateDir+"/") {
			continue
		}
		out = append(out, e)
	}
	return out
}
