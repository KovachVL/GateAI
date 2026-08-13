package policy

import (
	"testing"

	"github.com/KovachVL/GateAI/internal/finding"
	"github.com/KovachVL/GateAI/internal/verdict"
)

func boolp(b bool) *bool { return &b }

func TestGateEvaluate(t *testing.T) {
	gate := Gate{
		BlockOn:    BlockOn{Verdict: "exploitable", MinSeverity: finding.SevHigh, MinConfidence: 0.7},
		NeedsHuman: "warn",
	}

	vs := []verdict.Verdict{
		{Kind: verdict.Exploitable, AdjustedSeverity: finding.SevCritical, Confidence: 0.9},
		{Kind: verdict.Exploitable, AdjustedSeverity: finding.SevLow, Confidence: 0.9},
		{Kind: verdict.Exploitable, AdjustedSeverity: finding.SevHigh, Confidence: 0.4},
		{Kind: verdict.NotExploitable, AdjustedSeverity: finding.SevCritical, Confidence: 1},
		{Kind: verdict.NeedsHuman, AdjustedSeverity: finding.SevHigh, Confidence: 0.5},
	}

	blocking, needsHuman, suppressed := gate.Evaluate(vs)
	if len(blocking) != 1 {
		t.Errorf("blocking = %d, want 1", len(blocking))
	}
	if len(needsHuman) != 1 {
		t.Errorf("needsHuman = %d, want 1", len(needsHuman))
	}
	if len(suppressed) != 3 {
		t.Errorf("suppressed = %d, want 3", len(suppressed))
	}

	gate.NeedsHuman = "block"
	blocking, _, _ = gate.Evaluate(vs)
	if len(blocking) != 2 {
		t.Errorf("with needs_human=block, blocking = %d, want 2", len(blocking))
	}
}

func TestGateRequireReachable(t *testing.T) {
	gate := Gate{
		BlockOn:          BlockOn{Verdict: "exploitable", MinSeverity: finding.SevLow},
		RequireReachable: true,
	}
	yes, no := true, false
	vs := []verdict.Verdict{
		{Kind: verdict.Exploitable, AdjustedSeverity: finding.SevCritical, Reachable: &yes},
		{Kind: verdict.Exploitable, AdjustedSeverity: finding.SevCritical, Reachable: &no},
		{Kind: verdict.Exploitable, AdjustedSeverity: finding.SevCritical, Reachable: nil},
	}
	blocking, _, suppressed := gate.Evaluate(vs)
	if len(blocking) != 1 {
		t.Errorf("blocking = %d, want 1 (only the reachable one)", len(blocking))
	}
	if len(suppressed) != 2 {
		t.Errorf("suppressed = %d, want 2", len(suppressed))
	}
}

func TestResolveMergesDefaults(t *testing.T) {
	d := StageDefaults{Model: "claude-sonnet-5", Effort: "medium", MaxTokens: 16000, Skeptic: true}
	s := Stage{Stage: "sast", Effort: "high"}.Resolve(d)

	if s.Model != "claude-sonnet-5" {
		t.Errorf("Model = %q, want the default", s.Model)
	}
	if s.Effort != "high" {
		t.Errorf("Effort = %q, want the stage override to win", s.Effort)
	}
	if s.Skeptic == nil || !*s.Skeptic {
		t.Error("Skeptic did not inherit the default")
	}
	if s.Gate.OnFail != "stop" || s.Gate.NeedsHuman != "warn" {
		t.Errorf("gate defaults not applied: %+v", s.Gate)
	}

	s2 := Stage{Stage: "sca", Skeptic: boolp(false)}.Resolve(d)
	if s2.Skeptic == nil || *s2.Skeptic {
		t.Error("explicit skeptic=false was overwritten by the default")
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !finding.SevCritical.AtLeast(finding.SevHigh) {
		t.Error("critical should satisfy a high bar")
	}
	if finding.SevMedium.AtLeast(finding.SevHigh) {
		t.Error("medium should not satisfy a high bar")
	}
	if !finding.Severity("ERROR").AtLeast(finding.SevHigh) {
		t.Error("semgrep's ERROR should normalize to high")
	}
}
