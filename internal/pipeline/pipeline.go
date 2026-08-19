package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KovachVL/GateAI/internal/cache"
	"github.com/KovachVL/GateAI/internal/codeview"
	"github.com/KovachVL/GateAI/internal/collector"
	"github.com/KovachVL/GateAI/internal/finding"
	"github.com/KovachVL/GateAI/internal/policy"
	"github.com/KovachVL/GateAI/internal/triage"
	"github.com/KovachVL/GateAI/internal/verdict"
	"github.com/anthropics/anthropic-sdk-go"
)

type StageResult struct {
	Stage               string            `json:"stage"`
	Result              string            `json:"result"`
	Skipped             string            `json:"skipped_reason,omitempty"`
	Error               string            `json:"error,omitempty"`
	Scanned             int               `json:"scanned"`
	Triaged             int               `json:"triaged"`
	CacheHits           int               `json:"cache_hits"`
	TriageErrors        int               `json:"triage_errors"`
	Blocking            []verdict.Verdict `json:"blocking,omitempty"`
	NeedsHuman          []verdict.Verdict `json:"needs_human,omitempty"`
	Suppressed          int               `json:"suppressed"`
	SuppressedVerdicts  []verdict.Verdict `json:"suppressed_verdicts,omitempty"`
	InTokens            int64             `json:"in_tokens"`
	OutTokens           int64             `json:"out_tokens"`
	BaseInTokens        int64             `json:"base_in_tokens"`
	CacheReadTokens     int64             `json:"cache_read_tokens"`
	CacheCreationTokens int64             `json:"cache_creation_tokens"`
	Turns               int               `json:"turns"`
	Duration            string            `json:"duration"`
}

type Report struct {
	Target string        `json:"target"`
	Result string        `json:"result"`
	Stages []StageResult `json:"stages"`
}

type Runner struct {
	Config *policy.Config
	Client *anthropic.Client
	View   *codeview.View
	Target collector.Target
	Cache  *cache.Cache
	Log    io.Writer

	Baseline map[string]bool

	FailOnSkip bool
}

func (r *Runner) logf(format string, args ...any) {
	if r.Log != nil {
		fmt.Fprintf(r.Log, format+"\n", args...)
	}
}

func collectorFor(stage string) collector.Collector {
	switch stage {
	case "sast":
		return &collector.Semgrep{}
	case "sca":
		return &collector.OSV{}
	case "bca":
		return &collector.BCA{}
	}
	return nil
}

func (r *Runner) Run(ctx context.Context) (*Report, error) {
	report := &Report{Target: r.Target.Root, Result: "pass"}
	ran := 0

	for _, raw := range r.Config.Pipeline {
		if !raw.IsEnabled() {
			report.Stages = append(report.Stages, StageResult{
				Stage: raw.Stage, Result: "skipped", Skipped: "disabled in config",
			})
			continue
		}
		stage := raw.Resolve(r.Config.Defaults)
		sr := r.runStage(ctx, stage)
		report.Stages = append(report.Stages, sr)

		if sr.Result == "skipped" && r.FailOnSkip {
			r.logf("stage %s: skipped and --fail-on-skip is set — treating as a failure", stage.Stage)
			report.Result = "fail"
			break
		}
		if sr.Result != "skipped" {
			ran++
		}

		if sr.Result == "fail" {
			report.Result = "fail"
			if stage.Gate.OnFail == "stop" {
				r.logf("gate %s: FAIL — stopping the pipeline, later stages not run", stage.Stage)
				break
			}
			r.logf("gate %s: FAIL — on_fail=continue, proceeding", stage.Stage)
			continue
		}
		if sr.Result == "error" {
			report.Result = "fail"
			break
		}
		if len(sr.NeedsHuman) > 0 && report.Result == "pass" {
			report.Result = "needs_human"
		}
	}

	if ran == 0 && report.Result != "fail" {
		report.Result = "no_coverage"
		r.logf("no stage ran — reporting no_coverage rather than pass")
	}
	return report, nil
}

func (r *Runner) runStage(ctx context.Context, stage policy.Stage) StageResult {
	started := time.Now()
	sr := StageResult{Stage: stage.Stage}

	coll := collectorFor(stage.Stage)
	if coll == nil {
		sr.Result = "error"
		sr.Error = "no collector for stage"
		return sr
	}
	if err := coll.Available(); err != nil {

		sr.Result = "skipped"
		sr.Skipped = err.Error()
		sr.Duration = time.Since(started).String()
		r.logf("stage %s: SKIPPED (%v)", stage.Stage, err)
		return sr
	}

	r.logf("stage %s: scanning with %s…", stage.Stage, coll.Name())
	findings, err := coll.Scan(ctx, r.Target)
	if err != nil {
		sr.Result = "error"
		sr.Error = err.Error()
		sr.Duration = time.Since(started).String()
		return sr
	}
	sr.Scanned = len(findings)

	if len(r.Baseline) > 0 {
		kept := findings[:0]
		for _, f := range findings {
			if !r.Baseline[f.ID] {
				kept = append(kept, f)
			}
		}
		if n := len(findings) - len(kept); n > 0 {
			r.logf("stage %s: %d finding(s) suppressed by baseline", stage.Stage, n)
		}
		findings = kept
	}

	if len(findings) == 0 {
		sr.Result = "pass"
		sr.Duration = time.Since(started).String()
		r.logf("stage %s: 0 findings — PASS", stage.Stage)
		return sr
	}

	r.logf("stage %s: %d finding(s), triaging with %s (effort=%s, concurrency=%d)…",
		stage.Stage, len(findings), stage.Model, stage.Effort, r.Config.Concurrency)

	verdicts, hits := r.triageAll(ctx, stage, findings)
	sr.Triaged = len(verdicts)
	sr.CacheHits = hits
	var firstErr string
	for _, v := range verdicts {
		sr.InTokens += v.InTokens
		sr.OutTokens += v.OutTokens
		sr.BaseInTokens += v.BaseInTokens
		sr.CacheReadTokens += v.CacheReadTokens
		sr.CacheCreationTokens += v.CacheCreationTokens
		sr.Turns += v.Turns
		if v.Error != "" {
			sr.TriageErrors++
			if firstErr == "" {
				firstErr = v.Error
			}
		}
	}

	if sr.TriageErrors > 0 {
		sr.Result = "error"
		sr.Error = fmt.Sprintf("%d of %d finding(s) could not be triaged: %s",
			sr.TriageErrors, sr.Triaged, firstLine(firstErr))
		sr.Duration = time.Since(started).String()
		r.logf("stage %s: ERROR — %s", stage.Stage, sr.Error)
		return sr
	}

	blocking, needsHuman, suppressed := stage.Gate.Evaluate(verdicts)
	sortVerdicts(blocking)
	sortVerdicts(needsHuman)
	sr.Blocking = blocking
	sr.NeedsHuman = needsHuman
	sortVerdicts(suppressed)
	sr.Suppressed = len(suppressed)
	sr.SuppressedVerdicts = suppressed

	if len(blocking) > 0 {
		sr.Result = "fail"
	} else {
		sr.Result = "pass"
	}
	sr.Duration = time.Since(started).String()

	cacheHitPct := 0.0
	if promptTokens := sr.BaseInTokens + sr.CacheReadTokens + sr.CacheCreationTokens; promptTokens > 0 {
		cacheHitPct = 100 * float64(sr.CacheReadTokens) / float64(promptTokens)
	}
	r.logf("stage %s: %s — %d blocking, %d needs-human, %d suppressed (%d verdict cache hits) — "+
		"%d in (%d base, %d cache read [%.0f%%], %d cache write), %d out, %d turns",
		stage.Stage, upper(sr.Result), len(blocking), len(needsHuman), len(suppressed), hits,
		sr.InTokens, sr.BaseInTokens, sr.CacheReadTokens, cacheHitPct, sr.CacheCreationTokens, sr.OutTokens, sr.Turns)
	return sr
}

func (r *Runner) triageAll(ctx context.Context, stage policy.Stage, findings []finding.Finding) ([]verdict.Verdict, int) {
	opts := triage.Options{
		Model:         stage.Model,
		Effort:        stage.Effort,
		MaxTokens:     stage.MaxTokens,
		MaxIterations: stage.MaxIterations,
		MinConfidence: stage.MinConfidence,
		Skeptic:       stage.Skeptic != nil && *stage.Skeptic,
	}
	tr := triage.New(r.Client, r.View, opts)
	resolved := tr.Options()

	out := make([]verdict.Verdict, len(findings))
	total := len(findings)
	var hits, done int
	var mu sync.Mutex

	progress := func(f *finding.Finding, v verdict.Verdict, started time.Time, cached bool) {
		mu.Lock()
		done++
		n := done
		mu.Unlock()
		suffix := fmt.Sprintf("%.0fs", time.Since(started).Seconds())
		if cached {
			suffix = "cached"
		}
		r.logf("  [%s %d/%d] %s → %s (%s)",
			stage.Stage, n, total, f.Location.String(), v.Kind, suffix)
	}

	sem := make(chan struct{}, r.Config.Concurrency)
	var wg sync.WaitGroup

	for i := range findings {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			f := &findings[i]
			key := cache.Key(f.Fingerprint(), resolved.Model, resolved.Effort,
				triage.PromptVersion, resolved.Skeptic)

			if v, ok := r.Cache.Get(key); ok {
				v.Finding = f
				out[i] = v
				mu.Lock()
				hits++
				mu.Unlock()
				progress(f, v, time.Now(), true)
				return
			}

			started := time.Now()
			r.logf("  [%s] triaging %s (%s)…", stage.Stage, f.Location.String(), f.RuleID)

			v, err := tr.Run(ctx, f)
			if err != nil {
				v = verdict.Verdict{
					FindingID:        f.ID,
					Kind:             verdict.NeedsHuman,
					AdjustedSeverity: f.RawSeverity,
					Reasoning:        "triage failed: " + err.Error(),
					Error:            err.Error(),
					Model:            resolved.Model,
					Finding:          f,
				}
				out[i] = v
				if !errors.Is(err, context.Canceled) {
					r.logf("  [%s] %s → ERROR: %s", stage.Stage, f.Location.String(), firstLine(err.Error()))
				}
				progress(f, v, started, false)
				return
			}
			out[i] = v
			r.Cache.Put(key, v)
			progress(f, v, started, false)
		}(i)
	}
	wg.Wait()
	return out, hits
}

func sortVerdicts(vs []verdict.Verdict) {
	rank := map[finding.Severity]int{
		finding.SevCritical: 0, finding.SevHigh: 1, finding.SevMedium: 2,
		finding.SevLow: 3, finding.SevInfo: 4,
	}
	sort.SliceStable(vs, func(i, j int) bool {
		if rank[vs[i].AdjustedSeverity] != rank[vs[j].AdjustedSeverity] {
			return rank[vs[i].AdjustedSeverity] < rank[vs[j].AdjustedSeverity]
		}
		return vs[i].Confidence > vs[j].Confidence
	})
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
