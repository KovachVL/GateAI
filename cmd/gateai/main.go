package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/KovachVL/GateAI/internal/cache"
	"github.com/KovachVL/GateAI/internal/codeview"
	"github.com/KovachVL/GateAI/internal/collector"
	"github.com/KovachVL/GateAI/internal/pipeline"
	"github.com/KovachVL/GateAI/internal/policy"
	"github.com/KovachVL/GateAI/internal/verdict"
)

func main() {
	var (
		configPath     = flag.String("config", "", "path to policy YAML (default: built-in policy)")
		artifact       = flag.String("artifact", "", "container image or binary for the BCA stage, e.g. 'myapp:latest'")
		jsonOut        = flag.String("json", "", "write the full report as JSON to this path")
		baselinePath   = flag.String("baseline", "", "path to a baseline file; findings listed there do not block")
		writeBaseline  = flag.String("write-baseline", "", "scan, then write all current finding IDs to this path and exit 0")
		model          = flag.String("model", "", "override the model for every stage")
		effort         = flag.String("effort", "", "override effort for every stage: low|medium|high|xhigh|max")
		quiet          = flag.Bool("quiet", false, "suppress progress output")
		failOnSkip     = flag.Bool("fail-on-skip", false, "treat a skipped stage (missing scanner) as a failure; recommended in CI")
		showSuppressed = flag.Bool("show-suppressed", false, "also print verdicts the gate dismissed, so dismissals can be reviewed")
	)
	flag.Usage = usage
	flag.Parse()

	root := "."
	if flag.NArg() > 0 {
		root = flag.Arg(0)
	}

	if err := run(root, *configPath, *artifact, *jsonOut, *baselinePath, *writeBaseline, *model, *effort, *quiet, *failOnSkip, *showSuppressed); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if ec, ok := err.(exitCoder); ok {
			os.Exit(ec.code())
		}
		os.Exit(3)
	}
}

type exitCoder interface{ code() int }

type exitErr struct {
	msg string
	c   int
}

func (e exitErr) Error() string { return e.msg }
func (e exitErr) code() int     { return e.c }

func run(root, configPath, artifact, jsonOut, baselinePath, writeBaseline, model, effort string, quiet, failOnSkip, showSuppressed bool) error {
	cfg := policy.Default()
	if configPath != "" {
		loaded, err := policy.Load(configPath)
		if err != nil {
			return err
		}
		cfg = loaded
	}
	if model != "" {
		cfg.Defaults.Model = model
		for i := range cfg.Pipeline {
			cfg.Pipeline[i].Model = model
		}
	}
	if effort != "" {
		cfg.Defaults.Effort = effort
		for i := range cfg.Pipeline {
			cfg.Pipeline[i].Effort = effort
		}
	}

	view, err := codeview.New(root)
	if err != nil {
		return fmt.Errorf("open repository %q: %w", root, err)
	}

	if os.Getenv("ANTHROPIC_API_KEY") == "" && os.Getenv("ANTHROPIC_AUTH_TOKEN") == "" && !quiet {
		fmt.Fprintln(os.Stderr,
			"note: ANTHROPIC_API_KEY is unset — falling back to an `ant auth login` profile if one exists")
	}
	client := anthropic.NewClient()

	verdictCache, err := cache.Open(cfg.Cache)
	if err != nil {
		return fmt.Errorf("open verdict cache: %w", err)
	}

	baseline, err := loadBaseline(baselinePath)
	if err != nil {
		return err
	}

	var logw = os.Stderr
	runner := &pipeline.Runner{
		Config:     cfg,
		Client:     &client,
		View:       view,
		Target:     collector.Target{Root: view.Root(), Artifact: artifact},
		Cache:      verdictCache,
		Baseline:   baseline,
		FailOnSkip: failOnSkip,
	}
	if !quiet {
		runner.Log = logw
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if writeBaseline != "" {
		return doWriteBaseline(ctx, runner, writeBaseline)
	}

	report, err := runner.Run(ctx)
	if err != nil {
		return err
	}
	if err := verdictCache.Save(); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not save verdict cache:", err)
	}

	if jsonOut != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(jsonOut, data, 0o644); err != nil {
			return err
		}
	}

	printReport(os.Stdout, report, showSuppressed)

	switch report.Result {
	case "fail":
		return exitErr{msg: "gate blocked the run", c: 1}
	case "needs_human":
		return exitErr{msg: "findings require human review", c: 2}
	case "no_coverage":
		return exitErr{
			msg: "no stage ran — every scanner was missing or disabled, so nothing was checked " +
				"(install the scanners, or pass --fail-on-skip to make this a hard failure)",
			c: 2,
		}
	}
	return nil
}

func doWriteBaseline(ctx context.Context, r *pipeline.Runner, path string) error {
	ids := map[string]bool{}
	for _, stage := range r.Config.Pipeline {
		if !stage.IsEnabled() {
			continue
		}
		coll := collectorForStage(stage.Stage)
		if coll == nil {
			continue
		}
		if err := coll.Available(); err != nil {
			fmt.Fprintf(os.Stderr, "baseline: skipping %s (%v)\n", stage.Stage, err)
			continue
		}
		fs, err := coll.Scan(ctx, r.Target)
		if err != nil {
			return fmt.Errorf("baseline scan %s: %w", stage.Stage, err)
		}
		for _, f := range fs {
			ids[f.ID] = true
		}
		fmt.Fprintf(os.Stderr, "baseline: %s → %d finding(s)\n", stage.Stage, len(fs))
	}
	list := make([]string, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	data, err := json.MarshalIndent(map[string]any{"findings": list}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote baseline with %d finding(s) to %s\n", len(list), path)
	return nil
}

func collectorForStage(stage string) collector.Collector {
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

func loadBaseline(path string) (map[string]bool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var parsed struct {
		Findings []string `json:"findings"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	m := make(map[string]bool, len(parsed.Findings))
	for _, id := range parsed.Findings {
		m[id] = true
	}
	return m, nil
}

func printReport(w *os.File, r *pipeline.Report, showSuppressed bool) {
	fmt.Fprintf(w, "\n=== gateai: %s ===\n", r.Target)
	var inTok, outTok int64
	for _, s := range r.Stages {
		inTok += s.InTokens
		outTok += s.OutTokens

		switch s.Result {
		case "skipped":
			fmt.Fprintf(w, "\n[%s] SKIPPED — %s\n", strings.ToUpper(s.Stage), s.Skipped)
			continue
		case "error":
			fmt.Fprintf(w, "\n[%s] ERROR — %s\n", strings.ToUpper(s.Stage), s.Error)
			continue
		}

		fmt.Fprintf(w, "\n[%s] %s — scanned %d, triaged %d (%d cached), suppressed %d, %s\n",
			strings.ToUpper(s.Stage), strings.ToUpper(s.Result),
			s.Scanned, s.Triaged, s.CacheHits, s.Suppressed, s.Duration)

		for _, v := range s.Blocking {
			printVerdict(w, "BLOCKING", v)
		}
		for _, v := range s.NeedsHuman {
			printVerdict(w, "NEEDS HUMAN", v)
		}
		if showSuppressed {
			for _, v := range s.SuppressedVerdicts {
				printVerdict(w, "dismissed", v)
			}
		}
	}
	fmt.Fprintf(w, "\n--- result: %s (tokens: %d in / %d out) ---\n",
		strings.ToUpper(r.Result), inTok, outTok)
}

func printVerdict(w *os.File, label string, v verdict.Verdict) {
	loc := ""
	title := ""
	if v.Finding != nil {
		loc = v.Finding.Location.String()
		title = v.Finding.Title
	}
	fmt.Fprintf(w, "  %s  %s  %s\n", label, strings.ToUpper(string(v.AdjustedSeverity)), title)
	fmt.Fprintf(w, "      at %s  (confidence %.2f", loc, v.Confidence)
	if v.Reachable != nil {
		fmt.Fprintf(w, ", reachable=%v", *v.Reachable)
	}
	if v.Cached {
		fmt.Fprint(w, ", cached")
	}
	if v.Repaired {
		fmt.Fprint(w, ", repaired")
	}
	fmt.Fprintln(w, ")")
	fmt.Fprintf(w, "      %s\n", v.Reasoning)
	if len(v.Evidence) > 0 {
		fmt.Fprintf(w, "      evidence: %s\n", strings.Join(v.Evidence, ", "))
	}
	if v.SuggestedFix != "" {
		fmt.Fprintf(w, "      fix: %s\n", v.SuggestedFix)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `gateai — gated AI SAST → SCA → BCA pipeline

usage: gateai [flags] [repository-path]

Each stage scans, triages every finding with a model, and then decides whether
the run continues. A stage passes when nothing survives triage as exploitable —
not when the scanner found nothing.

flags:
`)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, `
exit codes:
  0  all stages passed
  1  a gate blocked the run
  2  findings need human review, or no stage ran (no_coverage)
  3  usage or configuration error

required scanners (install what you need; a missing one skips its stage):
  semgrep       brew install semgrep
  osv-scanner   brew install osv-scanner
  syft          brew install syft
`)
}
