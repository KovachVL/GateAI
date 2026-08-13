package policy

import (
	"fmt"
	"os"
	"strings"

	"github.com/KovachVL/GateAI/internal/finding"
	"github.com/KovachVL/GateAI/internal/verdict"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Concurrency int `yaml:"concurrency"`

	Cache string `yaml:"cache"`

	Defaults StageDefaults `yaml:"defaults"`
	Pipeline []Stage       `yaml:"pipeline"`
}

type StageDefaults struct {
	Model         string  `yaml:"model"`
	Effort        string  `yaml:"effort"`
	MaxTokens     int64   `yaml:"max_tokens"`
	MaxIterations int     `yaml:"max_iterations"`
	MinConfidence float64 `yaml:"min_confidence"`
	Skeptic       bool    `yaml:"skeptic"`
}

type Stage struct {
	Stage   string `yaml:"stage"`
	Enabled *bool  `yaml:"enabled"`

	Model         string  `yaml:"model"`
	Effort        string  `yaml:"effort"`
	MaxTokens     int64   `yaml:"max_tokens"`
	MaxIterations int     `yaml:"max_iterations"`
	MinConfidence float64 `yaml:"min_confidence"`
	Skeptic       *bool   `yaml:"skeptic"`

	Gate Gate `yaml:"gate"`
}

type Gate struct {
	BlockOn BlockOn `yaml:"block_on"`

	NeedsHuman string `yaml:"needs_human"`

	OnFail string `yaml:"on_fail"`

	RequireReachable bool `yaml:"require_reachable"`
}

type BlockOn struct {
	Verdict       string           `yaml:"verdict"`
	MinSeverity   finding.Severity `yaml:"min_severity"`
	MinConfidence float64          `yaml:"min_confidence"`
}

func (s Stage) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

func (s Stage) Resolve(d StageDefaults) Stage {
	if s.Model == "" {
		s.Model = d.Model
	}
	if s.Effort == "" {
		s.Effort = d.Effort
	}
	if s.MaxTokens == 0 {
		s.MaxTokens = d.MaxTokens
	}
	if s.MaxIterations == 0 {
		s.MaxIterations = d.MaxIterations
	}
	if s.MinConfidence == 0 {
		s.MinConfidence = d.MinConfidence
	}
	if s.Skeptic == nil {
		v := d.Skeptic
		s.Skeptic = &v
	}
	if s.Gate.BlockOn.Verdict == "" {
		s.Gate.BlockOn.Verdict = string(verdict.Exploitable)
	}
	if s.Gate.BlockOn.MinSeverity == "" {
		s.Gate.BlockOn.MinSeverity = finding.SevHigh
	}
	if s.Gate.NeedsHuman == "" {
		s.Gate.NeedsHuman = "warn"
	}
	if s.Gate.OnFail == "" {
		s.Gate.OnFail = "stop"
	}
	return s
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func Default() *Config {
	t := true
	return &Config{
		Concurrency: 4,
		Cache:       ".gateai/verdicts.json",
		Defaults: StageDefaults{
			Model:         "claude-sonnet-5",
			Effort:        "medium",
			MaxTokens:     16000,
			MaxIterations: 14,
			MinConfidence: 0.7,
			Skeptic:       true,
		},
		Pipeline: []Stage{
			{Stage: "sast", Gate: Gate{
				BlockOn:    BlockOn{Verdict: "exploitable", MinSeverity: finding.SevHigh},
				NeedsHuman: "warn", OnFail: "stop",
			}},
			{Stage: "sca", Gate: Gate{
				BlockOn:          BlockOn{Verdict: "exploitable", MinSeverity: finding.SevCritical},
				NeedsHuman:       "warn",
				OnFail:           "stop",
				RequireReachable: true,
			}},
			{Stage: "bca", Enabled: &t, Gate: Gate{
				BlockOn:    BlockOn{Verdict: "exploitable", MinSeverity: finding.SevCritical},
				NeedsHuman: "warn", OnFail: "stop",
			}},
		},
	}
}

func (c *Config) validate() error {
	valid := map[string]bool{"sast": true, "sca": true, "bca": true}
	for _, s := range c.Pipeline {
		if !valid[s.Stage] {
			return fmt.Errorf("unknown stage %q (expected sast, sca or bca)", s.Stage)
		}
		if m := strings.ToLower(s.Gate.NeedsHuman); m != "" && m != "block" && m != "warn" && m != "ignore" {
			return fmt.Errorf("stage %s: needs_human must be block, warn or ignore", s.Stage)
		}
		if m := strings.ToLower(s.Gate.OnFail); m != "" && m != "stop" && m != "continue" {
			return fmt.Errorf("stage %s: on_fail must be stop or continue", s.Stage)
		}
	}
	if c.Concurrency < 1 {
		c.Concurrency = 1
	}
	return nil
}

func (g Gate) Evaluate(vs []verdict.Verdict) (blocking, needsHuman, suppressed []verdict.Verdict) {
	for _, v := range vs {
		switch v.Kind {
		case verdict.NeedsHuman:
			needsHuman = append(needsHuman, v)
			if strings.EqualFold(g.NeedsHuman, "block") {
				blocking = append(blocking, v)
			}
		case verdict.Kind(g.BlockOn.Verdict):
			if !v.AdjustedSeverity.AtLeast(g.BlockOn.MinSeverity) {
				suppressed = append(suppressed, v)
				continue
			}
			if v.Confidence < g.BlockOn.MinConfidence {
				suppressed = append(suppressed, v)
				continue
			}
			if g.RequireReachable && (v.Reachable == nil || !*v.Reachable) {
				suppressed = append(suppressed, v)
				continue
			}
			blocking = append(blocking, v)
		default:
			suppressed = append(suppressed, v)
		}
	}
	return
}
