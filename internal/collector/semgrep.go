package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KovachVL/GateAI/internal/finding"
)

type Semgrep struct {
	Config string

	Timeout int
}

var defaultSemgrepConfigs = []string{"p/default", "p/secrets"}

func (s *Semgrep) configs() []string {
	if s.Config != "" {
		return splitConfigs(s.Config)
	}
	if env := os.Getenv("GATEAI_SEMGREP_CONFIG"); env != "" {
		return splitConfigs(env)
	}
	return defaultSemgrepConfigs
}

func splitConfigs(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Semgrep) Name() string         { return "semgrep" }
func (s *Semgrep) Layer() finding.Layer { return finding.LayerSAST }
func (s *Semgrep) Available() error     { return requireBinary("semgrep") }

type semgrepOutput struct {
	Paths struct {
		Scanned []string `json:"scanned"`
	} `json:"paths"`
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Lines    string `json:"lines"`
			Metadata struct {
				CWE        json.RawMessage `json:"cwe"`
				Confidence string          `json:"confidence"`
				Category   string          `json:"category"`
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (s *Semgrep) Scan(ctx context.Context, t Target) ([]finding.Finding, error) {
	configs := s.configs()
	args := []string{"--json", "--quiet", "--exclude", ".gateai"}
	for _, c := range configs {
		args = append(args, "--config", c)
	}
	if s.Timeout > 0 {
		args = append(args, "--timeout", itoa(s.Timeout))
	}
	args = append(args, t.Root)

	out, err := runJSON(ctx, "semgrep", args...)
	if err != nil {
		return nil, err
	}
	var parsed semgrepOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, err
	}

	if len(parsed.Paths.Scanned) == 0 {
		return nil, fmt.Errorf("semgrep scanned 0 files under %s — the path is empty, unreadable, "+
			"or entirely excluded; reporting this as an error rather than a clean result", t.Root)
	}

	findings := make([]finding.Finding, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		rel := relTo(t.Root, r.Path)
		f := finding.Finding{
			Layer:       finding.LayerSAST,
			Tool:        "semgrep",
			RuleID:      r.CheckID,
			Title:       shortRule(r.CheckID),
			Message:     r.Extra.Message,
			RawSeverity: finding.Severity(r.Extra.Severity).Normalize(),
			Location:    finding.Location{File: rel, Line: r.Start.Line},
			Snippet:     snippetFor(t.Root, rel, r.Start.Line, r.End.Line, r.Extra.Lines),
			CWE:         parseCWE(r.Extra.Metadata.CWE),
			Language:    finding.LanguageOf(rel),
		}
		f.ID = f.Fingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}

func parseCWE(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil && one != "" {
		return []string{one}
	}
	return nil
}

func shortRule(id string) string {
	if i := strings.LastIndex(id, "."); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

func relTo(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return path
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

var placeholderSnippets = map[string]bool{
	"requires login": true,
	"requires_login": true,
	"<redacted>":     true,
	"...":            true,
}

func isPlaceholderSnippet(s string) bool {
	return placeholderSnippets[strings.ToLower(strings.TrimSpace(s))]
}

func snippetFor(root, rel string, start, end int, provided string) string {
	provided = strings.TrimRight(provided, "\n")
	if strings.TrimSpace(provided) != "" && !isPlaceholderSnippet(provided) {
		return provided
	}
	if start <= 0 {
		return ""
	}
	if end < start {
		end = start
	}
	if end-start > 40 {
		end = start + 40
	}
	return readLines(filepath.Join(root, rel), start, end)
}

func readLines(path string, start, end int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	var b strings.Builder
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		if n < start {
			continue
		}
		if n > end {
			break
		}
		b.WriteString(sc.Text())
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}
