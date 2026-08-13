package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type Layer string

const (
	LayerSAST Layer = "sast"
	LayerSCA  Layer = "sca"
	LayerBCA  Layer = "bca"
)

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

var sevRank = map[Severity]int{
	SevInfo: 0, SevLow: 1, SevMedium: 2, SevHigh: 3, SevCritical: 4,
}

func (s Severity) AtLeast(min Severity) bool {
	return sevRank[s.Normalize()] >= sevRank[min.Normalize()]
}

func (s Severity) Normalize() Severity {
	switch strings.ToLower(string(s)) {
	case "critical", "crit":
		return SevCritical
	case "high", "error":
		return SevHigh
	case "medium", "moderate", "warning", "warn":
		return SevMedium
	case "low", "minor":
		return SevLow
	default:
		return SevInfo
	}
}

type Location struct {
	File   string `json:"file"`
	Line   int    `json:"line,omitempty"`
	Symbol string `json:"symbol,omitempty"`
}

func (l Location) String() string {
	if l.Line > 0 {
		return fmt.Sprintf("%s:%d", l.File, l.Line)
	}
	return l.File
}

type Component struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`

	Ecosystem string `json:"ecosystem,omitempty"`
}

type Finding struct {
	ID          string     `json:"id"`
	Layer       Layer      `json:"layer"`
	Tool        string     `json:"tool"`
	RuleID      string     `json:"rule_id,omitempty"`
	Title       string     `json:"title"`
	Message     string     `json:"message,omitempty"`
	RawSeverity Severity   `json:"raw_severity"`
	Location    Location   `json:"location"`
	Component   *Component `json:"component,omitempty"`
	CWE         []string   `json:"cwe,omitempty"`
	CVE         []string   `json:"cve,omitempty"`
	Snippet     string     `json:"snippet,omitempty"`

	Language string `json:"language,omitempty"`
}

func (f *Finding) Fingerprint() string {
	h := sha256.New()
	parts := []string{
		string(f.Layer), f.Tool, f.RuleID, f.Location.File,
		normalizeWhitespace(f.Snippet), strings.Join(f.CVE, ","),
	}
	if f.Component != nil {
		parts = append(parts, f.Component.Name, f.Component.Version)
	}
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func normalizeWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func LanguageOf(path string) string {
	i := strings.LastIndex(path, ".")
	if i < 0 {
		return ""
	}
	switch strings.ToLower(path[i:]) {
	case ".go":
		return "Go"
	case ".py":
		return "Python"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "JavaScript"
	case ".ts", ".tsx":
		return "TypeScript"
	case ".java":
		return "Java"
	case ".kt", ".kts":
		return "Kotlin"
	case ".rb":
		return "Ruby"
	case ".php":
		return "PHP"
	case ".cs":
		return "C#"
	case ".rs":
		return "Rust"
	case ".c", ".h":
		return "C"
	case ".cc", ".cpp", ".cxx", ".hpp":
		return "C++"
	case ".scala":
		return "Scala"
	case ".swift":
		return "Swift"
	case ".tf":
		return "Terraform"
	case ".yaml", ".yml":
		return "YAML"
	default:
		return ""
	}
}
