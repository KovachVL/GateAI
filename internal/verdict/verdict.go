package verdict

import "github.com/KovachVL/GateAI/internal/finding"

type Kind string

const (
	Exploitable    Kind = "exploitable"
	NotExploitable Kind = "not_exploitable"
	NeedsHuman     Kind = "needs_human"
)

type Verdict struct {
	FindingID        string           `json:"finding_id"`
	Kind             Kind             `json:"verdict"`
	Confidence       float64          `json:"confidence"`
	AdjustedSeverity finding.Severity `json:"adjusted_severity"`
	Reasoning        string           `json:"reasoning"`

	Evidence      []string `json:"evidence,omitempty"`
	Reachable     *bool    `json:"reachable,omitempty"`
	ExploitSketch string   `json:"exploit_sketch,omitempty"`
	SuggestedFix  string   `json:"suggested_fix,omitempty"`

	Model     string `json:"model"`
	Cached    bool   `json:"cached,omitempty"`
	Repaired  bool   `json:"repaired,omitempty"`
	Error     string `json:"error,omitempty"`
	InTokens  int64  `json:"in_tokens,omitempty"`
	OutTokens int64  `json:"out_tokens,omitempty"`

	Finding *finding.Finding `json:"finding,omitempty"`
}
