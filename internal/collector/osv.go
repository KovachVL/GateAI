package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KovachVL/GateAI/internal/finding"
)

type OSV struct{}

func (o *OSV) Name() string         { return "osv-scanner" }
func (o *OSV) Layer() finding.Layer { return finding.LayerSCA }
func (o *OSV) Available() error     { return requireBinary("osv-scanner") }

type osvOutput struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID       string   `json:"id"`
				Aliases  []string `json:"aliases"`
				Summary  string   `json:"summary"`
				Details  string   `json:"details"`
				Severity []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				} `json:"severity"`
				DatabaseSpecific struct {
					Severity string `json:"severity"`
				} `json:"database_specific"`
				Affected []struct {
					EcosystemSpecific struct {
						Imports []struct {
							Path    string   `json:"path"`
							Symbols []string `json:"symbols"`
						} `json:"imports"`
					} `json:"ecosystem_specific"`
				} `json:"affected"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

func (o *OSV) Scan(ctx context.Context, t Target) ([]finding.Finding, error) {
	out, err := runJSON(ctx, "osv-scanner", "--format", "json", "--recursive", t.Root)
	if err != nil {
		return nil, err
	}
	var parsed osvOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, err
	}

	var findings []finding.Finding
	for _, res := range parsed.Results {
		manifest := relTo(t.Root, res.Source.Path)
		for _, pkg := range res.Packages {
			for _, v := range pkg.Vulnerabilities {
				comp := finding.Component{
					Name:      pkg.Package.Name,
					Version:   pkg.Package.Version,
					Ecosystem: pkg.Package.Ecosystem,
				}
				f := finding.Finding{
					Layer:       finding.LayerSCA,
					Tool:        "osv-scanner",
					RuleID:      v.ID,
					Title:       fmt.Sprintf("%s in %s@%s", v.ID, comp.Name, comp.Version),
					Message:     firstNonEmpty(v.Summary, truncate(v.Details, 400)),
					RawSeverity: osvSeverity(v.DatabaseSpecific.Severity, v.Severity),
					Location:    finding.Location{File: manifest, Symbol: vulnSymbols(v.Affected)},
					Component:   &comp,
					CVE:         cveAliases(v.ID, v.Aliases),
				}
				f.ID = f.Fingerprint()
				findings = append(findings, f)
			}
		}
	}
	return findings, nil
}

func vulnSymbols(affected []struct {
	EcosystemSpecific struct {
		Imports []struct {
			Path    string   `json:"path"`
			Symbols []string `json:"symbols"`
		} `json:"imports"`
	} `json:"ecosystem_specific"`
}) string {
	var syms []string
	for _, a := range affected {
		for _, imp := range a.EcosystemSpecific.Imports {
			for _, s := range imp.Symbols {
				syms = append(syms, imp.Path+"."+s)
			}
		}
	}
	if len(syms) > 8 {
		syms = syms[:8]
	}
	return strings.Join(syms, ", ")
}

func osvSeverity(dbSeverity string, scores []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) finding.Severity {
	if dbSeverity != "" {
		return finding.Severity(dbSeverity).Normalize()
	}

	for _, s := range scores {
		if strings.Contains(strings.ToUpper(s.Score), "CRITICAL") {
			return finding.SevCritical
		}
	}
	return finding.SevMedium
}

func cveAliases(id string, aliases []string) []string {
	var out []string
	if strings.HasPrefix(id, "CVE-") {
		out = append(out, id)
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			out = append(out, a)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
