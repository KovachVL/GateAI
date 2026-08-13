package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KovachVL/GateAI/internal/finding"
)

type BCA struct{}

func (b *BCA) Name() string         { return "syft" }
func (b *BCA) Layer() finding.Layer { return finding.LayerBCA }
func (b *BCA) Available() error     { return requireBinary("syft") }

type syftOutput struct {
	Artifacts []struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Type      string `json:"type"`
		PURL      string `json:"purl"`
		Locations []struct {
			Path string `json:"path"`
		} `json:"locations"`
	} `json:"artifacts"`
}

func (b *BCA) Scan(ctx context.Context, t Target) ([]finding.Finding, error) {
	if t.Artifact == "" {
		return nil, nil
	}

	declared, err := b.sbom(ctx, "dir:"+t.Root)
	if err != nil {
		return nil, fmt.Errorf("sbom of source tree: %w", err)
	}
	shipped, err := b.sbom(ctx, t.Artifact)
	if err != nil {
		return nil, fmt.Errorf("sbom of artifact %q: %w", t.Artifact, err)
	}

	var findings []finding.Finding
	for name, shippedVer := range shipped {
		declaredVer, ok := declared[name]
		switch {
		case !ok:
			f := finding.Finding{
				Layer:  finding.LayerBCA,
				Tool:   "syft",
				RuleID: "bca/undeclared-component",
				Title:  fmt.Sprintf("%s@%s present in artifact but not in any manifest", name, shippedVer),
				Message: "The built artifact contains a component that no source manifest declares. " +
					"Source-level SCA cannot see it, so any vulnerability in it is currently unmonitored. " +
					"Common causes: vendored source, static linking, a base-image layer.",
				RawSeverity: finding.SevMedium,
				Location:    finding.Location{File: t.Artifact, Symbol: name},
				Component:   &finding.Component{Name: name, Version: shippedVer},
			}
			f.ID = f.Fingerprint()
			findings = append(findings, f)
		case declaredVer != shippedVer:
			f := finding.Finding{
				Layer:  finding.LayerBCA,
				Tool:   "syft",
				RuleID: "bca/version-drift",
				Title: fmt.Sprintf("%s: manifest declares %s, artifact ships %s",
					name, declaredVer, shippedVer),
				Message: "The version in the built artifact differs from the declared one. " +
					"SCA results for this component describe a version that was not shipped.",
				RawSeverity: finding.SevMedium,
				Location:    finding.Location{File: t.Artifact, Symbol: name},
				Component:   &finding.Component{Name: name, Version: shippedVer},
			}
			f.ID = f.Fingerprint()
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func (b *BCA) sbom(ctx context.Context, source string) (map[string]string, error) {
	out, err := runJSON(ctx, "syft", "scan", source, "-o", "syft-json", "-q")
	if err != nil {
		return nil, err
	}
	var parsed syftOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, err
	}
	m := make(map[string]string, len(parsed.Artifacts))
	for _, a := range parsed.Artifacts {
		key := strings.ToLower(a.Type + "/" + a.Name)

		if _, exists := m[key]; !exists {
			m[key] = a.Version
		}
	}
	return m, nil
}
