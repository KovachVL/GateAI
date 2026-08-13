package collector

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/KovachVL/GateAI/internal/finding"
)

type Target struct {
	Root string

	Artifact string
}

var ErrNotInstalled = errors.New("scanner binary not installed")

type Collector interface {
	Name() string

	Layer() finding.Layer

	Available() error

	Scan(ctx context.Context, t Target) ([]finding.Finding, error)
}

func requireBinary(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%w: %s", ErrNotInstalled, name)
	}
	return nil
}

func runJSON(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%s failed (exit %d): %s", name, ee.ExitCode(), truncate(string(ee.Stderr), 500))
		}
		return nil, fmt.Errorf("%s failed: %w", name, err)
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
