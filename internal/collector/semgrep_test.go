package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Semgrep returns the literal string "requires login" instead of the code for
// registry rules when the CLI is not authenticated. Sending that to the model
// as a code snippet is worse than sending nothing: it reads as injected text.
func TestSnippetFallsBackToRealSource(t *testing.T) {
	root := t.TempDir()
	body := "package main\n\nfunc run() {\n\texec.Command(name, args...)\n}\n"
	if err := os.WriteFile(filepath.Join(root, "a.go"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	got := snippetFor(root, "a.go", 4, 4, "requires login")
	if strings.Contains(got, "requires login") {
		t.Errorf("placeholder passed through as a snippet: %q", got)
	}
	if !strings.Contains(got, "exec.Command") {
		t.Errorf("snippet did not fall back to the real source line: %q", got)
	}

	real := "\texec.Command(name, args...)"
	if got := snippetFor(root, "a.go", 4, 4, real); got != real {
		t.Errorf("a genuine snippet was replaced: %q", got)
	}

	if got := snippetFor(root, "missing.go", 4, 4, "requires login"); got != "" {
		t.Errorf("unreadable file should yield an empty snippet, got %q", got)
	}
}
