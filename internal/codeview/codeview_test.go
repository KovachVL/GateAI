package codeview

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveRefusesEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("token=hunter2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ok.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(outside, filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}

	v, err := New(root)
	if err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{
		"../secret.txt",
		"../../etc/passwd",
		"a/../../secret.txt",
		outside,
		"/etc/passwd",
		"link.txt",
	} {
		if _, err := v.ReadFile(bad, 1, 10); err == nil {
			t.Errorf("ReadFile(%q) = nil error, want refusal", bad)
		}
	}

	if _, err := v.ReadFile("ok.go", 1, 10); err != nil {
		t.Errorf("ReadFile on an in-repo file failed: %v", err)
	}
}

func TestReadFileLineRange(t *testing.T) {
	root := t.TempDir()
	body := "one\ntwo\nthree\nfour\nfive\n"
	if err := os.WriteFile(filepath.Join(root, "f.txt"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	out, err := v.ReadFile("f.txt", 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "two") || !strings.Contains(out, "three") {
		t.Errorf("missing requested lines: %q", out)
	}
	if strings.Contains(out, "one") || strings.Contains(out, "four") {
		t.Errorf("returned lines outside the requested range: %q", out)
	}
}

func TestSearchAndCallers(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"main.go":           "package main\n\nfunc main() {\n\tParseInput(userData)\n}\n",
		"parse.go":          "package main\n\nfunc ParseInput(s string) {}\n",
		"node_modules/x.js": "ParseInput(evil)\n",
	}
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	v, err := New(root)
	if err != nil {
		t.Fatal(err)
	}

	defs, err := v.FindDefinition("pkg/mod.ParseInput")
	if err != nil {
		t.Fatal(err)
	}
	if len(defs) == 0 || defs[0].File != "parse.go" {
		t.Errorf("FindDefinition = %+v, want a hit in parse.go", defs)
	}

	for _, d := range defs {
		if d.File == "main.go" {
			t.Errorf("call site reported as a definition: %+v", d)
		}
	}

	for _, tc := range []struct{ name, body, want string }{
		{"java", "public class A {\n  public void Handle(String s) {}\n}\n", "Handle"},
		{"python", "def Handle(s):\n    pass\n", "Handle"},
		{"c", "static int Handle(char *s) {\n  return 0;\n}\n", "Handle"},
		{"js", "const Handle = (s) => { return s; }\n", "Handle"},
	} {
		sub := t.TempDir()
		if err := os.WriteFile(filepath.Join(sub, "f."+tc.name), []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		sv, err := New(sub)
		if err != nil {
			t.Fatal(err)
		}
		got, err := sv.FindDefinition(tc.want)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 0 {
			t.Errorf("%s: FindDefinition(%q) found nothing in %q", tc.name, tc.want, tc.body)
		}
	}

	callers, err := v.FindCallers("ParseInput")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range callers {
		if strings.HasPrefix(c.File, "node_modules/") {
			t.Errorf("searched inside node_modules: %+v", c)
		}
		if c.File == "parse.go" {
			t.Errorf("declaration reported as a call site: %+v", c)
		}
	}
	if len(callers) != 1 || callers[0].File != "main.go" {
		t.Errorf("FindCallers = %+v, want one hit in main.go", callers)
	}

	eps, err := v.Entrypoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) == 0 {
		t.Error("Entrypoints found no main()")
	}
}

func TestStateDirIsNotVisible(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, StateDir)
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "report.json"), []byte(`{"verdict":"not_exploitable"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("package main\n// verdict marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	v, err := New(root)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := v.ReadFile(StateDir+"/report.json", 1, 10); err == nil {
		t.Error("reading our own report was allowed; a prior run's verdicts must not become evidence")
	}

	ms, err := v.Search("verdict", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if strings.HasPrefix(m.File, StateDir) {
			t.Errorf("search returned a file from %s: %+v", StateDir, m)
		}
	}
	if len(ms) != 1 || ms[0].File != "app.go" {
		t.Errorf("search = %+v, want only the app.go hit", ms)
	}
}
