package codeview

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	maxFileBytes  = 2 << 20
	maxMatches    = 60
	maxLineLength = 400
)

const StateDir = ".gateai"

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, "target": true, ".venv": true, "venv": true,
	"__pycache__": true, ".idea": true, ".gradle": true, "testdata": true,
	StateDir: true,
}

type View struct {
	root string
}

func New(root string) (*View, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", resolved)
	}
	return &View{root: resolved}, nil
}

func (v *View) Root() string { return v.root }

var errEscape = errors.New("path escapes the repository root")

var errState = errors.New("path is inside " + StateDir + ", which holds this tool's own reports and cached verdicts; it is not part of the code under analysis and must not be used as evidence")

func inStateDir(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	return rel == StateDir || strings.HasPrefix(rel, StateDir+"/")
}

func (v *View) resolve(rel string) (string, error) {
	if rel == "" {
		return "", errors.New("empty path")
	}
	joined := filepath.Join(v.root, filepath.FromSlash(rel))
	if filepath.IsAbs(rel) {
		joined = filepath.Clean(rel)
	}
	clean := filepath.Clean(joined)
	if !within(v.root, clean) {
		return "", errEscape
	}
	if inStateDir(v.root, clean) {
		return "", errState
	}

	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		if !within(v.root, resolved) {
			return "", errEscape
		}
		return resolved, nil
	}
	return clean, nil
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

func (v *View) ReadFile(rel string, start, end int) (string, error) {
	abs, err := v.resolve(rel)
	if err != nil {
		return "", err
	}
	f, err := os.Open(abs)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if start < 1 {
		start = 1
	}
	if end <= 0 || end < start {
		end = start + 399
	}
	if end-start > 400 {
		end = start + 400
	}

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
		fmt.Fprintf(&b, "%6d| %s\n", n, clip(sc.Text()))
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if b.Len() == 0 {
		return fmt.Sprintf("(no lines in %s at %d-%d; file has %d lines)", rel, start, end, n), nil
	}
	return b.String(), nil
}

type Match struct {
	File string
	Line int
	Text string
}

func (v *View) Search(pattern, pathGlob string) ([]Match, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regexp: %w", err)
	}
	var matches []Match
	err = filepath.WalkDir(v.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if len(matches) >= maxMatches {
			return filepath.SkipAll
		}
		rel, _ := filepath.Rel(v.root, path)
		rel = filepath.ToSlash(rel)
		if pathGlob != "" && !globMatch(pathGlob, rel) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileBytes || !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		n := 0
		for sc.Scan() {
			n++
			line := sc.Text()
			if !re.MatchString(line) {
				continue
			}
			matches = append(matches, Match{File: rel, Line: n, Text: clip(strings.TrimSpace(line))})
			if len(matches) >= maxMatches {
				return filepath.SkipAll
			}
		}
		return nil
	})
	return matches, err
}

func globMatch(pattern, rel string) bool {
	if ok, _ := filepath.Match(pattern, rel); ok {
		return true
	}
	if ok, _ := filepath.Match(pattern, filepath.Base(rel)); ok {
		return true
	}

	if strings.HasPrefix(pattern, "**/") {
		if ok, _ := filepath.Match(pattern[3:], filepath.Base(rel)); ok {
			return true
		}
	}
	return strings.Contains(rel, strings.Trim(pattern, "*"))
}

var definitionPatterns = []string{
	`(?:func|def|fn|sub|function)\s+(?:\(\s*\w+[^)]*\)\s*)?%s\b`,
	`(?:class|interface|struct|type|trait|enum|record)\s+%s\b`,
	`^\s*(?:(?:public|private|protected|static|final|abstract|synchronized|override|async)\s+)+[\w<>\[\],.\s]*\b%s\s*\(`,
	`^\s*[\w<>\[\],.*&]+\s+\*?%s\s*\([^;]*\)\s*(?:const\s*)?\{`,
	`\b%s\s*[:=]\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*(?:=>|\{))`,
	`\b%s\s*=\s*(?:lambda|proc)\b`,
}

func (v *View) FindDefinition(symbol string) ([]Match, error) {
	sym := lastSegment(symbol)
	if sym == "" {
		return nil, errors.New("empty symbol")
	}
	quoted := regexp.QuoteMeta(sym)
	var all []Match
	seen := map[string]bool{}
	for _, p := range definitionPatterns {
		ms, err := v.Search(fmt.Sprintf(p, quoted), "")
		if err != nil {
			continue
		}
		for _, m := range ms {
			key := fmt.Sprintf("%s:%d", m.File, m.Line)
			if !seen[key] {
				seen[key] = true
				all = append(all, m)
			}
		}
		if len(all) >= maxMatches {
			break
		}
	}
	sortMatches(all)
	return all, nil
}

func (v *View) FindCallers(symbol string) ([]Match, error) {
	sym := lastSegment(symbol)
	if sym == "" {
		return nil, errors.New("empty symbol")
	}
	ms, err := v.Search(fmt.Sprintf(`\b%s\s*\(`, regexp.QuoteMeta(sym)), "")
	if err != nil {
		return nil, err
	}
	decl := regexp.MustCompile(`^\s*(?:func|def|fn|class|public|private|protected|static)\b`)
	out := ms[:0]
	for _, m := range ms {
		if decl.MatchString(m.Text) {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

var entrypointPatterns = []string{
	`func\s+main\s*\(`,
	`if\s+__name__\s*==\s*['"]__main__['"]`,
	`public\s+static\s+void\s+main\s*\(`,
	`@(?:Get|Post|Put|Delete|Patch|Request)Mapping`,
	`@app\.(?:route|get|post|put|delete)`,
	`@router\.(?:get|post|put|delete|patch)`,
	`app\.(?:get|post|put|delete|use)\s*\(`,
	`http\.HandleFunc|\.HandleFunc\(|mux\.Handle`,
	`(?:get|post|put|delete|patch)\s+['"]/`,
	`\$_(?:GET|POST|REQUEST|COOKIE)\b`,
	`\[HttpGet\]|\[HttpPost\]|\[Route\(`,
	`lambda_handler\s*\(|exports\.handler\s*=`,
	`os\.Args|sys\.argv|process\.argv`,
}

func (v *View) Entrypoints() ([]Match, error) {
	var all []Match
	seen := map[string]bool{}
	for _, p := range entrypointPatterns {
		ms, err := v.Search(p, "")
		if err != nil {
			continue
		}
		for _, m := range ms {
			key := fmt.Sprintf("%s:%d", m.File, m.Line)
			if !seen[key] {
				seen[key] = true
				all = append(all, m)
			}
		}
		if len(all) >= maxMatches {
			break
		}
	}
	sortMatches(all)
	return all, nil
}

func sortMatches(m []Match) {
	sort.Slice(m, func(i, j int) bool {
		if m[i].File != m[j].File {
			return m[i].File < m[j].File
		}
		return m[i].Line < m[j].Line
	})
}

func lastSegment(sym string) string {
	sym = strings.TrimSpace(sym)
	for _, sep := range []string{"::", ".", "/", "->"} {
		if i := strings.LastIndex(sym, sep); i >= 0 {
			sym = sym[i+len(sep):]
		}
	}
	return strings.Trim(sym, "()#$@ ")
}

func clip(s string) string {
	if len(s) <= maxLineLength {
		return s
	}
	return s[:maxLineLength] + " …(truncated)"
}
