package crap

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/cover"
)

const source = `package sample

type T struct{}

func Plain() {}

func Branches(a, b int) int {
	if a > 0 && b > 0 {
		return 1
	}
	for i := 0; i < a; i++ {
		switch i {
		case 1:
			return 2
		default:
		}
	}
	return 0
}

func (t *T) Method() func() bool {
	return func() bool { return true || false }
}

func (t T) Value() {}
`

func parse(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "sample.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	funcs := map[string]*ast.FuncDecl{}
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok {
			funcs[FuncName(fn)] = fn
		}
	}
	return funcs
}

func TestComplexityAndNames(t *testing.T) {
	funcs := parse(t)
	want := map[string]int{
		"Plain":       1,
		"Branches":    5, // 1 + if + && + for + case 1 (default does not count)
		"(*T).Method": 2, // the closure's || counts toward the enclosing function
		"(T).Value":   1,
	}
	for name, complexity := range want {
		fn, ok := funcs[name]
		if !ok {
			t.Fatalf("no function named %q (have %v)", name, keys(funcs))
		}
		if got := Complexity(fn); got != complexity {
			t.Errorf("Complexity(%s) = %d, want %d", name, got, complexity)
		}
	}
}

func TestScore(t *testing.T) {
	cases := []struct {
		f    Func
		want float64
	}{
		{Func{Complexity: 10, Coverage: 0}, 110},
		{Func{Complexity: 10, Coverage: 1}, 10},
		{Func{Complexity: 53, Coverage: 0}, 2862},
		{Func{Complexity: 4, Coverage: 0.5}, 4*4*0.125 + 4},
	}
	for _, c := range cases {
		if got := c.f.Score(); got != c.want {
			t.Errorf("Score(complexity %d, coverage %.2f) = %v, want %v", c.f.Complexity, c.f.Coverage, got, c.want)
		}
	}
}

func TestAnalyzeJoinsCoverageByFunction(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.go"), "package a\n\nfunc Covered(x int) int {\n\tif x > 0 {\n\t\treturn 1\n\t}\n\treturn 0\n}\n\nfunc Uncovered() int {\n\treturn 2\n}\n")
	write(t, filepath.Join(dir, "a_test.go"), "package a\n\nfunc helper() { if true {} }\n")
	write(t, filepath.Join(dir, "nested", "go.mod"), "module other\n")
	write(t, filepath.Join(dir, "nested", "b.go"), "package b\n\nfunc Skipped() {}\n")

	profile := &cover.Profile{FileName: "example.com/m/a.go", Mode: "set", Blocks: []cover.ProfileBlock{
		{StartLine: 3, StartCol: 26, EndLine: 4, EndCol: 11, NumStmt: 1, Count: 1}, // if x > 0
		{StartLine: 4, StartCol: 11, EndLine: 6, EndCol: 3, NumStmt: 1, Count: 0},  // return 1
		{StartLine: 7, StartCol: 2, EndLine: 7, EndCol: 10, NumStmt: 1, Count: 1},  // return 0
		{StartLine: 10, StartCol: 21, EndLine: 12, EndCol: 2, NumStmt: 1, Count: 0},
	}}
	funcs, err := Analyze(dir, "example.com/m", []*cover.Profile{profile})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Func{}
	for _, f := range funcs {
		got[f.Key] = f
	}
	if len(got) != 2 {
		t.Fatalf("analyzed %v, want only a.go's two functions (no tests, no nested module)", keysOf(got))
	}
	if f := got["a.go:Covered"]; f.Complexity != 2 || f.Coverage < 0.66 || f.Coverage > 0.67 {
		t.Errorf("Covered = %+v, want complexity 2 and 2/3 coverage", f)
	}
	if f := got["a.go:Uncovered"]; f.Coverage != 0 {
		t.Errorf("Uncovered coverage = %v, want 0", f.Coverage)
	}
}

func TestCheck(t *testing.T) {
	funcs := []Func{
		{Key: "a.go:Debt", Complexity: 10},               // 110, recorded at 110
		{Key: "a.go:Worse", Complexity: 12},              // 156, recorded at 110
		{Key: "a.go:Fixed", Complexity: 10, Coverage: 1}, // 10, recorded at 110
		{Key: "a.go:Fresh", Complexity: 8},               // 72, not recorded
		{Key: "a.go:Fine", Complexity: 3, Coverage: 1},   // 3
	}
	base := Baseline{"a.go:Debt": 110, "a.go:Worse": 110, "a.go:Fixed": 110}
	r := Check(funcs, base, 30)
	if len(r.New) != 1 || !strings.HasPrefix(r.New[0], "a.go:Fresh") {
		t.Errorf("New = %v", r.New)
	}
	if len(r.Worse) != 1 || !strings.HasPrefix(r.Worse[0], "a.go:Worse") {
		t.Errorf("Worse = %v", r.Worse)
	}
	if len(r.Improved) != 1 || !strings.HasPrefix(r.Improved[0], "a.go:Fixed") {
		t.Errorf("Improved = %v", r.Improved)
	}
}

func TestRatchetOnlyShrinks(t *testing.T) {
	base := Baseline{"a.go:Debt": 110, "a.go:Fixed": 110}

	t.Run("records improvements", func(t *testing.T) {
		funcs := []Func{
			{Key: "a.go:Debt", Complexity: 10, Coverage: 0.2}, // 100 × 0.512 + 10 = 61.2, still above 30
			{Key: "a.go:Fixed", Complexity: 10, Coverage: 1},  // 10: leaves the baseline
		}
		next, r := Ratchet(funcs, base, 30)
		if r.Failed() {
			t.Fatalf("refused an improvement: %+v", r)
		}
		if len(next) != 1 || next["a.go:Debt"] != 61.2 {
			t.Errorf("next = %v, want only Debt lowered to 61.2", next)
		}
	})

	t.Run("refuses a new function", func(t *testing.T) {
		funcs := []Func{{Key: "a.go:Debt", Complexity: 10}, {Key: "a.go:Fresh", Complexity: 20}}
		next, r := Ratchet(funcs, base, 30)
		if !r.Failed() || len(next) != len(base) {
			t.Errorf("accepted a new function into the baseline: %v", next)
		}
	})

	t.Run("refuses a worse score", func(t *testing.T) {
		funcs := []Func{{Key: "a.go:Debt", Complexity: 20}}
		if _, r := Ratchet(funcs, base, 30); !r.Failed() {
			t.Error("accepted a worse score")
		}
	})
}

func TestBaselineRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quality", "crap-baseline.txt")
	if _, exists, err := ReadBaseline(path); exists || err != nil {
		t.Fatalf("missing baseline: exists=%v err=%v", exists, err)
	}
	base := Baseline{"a.go:(*T).Big": 2862, "b.go:Small": 31.5}
	if err := WriteBaseline(path, base, 30); err != nil {
		t.Fatal(err)
	}
	read, exists, err := ReadBaseline(path)
	if err != nil || !exists || len(read) != 2 || read["a.go:(*T).Big"] != 2862 || read["b.go:Small"] != 31.5 {
		t.Fatalf("read back %v (exists=%v, err=%v)", read, exists, err)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func keys(m map[string]*ast.FuncDecl) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysOf(m map[string]Func) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCoverageBlockBoundaries(t *testing.T) {
	// A function from 3:10 to 5:2. Blocks that only touch its edges belong to its neighbours.
	start := token.Position{Line: 3, Column: 10}
	end := token.Position{Line: 5, Column: 2}
	p := &cover.Profile{Blocks: []cover.ProfileBlock{
		{StartLine: 1, StartCol: 1, EndLine: 2, EndCol: 5, NumStmt: 9, Count: 1},  // before: excluded
		{StartLine: 1, StartCol: 1, EndLine: 3, EndCol: 10, NumStmt: 9, Count: 1}, // ends at the start: excluded
		{StartLine: 2, StartCol: 1, EndLine: 3, EndCol: 12, NumStmt: 1, Count: 1}, // overlaps the start line: included
		{StartLine: 3, StartCol: 10, EndLine: 4, EndCol: 5, NumStmt: 1, Count: 1}, // inside: included
		{StartLine: 5, StartCol: 1, EndLine: 5, EndCol: 2, NumStmt: 1, Count: 0},  // on the end line, before the end: included
		{StartLine: 5, StartCol: 2, EndLine: 6, EndCol: 1, NumStmt: 9, Count: 1},  // starts at the end: excluded
		{StartLine: 7, StartCol: 1, EndLine: 8, EndCol: 1, NumStmt: 9, Count: 1},  // after: excluded
	}}
	if got := coverage(p, start, end); got != 2.0/3.0 {
		t.Errorf("coverage = %v, want 2/3", got)
	}
}

func TestComplexityIgnoresOnlyDefaultCases(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "s.go", `package s

func F(x int, c chan int) {
	switch x {
	case 1:
	case 2:
	default:
	}
	select {
	case <-c:
	case c <- 1:
	default:
	}
}
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := Complexity(file.Decls[0].(*ast.FuncDecl)); got != 5 { // 1 + case 1 + case 2 + case <-c + case c <- 1
		t.Errorf("Complexity = %d, want 5", got)
	}
}

func TestAnalyzeSkipsToolingDirectories(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.go"), "package a\n\nfunc Kept() {}\n")
	for _, skipped := range []string{".git", "_build", "vendor", "testdata"} {
		write(t, filepath.Join(dir, skipped, "x.go"), "package x\n\nfunc Skipped() {}\n")
	}
	write(t, filepath.Join(dir, "sub", "b.go"), "package sub\n\nfunc AlsoKept() {}\n")
	funcs, err := Analyze(dir, "example.com/m", nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range funcs {
		got = append(got, f.Key)
	}
	if strings.Join(got, ",") != "a.go:Kept,sub/b.go:AlsoKept" {
		t.Errorf("analyzed %v", got)
	}
}

func TestRatchetExcludesScoresAtTheMaximum(t *testing.T) {
	// Complexity 5 at 0% coverage scores exactly 30.
	next, r := Ratchet([]Func{{Key: "a.go:Edge", Complexity: 5}}, Baseline{"a.go:Edge": 30}, 30)
	if r.Failed() || len(next) != 0 {
		t.Errorf("a score equal to the maximum stayed in the baseline: %v", next)
	}
}

func TestReportMessages(t *testing.T) {
	r := Check([]Func{
		{Key: "a.go:New", Complexity: 10, Coverage: 0.2}, // 61.2
		{Key: "a.go:Worse", Complexity: 20, Coverage: 0.5},
	}, Baseline{"a.go:Worse": 31}, 30)
	if len(r.New) != 1 || !strings.Contains(r.New[0], "complexity 10, coverage 20.0%") {
		t.Errorf("New = %v", r.New)
	}
	if len(r.Worse) != 1 || !strings.Contains(r.Worse[0], "complexity 20, coverage 50.0%") {
		t.Errorf("Worse = %v", r.Worse)
	}
}

func TestBaselineFileOrderAndErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.txt")
	if err := WriteBaseline(path, Baseline{"b.go:Mid": 50, "z.go:Top": 900, "c.go:Tie": 50}, 30); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var entries []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if !strings.HasPrefix(line, "#") {
			entries = append(entries, line)
		}
	}
	if strings.Join(entries, "|") != "900.0 z.go:Top|50.0 b.go:Mid|50.0 c.go:Tie" {
		t.Errorf("entries = %v, want worst first, ties by name", entries)
	}

	os.WriteFile(path, []byte("# header\n10.0 a.go:F\nnot-a-number a.go:G\n"), 0o600)
	if _, _, err := ReadBaseline(path); err == nil || !strings.Contains(err.Error(), ":3:") {
		t.Errorf("err = %v, want the line number 3", err)
	}
}
