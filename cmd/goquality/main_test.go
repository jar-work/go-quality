package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HRECL/go-quality/internal/config"
	"github.com/HRECL/go-quality/internal/crap"
	"github.com/HRECL/go-quality/internal/mutation"
	"github.com/HRECL/go-quality/internal/security"
)

// newModule writes a small module: a tested function, an untested complex one, and a package
// that the arch rule below forbids from importing the root package.
func newModule(t *testing.T, config string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":         "module example.com/sample\n\ngo 1.26\n",
		"sample.go":      "package sample\n\nfunc Sign(x int) int {\n\tif x < 0 {\n\t\treturn -1\n\t}\n\treturn 1\n}\n",
		"sample_test.go": "package sample\n\nimport \"testing\"\n\nfunc TestSign(t *testing.T) {\n\tif Sign(-2) != -1 || Sign(3) != 1 {\n\t\tt.Fatal()\n\t}\n}\n",
		"low/low.go":     "package low\n\nimport _ \"example.com/sample\"\n",
		".quality.yaml":  config,
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const offlineConfig = "security:\n  govulncheck: {disabled: true}\n  gosec: {disabled: true}\n  gitleaks: {disabled: true}\n"

const complexFunc = `package sample

func Classify(a, b, c int) string {
	switch {
	case a > 0 && b > 0:
		return "both"
	case a > 0 || c > 0:
		return "one"
	}
	for i := 0; i < a; i++ {
		if i == b {
			return "found"
		}
	}
	return "none"
}
`

func runIn(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(dir, args, &out)
	return out.String(), err
}

func TestCheckPassesOnACleanModule(t *testing.T) {
	dir := newModule(t, offlineConfig)
	out, err := runIn(t, dir, "check")
	if err != nil {
		t.Fatalf("check failed: %v\n%s", err, out)
	}
	for _, want := range []string{"Architecture: ok", "Security: ok", "Tests: ok", "CRAP: ok", "Specs: no .feature files", "Mutation: no packages configured", "Quality: ok"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestCheckReportsEveryFailure(t *testing.T) {
	cfg := offlineConfig + "crap:\n  max: 10\narch:\n  rules:\n    - package: '^{module}/low$'\n      deny: '^{module}$'\n      reason: low does not import the root\n"
	dir := newModule(t, cfg)
	os.WriteFile(filepath.Join(dir, "complex.go"), []byte(complexFunc), 0o600)

	out, err := runIn(t, dir, "check", "--skip", "mutation")
	if !errors.Is(err, errFailed) {
		t.Fatalf("err = %v, want errFailed\n%s", err, out)
	}
	for _, want := range []string{
		"example.com/sample/low imports example.com/sample (low does not import the root)",
		"NEW        complex.go:Classify: CRAP 56.0 > 10",
		"== mutation (skipped)",
		"Quality: FAILED (arch, crap)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestCrapSkippedWhenTestsFail(t *testing.T) {
	dir := newModule(t, offlineConfig)
	os.WriteFile(filepath.Join(dir, "fail_test.go"), []byte("package sample\n\nimport \"testing\"\n\nfunc TestFail(t *testing.T) { t.Fatal(\"boom\") }\n"), 0o600)
	out, err := runIn(t, dir, "check", "--skip", "arch,security,specs,mutation")
	if !errors.Is(err, errFailed) || !strings.Contains(out, "== crap (skipped: tests failed)") {
		t.Errorf("err = %v\n%s", err, out)
	}
}

func TestCrapBaselineLifecycle(t *testing.T) {
	dir := newModule(t, offlineConfig+"crap:\n  max: 10\n")
	os.WriteFile(filepath.Join(dir, "complex.go"), []byte(complexFunc), 0o600)
	baseline := filepath.Join(dir, "quality", "crap-baseline.txt")

	if out, err := runIn(t, dir, "crap", "--update-baseline"); !errors.Is(err, errFailed) || !strings.Contains(out, "NEW") {
		t.Fatalf("update created entries from nothing: %v\n%s", err, out)
	}
	if _, err := os.Stat(baseline); err == nil {
		t.Fatal("a refused update wrote the baseline")
	}

	if out, err := runIn(t, dir, "crap", "--init-baseline"); err != nil || !strings.Contains(out, "Baseline created: 1 functions") {
		t.Fatalf("init: %v\n%s", err, out)
	}
	if out, err := runIn(t, dir, "crap"); err != nil {
		t.Fatalf("check after init: %v\n%s", err, out)
	}
	if _, err := runIn(t, dir, "crap", "--init-baseline"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second init: %v", err)
	}

	// Testing Classify fully brings it below the maximum: the update removes it.
	os.WriteFile(filepath.Join(dir, "complex_test.go"), []byte("package sample\n\nimport \"testing\"\n\nfunc TestClassify(t *testing.T) {\n\tfor _, c := range [][3]int{{1, 1, 0}, {1, 0, 0}, {0, 0, 1}, {3, 1, -1}, {2, 5, -1}, {0, 0, 0}} {\n\t\tClassify(c[0], c[1], c[2])\n\t}\n}\n"), 0o600)
	if out, err := runIn(t, dir, "crap"); err != nil || !strings.Contains(out, "IMPROVED") {
		t.Fatalf("improvement not reported: %v\n%s", err, out)
	}
	if out, err := runIn(t, dir, "crap", "--update-baseline"); err != nil || !strings.Contains(out, "Baseline updated: 0 functions above CRAP 10 (was 1)") {
		t.Fatalf("update: %v\n%s", err, out)
	}
	base, _, err := crap.ReadBaseline(baseline)
	if err != nil || len(base) != 0 {
		t.Errorf("baseline after update = %v (%v)", base, err)
	}
}

func TestSpecsRunWhenFeaturesExist(t *testing.T) {
	dir := newModule(t, offlineConfig)
	os.MkdirAll(filepath.Join(dir, "specs"), 0o750)
	os.WriteFile(filepath.Join(dir, "specs", "sign.feature"), []byte("Feature: sign\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "specs", "specs_test.go"), []byte("package specs\n\nimport \"testing\"\n\nfunc TestFeatures(t *testing.T) { t.Fatal(\"step undefined\") }\n"), 0o600)
	out, err := runIn(t, dir, "specs")
	if !errors.Is(err, errFailed) || !strings.Contains(out, "Specs: FAILED") {
		t.Errorf("err = %v\n%s", err, out)
	}
}

func TestRunArguments(t *testing.T) {
	dir := newModule(t, offlineConfig)
	if out, err := runIn(t, dir); err != nil || !strings.Contains(out, "usage: goquality") {
		t.Errorf("no command: %v\n%s", err, out)
	}
	if _, err := runIn(t, dir, "lint"); err == nil || !strings.Contains(err.Error(), `unknown command "lint"`) {
		t.Errorf("unknown command: %v", err)
	}
	if _, err := runIn(t, dir, "arch", "extra"); err == nil {
		t.Error("accepted extra arguments")
	}
	if _, err := runIn(t, dir, "check", "--nope"); err == nil {
		t.Error("accepted an unknown flag")
	}
	if _, err := runIn(t, t.TempDir(), "check"); err == nil || !strings.Contains(err.Error(), "module root") {
		t.Errorf("outside a module: %v", err)
	}
	os.WriteFile(filepath.Join(dir, ".quality.yaml"), []byte("crap:\n  maxx: 1\n"), 0o600)
	if _, err := runIn(t, dir, "check"); err == nil {
		t.Error("accepted an invalid config")
	}
}

func TestReports(t *testing.T) {
	var out bytes.Buffer
	findings := []security.Finding{{Rule: "G401", File: "a.go", Text: "a.go:5: weak crypto (Rule:G401"}}
	if reportGosec(&out, findings, map[string]int{"G104 main.go": 1}, "quality/gosec.txt") {
		t.Error("gosec passed with a new finding")
	}
	if !strings.Contains(out.String(), "FIXED  G104 main.go: remove it from quality/gosec.txt") {
		t.Errorf("gosec output:\n%s", out.String())
	}
	if !reportGosec(&out, nil, nil, "") {
		t.Error("gosec failed with no findings")
	}

	out.Reset()
	reportGitleaks(&out, false)
	if !strings.Contains(out.String(), "rotate it") {
		t.Errorf("gitleaks output: %s", out.String())
	}

	out.Reset()
	pkg := config.MutationPackage{Path: "./p", Efficacy: 90}
	if !reportMutation(&out, mutation.Summary{Killed: 5, Lived: 5, Efficacy: 50}, pkg) || !strings.Contains(out.String(), "LIVED mutants") {
		t.Errorf("mutation below threshold passed:\n%s", out.String())
	}
	if reportMutation(&out, mutation.Summary{Killed: 10, Efficacy: 100}, pkg) {
		t.Error("mutation above threshold failed")
	}
}

func TestMutationWithoutPackagesIsSkipped(t *testing.T) {
	dir := newModule(t, offlineConfig)
	if out, err := runIn(t, dir, "mutation"); err != nil || !strings.Contains(out, "skipped") {
		t.Errorf("%v\n%s", err, out)
	}
}
