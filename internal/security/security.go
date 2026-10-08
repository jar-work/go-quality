// Package security runs the OWASP-oriented checks: govulncheck (vulnerable dependencies),
// gosec (static analysis) and gitleaks (committed secrets).
package security

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/HRECL/go-quality/internal/execx"
	"github.com/HRECL/go-quality/internal/tools"
)

// Govulncheck fails when a vulnerability is reachable from the module's code. There is no
// baseline: a reachable vulnerability is fixed by upgrading the dependency.
func Govulncheck(dir string, out io.Writer) (bool, error) {
	_, code, err := execx.Run(dir, nil, out, "go", "run", tools.Govulncheck, "./...")
	return code == 0, err
}

type Finding struct {
	Rule, File, Text string
}

// Key is how a finding is recorded in the baseline: rule and file, not line, so unrelated
// edits that move code around do not invalidate it.
func (f Finding) Key() string { return f.Rule + " " + f.File }

// Gosec returns gosec's findings, with files relative to dir.
func Gosec(dir string) ([]Finding, error) {
	out, _, err := execx.Run(dir, nil, nil, "go", "run", tools.Gosec, "-quiet", "-tests=false", "-fmt=golint", "./...")
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	return ParseGosec(out, abs), nil
}

// golint format: "<path>:<line>:<col>: [CWE-x] <message> (Rule:G304, Severity:MEDIUM, Confidence:HIGH)"
var gosecLineRe = regexp.MustCompile(`^(.+?):\d+:\d+: .*\(Rule:(G\d+),`)

func ParseGosec(output, root string) []Finding {
	var findings []Finding
	for _, line := range strings.Split(output, "\n") {
		m := gosecLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		file := m[1]
		if rel, err := filepath.Rel(root, file); err == nil && !strings.HasPrefix(rel, "..") {
			file = filepath.ToSlash(rel)
		}
		findings = append(findings, Finding{Rule: m[2], File: file, Text: line})
	}
	return findings
}

// CompareGosec matches findings against baseline counts per key. fixed lists keys with fewer
// findings than recorded, which should be removed from the baseline.
func CompareGosec(findings []Finding, baseline map[string]int) (unexpected []Finding, fixed []string) {
	seen := map[string]int{}
	for _, f := range findings {
		seen[f.Key()]++
		if seen[f.Key()] > baseline[f.Key()] {
			unexpected = append(unexpected, f)
		}
	}
	for key, n := range baseline {
		if seen[key] < n {
			fixed = append(fixed, key)
		}
	}
	sort.Strings(fixed)
	return unexpected, fixed
}

// ReadGosecBaseline reads "<rule> <file>" lines, one per accepted finding; '#' starts a comment.
func ReadGosecBaseline(path string) (map[string]int, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]int{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	counts := map[string]int{}
	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s:%d: want \"<rule> <file>\"", path, line)
		}
		counts[fields[0]+" "+fields[1]]++
	}
	return counts, scanner.Err()
}

// Gitleaks scans the whole git history of the repository that contains dir. Known findings are
// listed by fingerprint in baseline (never by secret value). A missing baseline means none.
func Gitleaks(dir, baseline string, out io.Writer) (bool, error) {
	root, code, err := execx.Run(dir, nil, nil, "git", "rev-parse", "--show-toplevel")
	if err != nil || code != 0 {
		return false, fmt.Errorf("gitleaks needs a git repository: %s", strings.TrimSpace(root))
	}
	args, err := GitleaksArgs(dir, baseline, strings.TrimSpace(root))
	if err != nil {
		return false, err
	}
	_, code, err = execx.Run(dir, nil, out, "go", args...)
	return code == 0, err
}

// GitleaksArgs builds the `go run gitleaks` arguments. The baseline is passed only if it exists:
// gitleaks fails on a missing ignore file.
func GitleaksArgs(dir, baseline, repoRoot string) ([]string, error) {
	args := []string{"run", tools.Gitleaks, "git", "--no-banner", "--redact", "--log-level", "warn"}
	if baseline != "" {
		path, err := filepath.Abs(filepath.Join(dir, baseline))
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(path); err == nil {
			args = append(args, "--gitleaks-ignore-path", path)
		}
	}
	return append(args, repoRoot), nil
}
