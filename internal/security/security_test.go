package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const gosecOutput = `/repo/src/api/utils/database.go:23:21: [CWE-22] Potential file inclusion via variable (Rule:G304, Severity:MEDIUM, Confidence:HIGH)
/repo/src/api/utils/hash.go:5:42: [CWE-328] Use of weak cryptographic primitive (Rule:G401, Severity:MEDIUM, Confidence:HIGH)
/repo/src/api/utils/hash.go:3:8: [CWE-327] Blocklisted import crypto/md5: weak cryptographic primitive (Rule:G501, Severity:MEDIUM, Confidence:HIGH)
[gosec] some log line
`

func TestParseAndCompareGosec(t *testing.T) {
	findings := ParseGosec(gosecOutput, "/repo/src/api")
	if len(findings) != 3 || findings[0].Key() != "G304 utils/database.go" || findings[2].Key() != "G501 utils/hash.go" {
		t.Fatalf("findings = %+v", findings)
	}

	baseline := map[string]int{"G304 utils/database.go": 1, "G104 main.go": 1}
	unexpected, fixed := CompareGosec(findings, baseline)
	if len(unexpected) != 2 || unexpected[0].Rule != "G401" || unexpected[1].Rule != "G501" {
		t.Errorf("unexpected = %+v, want the two new findings in hash.go", unexpected)
	}
	if len(fixed) != 1 || fixed[0] != "G104 main.go" {
		t.Errorf("fixed = %v, want G104 main.go", fixed)
	}
}

func TestCompareGosecCountsRepeats(t *testing.T) {
	// Two findings of one rule in one file, with one recorded: the second is new.
	findings := ParseGosec(gosecOutput+"/repo/src/api/utils/database.go:40:2: x (Rule:G304, Severity:MEDIUM, Confidence:HIGH)\n", "/repo/src/api")
	unexpected, _ := CompareGosec(findings[:1], map[string]int{"G304 utils/database.go": 1})
	if len(unexpected) != 0 {
		t.Fatalf("one recorded finding reported as new: %+v", unexpected)
	}
	unexpected, _ = CompareGosec([]Finding{findings[0], findings[3]}, map[string]int{"G304 utils/database.go": 1})
	if len(unexpected) != 1 {
		t.Errorf("second G304 in the same file not reported: %+v", unexpected)
	}
}

func TestReadGosecBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gosec.txt")
	os.WriteFile(path, []byte("# why\nG304 utils/database.go\nG304 utils/database.go\n"), 0o644)
	counts, err := ReadGosecBaseline(path)
	if err != nil || counts["G304 utils/database.go"] != 2 {
		t.Errorf("counts = %v, err = %v", counts, err)
	}
	if counts, err := ReadGosecBaseline(filepath.Join(t.TempDir(), "missing.txt")); err != nil || len(counts) != 0 {
		t.Errorf("missing baseline: %v, %v", counts, err)
	}
}

func TestGitleaksArgs(t *testing.T) {
	dir := t.TempDir()
	args, err := GitleaksArgs(dir, "quality/gitleaks-baseline.txt", "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(args, " "), "--gitleaks-ignore-path") || args[len(args)-1] != "/repo" {
		t.Errorf("missing baseline passed to gitleaks: %v", args)
	}

	os.MkdirAll(filepath.Join(dir, "quality"), 0o750)
	os.WriteFile(filepath.Join(dir, "quality", "gitleaks-baseline.txt"), nil, 0o600)
	args, err = GitleaksArgs(dir, "quality/gitleaks-baseline.txt", "/repo")
	joined := strings.Join(args, " ")
	if err != nil || !strings.Contains(joined, "--gitleaks-ignore-path "+filepath.Join(dir, "quality", "gitleaks-baseline.txt")) {
		t.Errorf("existing baseline not passed: %v (%v)", args, err)
	}
	if !strings.Contains(joined, "--redact") {
		t.Errorf("gitleaks must run with --redact so secrets never reach the logs: %v", args)
	}
}

func TestReadGosecBaselineReportsTheBadLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gosec.txt")
	os.WriteFile(path, []byte("# header\nG304 a.go\nG304\n"), 0o600)
	if _, err := ReadGosecBaseline(path); err == nil || !strings.Contains(err.Error(), ":3:") {
		t.Errorf("err = %v, want line 3", err)
	}
}
