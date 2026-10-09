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

func TestParseGosec(t *testing.T) {
	found := ParseGosec(gosecOutput, "/repo/src/api")
	if len(found) != 3 || found[0].Key() != "G304 utils/database.go" || found[2].Key() != "G501 utils/hash.go" {
		t.Fatalf("findings = %+v", found)
	}
	if found[1].Text != strings.Split(gosecOutput, "\n")[1] {
		t.Errorf("Text = %q, want the whole gosec line", found[1].Text)
	}
	if outside := ParseGosec("/elsewhere/x.go:1:1: m (Rule:G101, Severity:HIGH, Confidence:LOW)", "/repo/src/api"); outside[0].File != "/elsewhere/x.go" {
		t.Errorf("a file outside the module was made relative: %q", outside[0].File)
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
