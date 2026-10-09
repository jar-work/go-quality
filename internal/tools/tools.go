// Package tools pins the external tools goquality runs.
//
// The Go tools are invoked with `go run pkg@version`: upgrading one here upgrades it in every
// repository on its next goquality release. hadolint and trivy are not Go programs, so they must
// be installed (brew, or their GitHub Actions in CI); goquality warns when their version differs.
package tools

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/jar-work/go-quality/internal/execx"
)

const (
	Gremlins    = "github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0"
	Gosec       = "github.com/securego/gosec/v2/cmd/gosec@v2.29.0"
	Govulncheck = "golang.org/x/vuln/cmd/govulncheck@v1.8.0"
	Gitleaks    = "github.com/zricethezav/gitleaks/v8@v8.30.1"
)

// Binary is an external tool that must be on PATH.
type Binary struct {
	Name, Version, Install string
}

var (
	Hadolint = Binary{Name: "hadolint", Version: "2.15.1", Install: "brew install hadolint (CI: hadolint/hadolint-action)"}
	Trivy    = Binary{Name: "trivy", Version: "0.75.0", Install: "brew install trivy (CI: aquasecurity/setup-trivy)"}
)

var versionRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

// Check fails when the binary is missing. When its version differs from the pinned one it
// returns a warning instead: results may differ from CI, but the check can still run.
func (b Binary) Check() (warning string, err error) {
	if _, err := exec.LookPath(b.Name); err != nil {
		return "", fmt.Errorf("%s is not installed: %s", b.Name, b.Install)
	}
	out, code, err := execx.Run("", nil, nil, b.Name, "--version")
	if err != nil || code != 0 {
		return "", fmt.Errorf("%s --version failed: %v %s", b.Name, err, out)
	}
	return VersionWarning(b, out), nil
}

// VersionWarning compares a `--version` output with the pinned version.
func VersionWarning(b Binary, versionOutput string) string {
	got := versionRe.FindString(versionOutput)
	if got == b.Version {
		return ""
	}
	if got == "" {
		got = strings.TrimSpace(versionOutput)
	}
	return fmt.Sprintf("%s %s is installed, goquality is pinned to %s: results may differ from CI", b.Name, got, b.Version)
}
