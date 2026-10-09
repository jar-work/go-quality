// Package container checks how images are built and deployed: hadolint lints Dockerfiles
// (best practices, plus ShellCheck on RUN), and trivy checks Dockerfiles, Kubernetes manifests
// and Helm charts for misconfigurations. Both are external binaries that must be on PATH.
package container

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jar-work/go-quality/internal/execx"
	"github.com/jar-work/go-quality/internal/findings"
)

// Dockerfiles returns the Dockerfiles under dir (Dockerfile, Dockerfile.*, *.Dockerfile),
// relative to it.
func Dockerfiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if p != dir && (strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		lower := strings.ToLower(name)
		if lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile") {
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	return files, err
}

// hadolint levels from most to least severe.
var levels = []string{"error", "warning", "info", "style"}

// ValidLevel reports whether level is a hadolint level.
func ValidLevel(level string) bool { return slices.Contains(levels, level) }

// Hadolint lints files (relative to dir) and keeps findings at minLevel or more severe.
func Hadolint(dir string, files []string, minLevel string) ([]findings.Finding, error) {
	if len(files) == 0 {
		return nil, nil
	}
	out, _, err := execx.Run(dir, nil, nil, "hadolint", append([]string{"--no-fail", "--format", "json"}, files...)...)
	if err != nil {
		return nil, err
	}
	return ParseHadolint(out, minLevel)
}

type hadolintResult struct {
	Code    string `json:"code"`
	File    string `json:"file"`
	Level   string `json:"level"`
	Line    int    `json:"line"`
	Message string `json:"message"`
}

func ParseHadolint(output, minLevel string) ([]findings.Finding, error) {
	var results []hadolintResult
	if err := json.Unmarshal([]byte(output), &results); err != nil {
		return nil, fmt.Errorf("could not parse hadolint output: %w\n%s", err, output)
	}
	limit := slices.Index(levels, minLevel)
	var out []findings.Finding
	for _, r := range results {
		if i := slices.Index(levels, r.Level); i < 0 || i > limit {
			continue
		}
		out = append(out, findings.Finding{
			Rule: r.Code,
			File: r.File,
			Text: fmt.Sprintf("%s:%d: %s (%s) %s", r.File, r.Line, r.Code, r.Level, r.Message),
		})
	}
	return out, nil
}

// Trivy checks target (a path relative to dir: the module, a chart...) for misconfigurations of
// the given severities. helmValues are values files for rendering Helm charts, relative to dir.
func Trivy(dir, target string, helmValues, severities []string) ([]findings.Finding, error) {
	args := []string{"config", "--quiet", "--format", "json", "--severity", strings.Join(severities, ",")}
	for _, v := range helmValues {
		args = append(args, "--helm-values", v)
	}
	out, code, err := execx.Run(dir, nil, nil, "trivy", append(args, target)...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("trivy config %s failed:\n%s", target, out)
	}
	return ParseTrivy(out, target)
}

type trivyReport struct {
	Results []struct {
		Target            string `json:"Target"`
		Misconfigurations []struct {
			ID            string `json:"ID"`
			Title         string `json:"Title"`
			Severity      string `json:"Severity"`
			Status        string `json:"Status"`
			Resolution    string `json:"Resolution"`
			CauseMetadata struct {
				StartLine int `json:"StartLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
	} `json:"Results"`
}

// ParseTrivy reads trivy's JSON report. Its targets are relative to the scanned path, so they
// are joined to target to name files relative to the module.
func ParseTrivy(output, target string) ([]findings.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		return nil, fmt.Errorf("could not parse trivy output: %w\n%s", err, output)
	}
	var out []findings.Finding
	for _, r := range report.Results {
		file := path.Join(filepath.ToSlash(target), r.Target)
		for _, m := range r.Misconfigurations {
			if m.Status != "FAIL" {
				continue
			}
			out = append(out, findings.Finding{
				Rule: m.ID,
				File: file,
				Text: fmt.Sprintf("%s:%d: %s (%s) %s. %s", file, m.CauseMetadata.StartLine, m.ID, m.Severity, m.Title, m.Resolution),
			})
		}
	}
	return out, nil
}
