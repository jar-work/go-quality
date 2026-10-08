package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefaultsWithoutFile(t *testing.T) {
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Crap.Max != 30 || cfg.Mutation.Workers != 2 || cfg.Security.Gosec.Baseline != "quality/gosec-baseline.txt" {
		t.Errorf("defaults = %+v", cfg)
	}
}

func TestLoadKeepsDefaultsForMissingKeys(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, FileName), []byte("crap:\n  max: 20\nmutation:\n  packages:\n    - path: ./p\n      efficacy: 90\n"), 0o644)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Crap.Max != 20 || cfg.Crap.Baseline != "quality/crap-baseline.txt" || cfg.Mutation.Workers != 2 {
		t.Errorf("cfg = %+v", cfg)
	}
	if len(cfg.Mutation.Packages) != 1 || cfg.Mutation.Packages[0].Efficacy != 90 {
		t.Errorf("packages = %+v", cfg.Mutation.Packages)
	}
}

func TestLoadRejectsMistakes(t *testing.T) {
	for name, content := range map[string]string{
		"typo in a key":        "crap:\n  maxx: 20\n",
		"threshold above 100":  "mutation:\n  packages:\n    - path: ./p\n      efficacy: 150\n",
		"package without path": "mutation:\n  packages:\n    - efficacy: 90\n",
		"zero workers":         "mutation:\n  workers: 0\n",
		"rule without deny":    "arch:\n  rules:\n    - package: x\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, FileName), []byte(content), 0o644)
			if _, err := Load(dir); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestModulePath(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("// comment\nmodule github.com/x/m\n\ngo 1.26\n"), 0o644)
	if got, err := ModulePath(dir); err != nil || got != "github.com/x/m" {
		t.Errorf("ModulePath = %q, %v", got, err)
	}
	if _, err := ModulePath(t.TempDir()); err == nil || !strings.Contains(err.Error(), "module root") {
		t.Errorf("missing go.mod: %v", err)
	}
}

func TestLoadAcceptsBoundaryValues(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, FileName), []byte("mutation:\n  workers: 1\n  packages:\n    - {path: ./a, efficacy: 0, mutant-coverage: 100}\n    - {path: ./b, efficacy: 100, mutant-coverage: 0}\n"), 0o600)
	if _, err := Load(dir); err != nil {
		t.Errorf("rejected valid boundary values: %v", err)
	}
	for name, content := range map[string]string{
		"negative efficacy":         "mutation:\n  packages:\n    - {path: ./a, efficacy: -1}\n",
		"negative mutant coverage":  "mutation:\n  packages:\n    - {path: ./a, mutant-coverage: -1}\n",
		"mutant coverage above 100": "mutation:\n  packages:\n    - {path: ./a, mutant-coverage: 101}\n",
		"rule without package":      "arch:\n  rules:\n    - deny: x\n",
	} {
		os.WriteFile(filepath.Join(dir, FileName), []byte(content), 0o600)
		if _, err := Load(dir); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
