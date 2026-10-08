// Package config loads a module's .quality.yaml: thresholds, rules and baseline locations.
// Everything has a default, so a module without the file still gets every generic check.
package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const FileName = ".quality.yaml"

type Config struct {
	Crap     Crap     `yaml:"crap"`
	Mutation Mutation `yaml:"mutation"`
	Arch     Arch     `yaml:"arch"`
	Security Security `yaml:"security"`
	Specs    Specs    `yaml:"specs"`
}

type Crap struct {
	Max      float64 `yaml:"max"`
	Baseline string  `yaml:"baseline"`
}

type Mutation struct {
	// Workers caps gremlins' parallelism: its default (one per CPU) can exhaust a laptop's memory.
	Workers            int               `yaml:"workers"`
	TimeoutCoefficient int               `yaml:"timeout-coefficient"`
	Packages           []MutationPackage `yaml:"packages"`
}

// MutationPackage sets thresholds per package, so a package can join at its current level
// and only go up from there.
type MutationPackage struct {
	Path           string  `yaml:"path"`
	Efficacy       float64 `yaml:"efficacy"`
	MutantCoverage float64 `yaml:"mutant-coverage"`
}

type Arch struct {
	Rules     []ArchRule `yaml:"rules"`
	InlineSQL *InlineSQL `yaml:"inline-sql"`
}

// ArchRule forbids packages matching Package from importing anything matching Deny. Both are
// regular expressions; {module} stands for the module path.
type ArchRule struct {
	Package string `yaml:"package"`
	Deny    string `yaml:"deny"`
	Reason  string `yaml:"reason"`
}

type InlineSQL struct {
	Dirs     []string `yaml:"dirs"`
	Baseline string   `yaml:"baseline"`
}

type Security struct {
	Govulncheck Check     `yaml:"govulncheck"`
	Gosec       Baselined `yaml:"gosec"`
	Gitleaks    Baselined `yaml:"gitleaks"`
}

type Check struct {
	Disabled bool `yaml:"disabled"`
}

type Baselined struct {
	Disabled bool   `yaml:"disabled"`
	Baseline string `yaml:"baseline"`
}

type Specs struct {
	Dir string `yaml:"dir"`
}

func Default() Config {
	return Config{
		Crap:     Crap{Max: 30, Baseline: "quality/crap-baseline.txt"},
		Mutation: Mutation{Workers: 2, TimeoutCoefficient: 10},
		Security: Security{
			Gosec:    Baselined{Baseline: "quality/gosec-baseline.txt"},
			Gitleaks: Baselined{Baseline: "quality/gitleaks-baseline.txt"},
		},
		Specs: Specs{Dir: "specs"},
	}
}

// Load reads dir/.quality.yaml over the defaults. Unknown keys are an error, so a typo in a
// threshold name cannot silently disable it.
func Load(dir string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return cfg, fmt.Errorf("%s: %w", FileName, err)
	}
	return cfg, cfg.validate()
}

func (c Config) validate() error {
	if c.Mutation.Workers < 1 {
		return fmt.Errorf("%s: mutation.workers must be at least 1", FileName)
	}
	for _, p := range c.Mutation.Packages {
		if p.Path == "" {
			return fmt.Errorf("%s: every mutation package needs a path", FileName)
		}
		if p.Efficacy < 0 || p.Efficacy > 100 || p.MutantCoverage < 0 || p.MutantCoverage > 100 {
			return fmt.Errorf("%s: thresholds for %s must be between 0 and 100", FileName, p.Path)
		}
	}
	for _, r := range c.Arch.Rules {
		if r.Package == "" || r.Deny == "" {
			return fmt.Errorf("%s: every arch rule needs package and deny", FileName)
		}
	}
	return nil
}

// ModulePath returns the module path declared in dir/go.mod.
func ModulePath(dir string) (string, error) {
	f, err := os.Open(filepath.Join(dir, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("run goquality from a module root: %w", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(scanner.Text()), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`), nil
		}
	}
	return "", fmt.Errorf("no module line in %s", filepath.Join(dir, "go.mod"))
}
