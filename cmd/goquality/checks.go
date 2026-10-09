package main

import (
	"fmt"
	"path/filepath"

	"github.com/jar-work/go-quality/internal/arch"
	"github.com/jar-work/go-quality/internal/container"
	"github.com/jar-work/go-quality/internal/crap"
	"github.com/jar-work/go-quality/internal/execx"
	"github.com/jar-work/go-quality/internal/findings"
	"github.com/jar-work/go-quality/internal/mutation"
	"github.com/jar-work/go-quality/internal/security"
	"github.com/jar-work/go-quality/internal/tools"

	"golang.org/x/tools/cover"
)

const coverFile = "coverage.out"

func (g *gate) arch() error {
	pkgs, err := arch.Packages(g.dir)
	if err != nil {
		return err
	}
	violations, err := arch.CheckDeps(pkgs, g.cfg.Arch.Rules, g.module)
	if err != nil {
		return err
	}
	for _, v := range violations {
		fmt.Fprintln(g.out, "DEPENDENCY  ", v)
	}
	sqlFailed, err := g.inlineSQL()
	if err != nil {
		return err
	}
	return verdict(g.out, "Architecture", len(violations) > 0 || sqlFailed)
}

func (g *gate) inlineSQL() (bool, error) {
	sql := g.cfg.Arch.InlineSQL
	if sql == nil {
		return false, nil
	}
	found, fixed, err := arch.InlineSQL(g.dir, *sql)
	for _, f := range found {
		fmt.Fprintln(g.out, "INLINE SQL  ", f, "(move the query to a .sql file)")
	}
	for _, f := range fixed {
		fmt.Fprintf(g.out, "FIXED        %s has no inline SQL left: remove it from %s\n", f, sql.Baseline)
	}
	return len(found) > 0, err
}

// security runs every enabled security check, even after one fails, so a single run shows all
// that needs fixing.
func (g *gate) security() error {
	failed := false
	for _, check := range []func() (bool, error){g.govulncheck, g.gosec, g.gitleaks, g.hadolint, g.trivy, g.dockerignore} {
		ok, err := check()
		if err != nil {
			return err
		}
		failed = failed || !ok
	}
	return verdict(g.out, "Security", failed)
}

func (g *gate) govulncheck() (bool, error) {
	if g.cfg.Security.Govulncheck.Disabled {
		return true, nil
	}
	fmt.Fprintln(g.out, "-- govulncheck")
	ok, err := security.Govulncheck(g.dir, g.out)
	if err == nil && !ok {
		fmt.Fprintln(g.out, "Vulnerable dependencies: upgrade them to the 'Fixed in' versions above.")
	}
	return ok, err
}

func (g *gate) gosec() (bool, error) {
	cfg := g.cfg.Security.Gosec
	if cfg.Disabled {
		return true, nil
	}
	fmt.Fprintln(g.out, "-- gosec")
	findings, err := security.Gosec(g.dir)
	if err != nil {
		return false, err
	}
	return g.compare("gosec", findings, cfg.Baseline)
}

func (g *gate) hadolint() (bool, error) {
	cfg := g.cfg.Security.Hadolint
	if cfg.Disabled {
		return true, nil
	}
	fmt.Fprintln(g.out, "-- hadolint")
	if err := g.requireBinary(tools.Hadolint); err != nil {
		return false, err
	}
	files, err := container.Dockerfiles(g.dir)
	if err != nil {
		return false, err
	}
	found, err := container.Hadolint(g.dir, files, cfg.Level)
	if err != nil {
		return false, err
	}
	return g.compare("hadolint", found, cfg.Baseline)
}

func (g *gate) trivy() (bool, error) {
	cfg := g.cfg.Security.Trivy
	if cfg.Disabled {
		return true, nil
	}
	fmt.Fprintln(g.out, "-- trivy")
	if err := g.requireBinary(tools.Trivy); err != nil {
		return false, err
	}
	var found []findings.Finding
	for _, target := range cfg.Targets {
		f, err := container.Trivy(g.dir, target.Path, target.HelmValues, cfg.Severities)
		if err != nil {
			return false, err
		}
		found = append(found, f...)
	}
	return g.compare("trivy", found, cfg.Baseline)
}

func (g *gate) dockerignore() (bool, error) {
	cfg := g.cfg.Security.Dockerignore
	if cfg.Disabled {
		return true, nil
	}
	fmt.Fprintln(g.out, "-- dockerignore")
	files, err := container.Dockerfiles(g.dir)
	if err != nil {
		return false, err
	}
	found, err := container.Dockerignore(g.dir, files)
	if err != nil {
		return false, err
	}
	return g.compare("dockerignore", found, cfg.Baseline)
}

// requireBinary fails when b is missing and prints a warning when its version is not the pinned one.
func (g *gate) requireBinary(b tools.Binary) error {
	warning, err := b.Check()
	if warning != "" {
		fmt.Fprintln(g.out, "warning:", warning)
	}
	return err
}

// compare reports findings against the baseline at path and returns whether the check passed.
func (g *gate) compare(name string, found []findings.Finding, path string) (bool, error) {
	baseline, err := findings.ReadBaseline(filepath.Join(g.dir, path))
	if err != nil {
		return false, err
	}
	return reportFindings(g.out, name, found, baseline, path), nil
}

func (g *gate) gitleaks() (bool, error) {
	cfg := g.cfg.Security.Gitleaks
	if cfg.Disabled {
		return true, nil
	}
	fmt.Fprintln(g.out, "-- gitleaks")
	ok, err := security.Gitleaks(g.dir, cfg.Baseline, g.out)
	if err == nil {
		reportGitleaks(g.out, ok)
	}
	return ok, err
}

func (g *gate) test() error {
	_, code, err := execx.Run(g.dir, nil, g.out, "go", "test", "-coverprofile="+coverFile, "./...")
	if err != nil {
		return err
	}
	return verdict(g.out, "Tests", code != 0)
}

// analyzeCrap scores the module's functions from the last test run and loads the baseline.
func (g *gate) analyzeCrap() ([]crap.Func, crap.Baseline, bool, error) {
	profiles, err := cover.ParseProfiles(filepath.Join(g.dir, coverFile))
	if err != nil {
		return nil, nil, false, fmt.Errorf("reading %s (run the tests first): %w", coverFile, err)
	}
	funcs, err := crap.Analyze(g.dir, g.module, profiles)
	if err != nil {
		return nil, nil, false, err
	}
	base, exists, err := crap.ReadBaseline(filepath.Join(g.dir, g.cfg.Crap.Baseline))
	return funcs, base, exists, err
}

func (g *gate) crap() error {
	funcs, base, _, err := g.analyzeCrap()
	if err != nil {
		return err
	}
	report := crap.Check(funcs, base, g.cfg.Crap.Max)
	reportCrap(g.out, report, true)
	return verdict(g.out, "CRAP", report.Failed())
}

func (g *gate) updateCrapBaseline() error {
	funcs, base, _, err := g.analyzeCrap()
	if err != nil {
		return err
	}
	next, report := crap.Ratchet(funcs, base, g.cfg.Crap.Max)
	reportCrap(g.out, report, false)
	if report.Failed() {
		return verdict(g.out, "CRAP", true)
	}
	if err := crap.WriteBaseline(filepath.Join(g.dir, g.cfg.Crap.Baseline), next, g.cfg.Crap.Max); err != nil {
		return err
	}
	fmt.Fprintf(g.out, "Baseline updated: %d functions above CRAP %g (was %d)\n", len(next), g.cfg.Crap.Max, len(base))
	return nil
}

func (g *gate) initCrapBaseline() error {
	funcs, _, exists, err := g.analyzeCrap()
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%s already exists: use --update-baseline, which only lets it shrink", g.cfg.Crap.Baseline)
	}
	base := crap.Init(funcs, g.cfg.Crap.Max)
	if err := crap.WriteBaseline(filepath.Join(g.dir, g.cfg.Crap.Baseline), base, g.cfg.Crap.Max); err != nil {
		return err
	}
	fmt.Fprintf(g.out, "Baseline created: %d functions above CRAP %g\n", len(base), g.cfg.Crap.Max)
	return nil
}

func (g *gate) specs() error {
	dir := filepath.Join(g.dir, g.cfg.Specs.Dir)
	features, _ := filepath.Glob(filepath.Join(dir, "*.feature"))
	nested, _ := filepath.Glob(filepath.Join(dir, "*", "*.feature"))
	if len(features)+len(nested) == 0 {
		fmt.Fprintf(g.out, "Specs: no .feature files under %s/ yet (skipped)\n", g.cfg.Specs.Dir)
		return nil
	}
	_, code, err := execx.Run(g.dir, nil, g.out, "go", "test", "./"+filepath.ToSlash(g.cfg.Specs.Dir)+"/...")
	if err != nil {
		return err
	}
	return verdict(g.out, "Specs", code != 0)
}

func (g *gate) mutation() error {
	if len(g.cfg.Mutation.Packages) == 0 {
		fmt.Fprintln(g.out, "Mutation: no packages configured (skipped)")
		return nil
	}
	failed := false
	for _, pkg := range g.cfg.Mutation.Packages {
		fmt.Fprintf(g.out, "-- %s (builds and tests every mutant, this takes a few minutes)\n", pkg.Path)
		summary, err := mutation.Run(g.dir, g.cfg.Mutation, pkg, g.out)
		if err != nil {
			return fmt.Errorf("%s: %w", pkg.Path, err)
		}
		failed = reportMutation(g.out, summary, pkg) || failed
	}
	return verdict(g.out, "Mutation", failed)
}
