// Command goquality runs a Go module's quality gate: architecture rules, security checks, tests,
// CRAP, acceptance specs and mutation testing. Run it from the module root; it reads .quality.yaml.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/HRECL/go-quality/internal/config"
)

const usage = `usage: goquality <command> [flags]

commands:
  check      run every check below, in this order (--skip arch,security,... to leave some out)
  arch       import rules and inline SQL
  security   govulncheck, gosec and gitleaks
  test       go test with coverage (writes coverage.out)
  crap       CRAP per function against the baseline (runs the tests first)
               --update-baseline  record improvements; refuses to add or raise entries
               --init-baseline    create the baseline when adopting goquality (fails if one exists)
  specs      Gherkin specs under the specs dir, when there are .feature files
  mutation   gremlins on each configured package, against its own thresholds
`

// errFailed marks a check that ran and failed, as opposed to one that could not run.
var errFailed = errors.New("failed")

type gate struct {
	dir, module string
	cfg         config.Config
	out         io.Writer
}

func main() {
	dir, err := os.Getwd()
	if err == nil {
		err = run(dir, os.Args[1:], os.Stdout)
	}
	if err != nil {
		if !errors.Is(err, errFailed) {
			fmt.Fprintln(os.Stderr, "goquality:", err)
		}
		os.Exit(1)
	}
}

func run(dir string, args []string, out io.Writer) error {
	if len(args) == 0 || slices.Contains([]string{"help", "-h", "--help"}, args[0]) {
		fmt.Fprint(out, usage)
		return nil
	}
	module, err := config.ModulePath(dir)
	if err != nil {
		return err
	}
	cfg, err := config.Load(dir)
	if err != nil {
		return err
	}
	g := &gate{dir: dir, module: module, cfg: cfg, out: out}

	commands := map[string]func([]string) error{
		"check":    g.checkCommand,
		"crap":     g.crapCommand,
		"arch":     noFlags(g.arch),
		"security": noFlags(g.security),
		"test":     noFlags(g.test),
		"specs":    noFlags(g.specs),
		"mutation": noFlags(g.mutation),
	}
	command, ok := commands[args[0]]
	if !ok {
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
	}
	return command(args[1:])
}

func noFlags(check func() error) func([]string) error {
	return func(args []string) error {
		if len(args) > 0 {
			return fmt.Errorf("unexpected arguments %v", args)
		}
		return check()
	}
}

func (g *gate) checkCommand(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	skip := fs.String("skip", "", "comma-separated checks to leave out")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return g.check(strings.Split(*skip, ","))
}

func (g *gate) crapCommand(args []string) error {
	fs := flag.NewFlagSet("crap", flag.ContinueOnError)
	update := fs.Bool("update-baseline", false, "record improvements in the baseline")
	initialize := fs.Bool("init-baseline", false, "create the baseline from the current code")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := g.test(); err != nil {
		return err
	}
	switch {
	case *initialize:
		return g.initCrapBaseline()
	case *update:
		return g.updateCrapBaseline()
	}
	return g.crap()
}

func (g *gate) check(skip []string) error {
	steps := []struct {
		name string
		run  func() error
	}{
		{"arch", g.arch},
		{"security", g.security},
		{"test", g.test},
		{"crap", g.crap},
		{"specs", g.specs},
		{"mutation", g.mutation},
	}
	var failed []string
	for _, step := range steps {
		switch {
		case slices.Contains(skip, step.name):
			fmt.Fprintf(g.out, "\n== %s (skipped)\n", step.name)
		case step.name == "crap" && slices.Contains(failed, "test"):
			fmt.Fprintln(g.out, "\n== crap (skipped: tests failed)")
		default:
			fmt.Fprintf(g.out, "\n== %s\n", step.name)
			if err := step.run(); err != nil {
				if !errors.Is(err, errFailed) {
					fmt.Fprintln(g.out, "error:", err)
				}
				failed = append(failed, step.name)
			}
		}
	}
	if len(failed) > 0 {
		fmt.Fprintf(g.out, "\nQuality: FAILED (%s)\n", strings.Join(failed, ", "))
		return errFailed
	}
	fmt.Fprintln(g.out, "\nQuality: ok")
	return nil
}

func verdict(out io.Writer, name string, failed bool) error {
	if failed {
		fmt.Fprintf(out, "%s: FAILED\n", name)
		return errFailed
	}
	fmt.Fprintf(out, "%s: ok\n", name)
	return nil
}
