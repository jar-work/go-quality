// Package mutation runs gremlins on one package at a time and judges its result against that
// package's own thresholds.
package mutation

import (
	"fmt"
	"io"
	"regexp"
	"strconv"

	"github.com/jar-work/go-quality/internal/config"
	"github.com/jar-work/go-quality/internal/execx"
	"github.com/jar-work/go-quality/internal/tools"
)

type Summary struct {
	Killed, Lived, NotCovered, TimedOut int
	Efficacy, MutantCoverage            float64 // percentages
}

// Run mutates pkg and returns gremlins' summary. Surviving mutants stream to out as they are found.
func Run(dir string, cfg config.Mutation, pkg config.MutationPackage, out io.Writer) (Summary, error) {
	env := []string{
		// gremlins sizes each mutant's timeout from how long the tests take; tests served from
		// the cache take ~0s and every mutant then times out.
		"GOFLAGS=-count=1 -p=2",
	}
	// Do not pass --test-cpu: gremlins v0.6.0 hands it to the test binary as a raw "-cpu" flag,
	// the binary exits 2, and every mutant is reported KILLED: a false 100%.
	output, _, err := execx.Run(dir, env, out, "go", "run", tools.Gremlins, "unleash",
		"--output-statuses", "l",
		"--timeout-coefficient", strconv.Itoa(cfg.TimeoutCoefficient),
		"--workers", strconv.Itoa(cfg.Workers),
		pkg.Path)
	if err != nil {
		return Summary{}, err
	}
	return ParseSummary(output)
}

var (
	countsRe   = regexp.MustCompile(`Killed: (\d+), Lived: (\d+), Not covered: (\d+)`)
	timedOutRe = regexp.MustCompile(`Timed out: (\d+)`)
	efficacyRe = regexp.MustCompile(`Test efficacy: ([\d.]+)%`)
	mcoverRe   = regexp.MustCompile(`Mutator coverage: ([\d.]+)%`)
)

func ParseSummary(output string) (Summary, error) {
	counts := countsRe.FindStringSubmatch(output)
	timedOut := timedOutRe.FindStringSubmatch(output)
	efficacy := efficacyRe.FindStringSubmatch(output)
	mcover := mcoverRe.FindStringSubmatch(output)
	if counts == nil || timedOut == nil || efficacy == nil || mcover == nil {
		return Summary{}, fmt.Errorf("could not parse gremlins output")
	}
	var s Summary
	s.Killed, _ = strconv.Atoi(counts[1])
	s.Lived, _ = strconv.Atoi(counts[2])
	s.NotCovered, _ = strconv.Atoi(counts[3])
	s.TimedOut, _ = strconv.Atoi(timedOut[1])
	s.Efficacy, _ = strconv.ParseFloat(efficacy[1], 64)
	s.MutantCoverage, _ = strconv.ParseFloat(mcover[1], 64)
	return s, nil
}

// Evaluate returns the reasons a run fails (none means it passed) and suggestions that do not
// fail it. gremlins v0.6.0 exits 0 even below its own --threshold-* flags, so thresholds are
// enforced here.
func Evaluate(s Summary, pkg config.MutationPackage) (problems, suggestions []string) {
	tested := s.Killed + s.Lived
	switch {
	case tested == 0 && s.TimedOut == 0:
		problems = append(problems, "no mutant ran against a test: the package has no tests or the run is broken")
	case s.TimedOut > tested:
		problems = append(problems, fmt.Sprintf("%d of %d mutants timed out: the run is broken (cached tests or too short a timeout), not strict",
			s.TimedOut, tested+s.TimedOut))
	}
	if s.Efficacy < pkg.Efficacy {
		problems = append(problems, fmt.Sprintf("efficacy %.2f%% < %g%%", s.Efficacy, pkg.Efficacy))
	} else if s.Efficacy >= pkg.Efficacy+5 {
		suggestions = append(suggestions, fmt.Sprintf("efficacy is %.2f%%: raise %s's efficacy threshold (now %g) to keep it there", s.Efficacy, pkg.Path, pkg.Efficacy))
	}
	if s.MutantCoverage < pkg.MutantCoverage {
		problems = append(problems, fmt.Sprintf("mutant coverage %.2f%% < %g%%", s.MutantCoverage, pkg.MutantCoverage))
	} else if s.MutantCoverage >= pkg.MutantCoverage+5 {
		suggestions = append(suggestions, fmt.Sprintf("mutant coverage is %.2f%%: raise %s's mutant-coverage threshold (now %g)", s.MutantCoverage, pkg.Path, pkg.MutantCoverage))
	}
	return problems, suggestions
}
