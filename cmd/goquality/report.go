package main

import (
	"fmt"
	"io"

	"github.com/jar-work/go-quality/internal/config"
	"github.com/jar-work/go-quality/internal/crap"
	"github.com/jar-work/go-quality/internal/findings"
	"github.com/jar-work/go-quality/internal/mutation"
)

// reportFindings prints findings missing from the baseline and baseline entries no longer found.
// It returns whether the check passed.
func reportFindings(out io.Writer, name string, found []findings.Finding, baseline map[string]int, baselinePath string) bool {
	unexpected, fixed := findings.Compare(found, baseline)
	for _, f := range unexpected {
		fmt.Fprintln(out, "NEW  ", f.Text)
	}
	for _, key := range fixed {
		fmt.Fprintf(out, "FIXED  %s: remove it from %s\n", key, baselinePath)
	}
	if len(unexpected) > 0 {
		fmt.Fprintf(out, "%s: new findings. Fix them; do not add them to the baseline.\n", name)
		return false
	}
	fmt.Fprintf(out, "%s: ok\n", name)
	return true
}

func reportGitleaks(out io.Writer, ok bool) {
	if ok {
		fmt.Fprintln(out, "gitleaks: ok")
		return
	}
	fmt.Fprintln(out, "gitleaks: a secret was committed. Remove it, rotate it, and never add it to the baseline.")
}

// reportCrap prints a CRAP report. withImproved adds the hint to record improvements, which an
// update has just done.
func reportCrap(out io.Writer, r crap.Report, withImproved bool) {
	for _, line := range r.New {
		fmt.Fprintln(out, "NEW       ", line)
	}
	for _, line := range r.Worse {
		fmt.Fprintln(out, "WORSE     ", line)
	}
	if withImproved {
		for _, line := range r.Improved {
			fmt.Fprintln(out, "IMPROVED  ", line+": record it with goquality crap --update-baseline")
		}
	}
	if r.Failed() {
		fmt.Fprintln(out, "Simplify these functions or add tests. The baseline cannot absorb new or worse entries.")
	}
}

// reportMutation prints why a package's run failed and how to tighten its thresholds. It returns
// whether the run failed.
func reportMutation(out io.Writer, s mutation.Summary, pkg config.MutationPackage) bool {
	problems, suggestions := mutation.Evaluate(s, pkg)
	for _, p := range problems {
		fmt.Fprintln(out, "   FAILED:", p)
	}
	for _, s := range suggestions {
		fmt.Fprintln(out, "   note:", s)
	}
	if len(problems) > 0 {
		fmt.Fprintln(out, "   LIVED mutants are behaviors no test verifies.")
	}
	return len(problems) > 0
}
