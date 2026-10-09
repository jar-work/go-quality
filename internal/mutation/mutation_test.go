package mutation

import (
	"strings"
	"testing"

	"github.com/jar-work/go-quality/internal/config"
)

const output = `Starting...
Gathering coverage... done in 1.18s
       LIVED CONDITIONALS_BOUNDARY at batch.go:139:41

Mutation testing completed in 38 seconds 83 milliseconds
Killed: 61, Lived: 8, Not covered: 19
Timed out: 2, Not viable: 0, Skipped: 0
Test efficacy: 88.41%
Mutator coverage: 78.41%
`

func TestParseSummary(t *testing.T) {
	s, err := ParseSummary(output)
	if err != nil {
		t.Fatal(err)
	}
	want := Summary{Killed: 61, Lived: 8, NotCovered: 19, TimedOut: 2, Efficacy: 88.41, MutantCoverage: 78.41}
	if s != want {
		t.Errorf("got %+v, want %+v", s, want)
	}
	if _, err := ParseSummary("ERROR: not in a Go module"); err == nil {
		t.Error("parsed a failed run")
	}
}

func TestEvaluate(t *testing.T) {
	pkg := config.MutationPackage{Path: "./p", Efficacy: 85, MutantCoverage: 75}
	cases := []struct {
		name        string
		summary     Summary
		wantProblem string // empty: passes
		wantNote    string
	}{
		{"passes", Summary{Killed: 61, Lived: 8, Efficacy: 88.41, MutantCoverage: 78.41}, "", ""},
		{"below efficacy", Summary{Killed: 50, Lived: 20, Efficacy: 71.4, MutantCoverage: 80}, "efficacy 71.40% < 85%", ""},
		{"below mutant coverage", Summary{Killed: 60, Lived: 1, Efficacy: 98, MutantCoverage: 40}, "mutant coverage", "raise ./p's efficacy"},
		// Tests served from the go test cache: every mutant times out and efficacy reads 0.
		{"cached tests", Summary{TimedOut: 71, NotCovered: 19}, "the run is broken", ""},
		{"no tests", Summary{NotCovered: 40}, "no mutant ran against a test", ""},
		{"well above", Summary{Killed: 66, Efficacy: 100, MutantCoverage: 77.65}, "", "raise ./p's efficacy threshold"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			problems, notes := Evaluate(c.summary, pkg)
			joined := strings.Join(problems, "; ")
			if c.wantProblem == "" && len(problems) > 0 {
				t.Errorf("unexpected problems: %s", joined)
			}
			if c.wantProblem != "" && !strings.Contains(joined, c.wantProblem) {
				t.Errorf("problems %q do not mention %q", joined, c.wantProblem)
			}
			if c.wantNote != "" && !strings.Contains(strings.Join(notes, "; "), c.wantNote) {
				t.Errorf("notes %v do not mention %q", notes, c.wantNote)
			}
		})
	}
}

func TestEvaluateBoundaries(t *testing.T) {
	pkg := config.MutationPackage{Path: "./p", Efficacy: 85, MutantCoverage: 75}
	cases := []struct {
		name         string
		summary      Summary
		wantProblems int
		wantNotes    int
	}{
		{"exactly at both thresholds passes", Summary{Killed: 17, Lived: 3, Efficacy: 85, MutantCoverage: 75}, 0, 0},
		{"just below efficacy", Summary{Killed: 17, Lived: 3, Efficacy: 84.99, MutantCoverage: 75}, 1, 0},
		{"just below mutant coverage", Summary{Killed: 17, Lived: 3, Efficacy: 85, MutantCoverage: 74.99}, 1, 0},
		{"5 points above both suggests raising both", Summary{Killed: 18, Lived: 2, Efficacy: 90, MutantCoverage: 80}, 0, 2},
		{"less than 5 above suggests nothing", Summary{Killed: 18, Lived: 2, Efficacy: 89.99, MutantCoverage: 79.99}, 0, 0},
		// As many timeouts as tested mutants is suspicious but not broken; more is.
		{"timeouts equal to tested mutants", Summary{Killed: 3, Lived: 3, TimedOut: 6, Efficacy: 85, MutantCoverage: 75}, 0, 0},
		{"lived mutants count as tested", Summary{Lived: 6, TimedOut: 6, Efficacy: 85, MutantCoverage: 75}, 0, 0},
		{"only timeouts", Summary{TimedOut: 1, Efficacy: 85, MutantCoverage: 75}, 1, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			problems, notes := Evaluate(c.summary, pkg)
			if len(problems) != c.wantProblems || len(notes) != c.wantNotes {
				t.Errorf("problems %v, notes %v; want %d and %d", problems, notes, c.wantProblems, c.wantNotes)
			}
		})
	}
}

func TestEvaluateMessages(t *testing.T) {
	problems, _ := Evaluate(Summary{Killed: 1, Lived: 1, TimedOut: 71}, config.MutationPackage{Path: "./p"})
	if len(problems) != 1 || !strings.HasPrefix(problems[0], "71 of 73 mutants timed out") {
		t.Errorf("problems = %v", problems)
	}
	_, notes := Evaluate(Summary{Killed: 1, Efficacy: 100, MutantCoverage: 100}, config.MutationPackage{Path: "./p", Efficacy: 80, MutantCoverage: 70})
	if len(notes) != 2 || !strings.Contains(notes[0], "(now 80)") || !strings.Contains(notes[1], "(now 70)") {
		t.Errorf("notes = %v", notes)
	}
}
