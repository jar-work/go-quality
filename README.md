# go-quality

A quality gate for Go modules, built for code written by AI agents: instead of reading every
line, the agent must pass deterministic checks that fail on their own.

```
goquality check
```

runs, in order:

| Check | Question it answers | How |
| --- | --- | --- |
| `arch` | Does each package import only what its layer allows? Is SQL kept out of Go code? | rules in `.quality.yaml` over `go list` |
| `security` | Vulnerable dependencies? Static-analysis findings? Committed secrets? | govulncheck, gosec, gitleaks |
| `test` | Do the tests pass? | `go test -coverprofile=coverage.out ./...` |
| `crap` | Which functions are complex *and* untested? | CRAP = complexity² × (1 − coverage)³ + complexity |
| `specs` | Does it do what the business asked? | `go test ./specs/...` once `.feature` files exist |
| `mutation` | Would the tests catch a bug? | gremlins, per package, against that package's thresholds |

Each check also runs on its own: `goquality crap`, `goquality mutation`, ... Use
`goquality check --skip mutation` for a fast local run and keep mutation for CI.

## Install

Pin it as a tool of each module (Go 1.24+), so every machine and CI run the same version:

```
go get -tool github.com/HRECL/go-quality/cmd/goquality@v1.0.0
go tool goquality check
```

The repository is private: set `GOPRIVATE=github.com/HRECL/*` and make sure git can read it
(in GitHub Actions, a token with read access to this repo).

The external tools (gremlins, gosec, govulncheck, gitleaks) are pinned in
`internal/tools/tools.go` and run with `go run pkg@version`. Upgrading one there upgrades it in
every repository on its next goquality release.

## Configuration

Everything has a default; a module without `.quality.yaml` still gets every generic check.
Unknown keys are an error, so a typo cannot silently disable a threshold.

```yaml
crap:
  max: 30                                   # default 30
  baseline: quality/crap-baseline.txt       # default

mutation:
  workers: 2                                # default 2; gremlins' default (one per CPU) can freeze a laptop
  timeout-coefficient: 10                   # default 10
  packages:                                 # only packages with real tests
    - path: ./handlers/joker
      efficacy: 100                         # killed / (killed + lived), in %
      mutant-coverage: 75                   # mutants in tested code / all mutants, in %

arch:
  rules:                                    # regular expressions; {module} is the module path
    - package: '^{module}/utils$'
      deny: '^{module}/(handlers|middlewares)'
      reason: utils is a base layer
  inline-sql:                               # optional
    dirs: [handlers, middlewares]
    baseline: quality/inline-sql-baseline.txt

security:
  govulncheck: {disabled: false}
  gosec: {baseline: quality/gosec-baseline.txt}
  gitleaks: {baseline: quality/gitleaks-baseline.txt}   # scans the whole repository's history

specs:
  dir: specs                                # default
```

In a repository with several modules, gitleaks scans the same history from each one. Enable it
in one module (or point every module's `gitleaks.baseline` at one shared file) and disable it in
the rest.

## The ratchet: thresholds go up, baselines go down

Adopting the gate must not require fixing everything first, and improvements must not be lost.

| What | Recorded in | Rule |
| --- | --- | --- |
| CRAP | `quality/crap-baseline.txt`: functions above the maximum and their score | `crap --update-baseline` removes entries and lowers scores; it **refuses** to add a function or raise a score |
| gosec | `quality/gosec-baseline.txt`: `<rule> <file>`, one line per accepted finding, with the reason in a comment | goquality reports entries that disappear (`FIXED`) so they can be removed |
| gitleaks | `quality/gitleaks-baseline.txt`: fingerprints, never secret values | a baseline entry for a real secret is not a fix: rotate it |
| inline SQL | `quality/inline-sql-baseline.txt`: files | goquality reports files that no longer contain SQL |
| mutation | thresholds per package in `.quality.yaml` | goquality suggests raising a threshold once the score is 5 points above it |
| govulncheck | nothing | a reachable vulnerability is fixed by upgrading the dependency |

Adopting goquality in a module:

1. Add `.quality.yaml` with the rules the code already follows.
2. `goquality crap --init-baseline` records today's CRAP debt (it refuses if a baseline exists).
3. Record existing gosec and gitleaks findings, each with a reason.
4. Add mutation packages one at a time, at their current scores.

Lowering `crap.max` is a deliberate decision, not a regression: delete the baseline, lower the
maximum, run `--init-baseline`, and review the diff in the pull request.

## Lessons encoded here

Each of these happened while building the original scripts, and goquality now guards against it:

- **Test cache**: gremlins sizes timeouts from the test run. Cached tests take ~0s and every
  mutant times out. goquality runs with `-count=1` and fails runs dominated by timeouts.
- **False 100%**: gremlins' `--test-cpu` reaches the test binary as an unknown flag, every run
  exits 2, and every mutant counts as killed. goquality never passes it.
- **Thresholds ignored**: gremlins v0.6.0 exits 0 below its own thresholds. goquality enforces them.
- **Memory**: one gremlins worker per CPU, each compiling and testing, froze a 16 GB laptop.
  goquality defaults to 2 workers and `-p=2`.
- **Baselines that hide regressions**: regenerating a baseline from scratch lets an agent absorb
  a new problem. `--update-baseline` only shrinks.

## For AI agents

Add this to the repository's `CLAUDE.md` (or equivalent):

```markdown
## Quality gate
- Before finishing, run `go tool goquality check --skip mutation` in every module you changed. It must pass.
- If CRAP reports IMPROVED, run `go tool goquality crap --update-baseline` and commit the baseline with your change.
- Never add entries or raise values in `quality/*-baseline.txt`, and never lower thresholds in `.quality.yaml`.
- If mutation testing reports LIVED mutants in code you touched, write tests that kill them.
- A gitleaks finding means a secret was committed: stop and tell the user. Do not baseline it.
```

## Developing

goquality passes its own gate: `go run ./cmd/goquality check` from the repository root.
