// Package findings holds rule violations reported per file (gosec, Dockerfile rules) and the
// baseline that records the accepted ones.
package findings

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

type Finding struct {
	Rule, File, Text string
}

// Key is how a finding is recorded in a baseline: rule and file, not line, so unrelated edits
// that move code around do not invalidate it.
func (f Finding) Key() string { return f.Rule + " " + f.File }

// Compare matches findings against baseline counts per key. fixed lists keys with fewer
// findings than recorded, which should be removed from the baseline.
func Compare(found []Finding, baseline map[string]int) (unexpected []Finding, fixed []string) {
	seen := map[string]int{}
	for _, f := range found {
		seen[f.Key()]++
		if seen[f.Key()] > baseline[f.Key()] {
			unexpected = append(unexpected, f)
		}
	}
	for key, n := range baseline {
		if seen[key] < n {
			fixed = append(fixed, key)
		}
	}
	sort.Strings(fixed)
	return unexpected, fixed
}

// ReadBaseline reads "<rule> <file>" lines, one per accepted finding; '#' starts a comment.
// A missing file is an empty baseline.
func ReadBaseline(path string) (map[string]int, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]int{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	counts := map[string]int{}
	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s:%d: want \"<rule> <file>\"", path, line)
		}
		counts[fields[0]+" "+fields[1]]++
	}
	return counts, scanner.Err()
}
