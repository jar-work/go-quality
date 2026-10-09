package findings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompare(t *testing.T) {
	found := []Finding{
		{Rule: "G304", File: "utils/database.go"},
		{Rule: "G401", File: "utils/hash.go"},
		{Rule: "G304", File: "utils/database.go"},
	}
	unexpected, fixed := Compare(found, map[string]int{"G304 utils/database.go": 1, "G104 main.go": 1})
	if len(unexpected) != 2 || unexpected[0].Rule != "G401" || unexpected[1].Key() != "G304 utils/database.go" {
		t.Errorf("unexpected = %+v, want the hash.go finding and the second G304", unexpected)
	}
	if len(fixed) != 1 || fixed[0] != "G104 main.go" {
		t.Errorf("fixed = %v, want G104 main.go", fixed)
	}
	if unexpected, fixed := Compare(found[:1], map[string]int{"G304 utils/database.go": 1}); len(unexpected)+len(fixed) != 0 {
		t.Errorf("an exact match reported %v / %v", unexpected, fixed)
	}
}

func TestReadBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.txt")
	os.WriteFile(path, []byte("# why\nG304 utils/database.go\n\nG304 utils/database.go\n"), 0o600)
	counts, err := ReadBaseline(path)
	if err != nil || len(counts) != 1 || counts["G304 utils/database.go"] != 2 {
		t.Errorf("counts = %v, err = %v", counts, err)
	}
	if counts, err := ReadBaseline(filepath.Join(t.TempDir(), "missing.txt")); err != nil || len(counts) != 0 {
		t.Errorf("missing baseline: %v, %v", counts, err)
	}
	os.WriteFile(path, []byte("# header\nG304 a.go\nG304\n"), 0o600)
	if _, err := ReadBaseline(path); err == nil || !strings.Contains(err.Error(), ":3:") {
		t.Errorf("err = %v, want line 3", err)
	}
}
