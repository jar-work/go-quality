package arch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jar-work/go-quality/internal/config"
)

func TestCheckDeps(t *testing.T) {
	pkgs := map[string][]string{
		"api":                   {"api/handlers/orders", "api/utils", "fmt"},
		"api/utils":             {"api/models", "api/handlers/orders"},  // violation
		"api/handlers/orders":   {"api/utils", "api/handlers/payments"}, // violation
		"api/handlers/payments": {"api/utils"},
		"api/models":            {"time"},
	}
	rules := []config.ArchRule{
		{Package: `^{module}/utils$`, Deny: `^{module}/handlers`, Reason: "utils is a base layer"},
		{Package: `^{module}/handlers/[^/]+$`, Deny: `^{module}/handlers`, Reason: "handlers do not import each other"},
	}
	got, err := CheckDeps(pkgs, rules, "api")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"api/handlers/orders imports api/handlers/payments (handlers do not import each other)",
		"api/utils imports api/handlers/orders (utils is a base layer)",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("violation %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCheckDepsModulePathIsLiteral(t *testing.T) {
	// A '.' in the module path must not match any character.
	pkgs := map[string][]string{"github.com/x/m/utils": {"githubXcom/x/m/handlers"}}
	rules := []config.ArchRule{{Package: `^{module}/utils$`, Deny: `^{module}/handlers`}}
	got, err := CheckDeps(pkgs, rules, "github.com/x/m")
	if err != nil || len(got) != 0 {
		t.Errorf("got %v, %v", got, err)
	}
}

func TestInlineSQL(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "handlers", "a.go"), "package h\n\nconst q = `SELECT id FROM t`\n")
	write(t, filepath.Join(dir, "handlers", "old.go"), "package h\n\nconst q = \"DELETE FROM t\"\n")
	write(t, filepath.Join(dir, "handlers", "gone.go"), "package h\n")
	write(t, filepath.Join(dir, "handlers", "a_test.go"), "package h\n\nconst q = `SELECT 1 FROM t`\n")
	write(t, filepath.Join(dir, "quality", "sql.txt"), "# known\nhandlers/old.go\nhandlers/gone.go\n")

	found, fixed, err := InlineSQL(dir, config.InlineSQL{Dirs: []string{"handlers", "missing"}, Baseline: "quality/sql.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || !strings.HasPrefix(found[0], "handlers/a.go:3:") {
		t.Errorf("found = %v, want only handlers/a.go:3", found)
	}
	if len(fixed) != 1 || fixed[0] != "handlers/gone.go" {
		t.Errorf("fixed = %v, want handlers/gone.go", fixed)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
