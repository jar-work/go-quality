// Package arch checks import rules between a module's packages and, optionally, that SQL lives
// in .sql files rather than inline in Go code.
package arch

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/HRECL/go-quality/internal/config"
	"github.com/HRECL/go-quality/internal/execx"
)

type Violation struct {
	Package, Import, Reason string
}

func (v Violation) String() string {
	return fmt.Sprintf("%s imports %s (%s)", v.Package, v.Import, v.Reason)
}

// Packages maps each package of the module in dir to its direct imports.
func Packages(dir string) (map[string][]string, error) {
	out, code, err := execx.Run(dir, nil, nil, "go", "list", "-f", "{{.ImportPath}} {{join .Imports \" \"}}", "./...")
	if err != nil || code != 0 {
		return nil, fmt.Errorf("go list failed: %v\n%s", err, out)
	}
	pkgs := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			pkgs[fields[0]] = fields[1:]
		}
	}
	return pkgs, nil
}

// CheckDeps applies rules to pkgs. In rule patterns, {module} stands for the module path.
func CheckDeps(pkgs map[string][]string, rules []config.ArchRule, modulePath string) ([]Violation, error) {
	type compiled struct {
		pkg, deny *regexp.Regexp
		reason    string
	}
	expand := func(pattern string) (*regexp.Regexp, error) {
		return regexp.Compile(strings.ReplaceAll(pattern, "{module}", regexp.QuoteMeta(modulePath)))
	}
	var rs []compiled
	for _, r := range rules {
		pkg, err := expand(r.Package)
		if err != nil {
			return nil, fmt.Errorf("arch rule package %q: %w", r.Package, err)
		}
		deny, err := expand(r.Deny)
		if err != nil {
			return nil, fmt.Errorf("arch rule deny %q: %w", r.Deny, err)
		}
		rs = append(rs, compiled{pkg, deny, r.Reason})
	}

	var violations []Violation
	for pkg, imports := range pkgs {
		for _, r := range rs {
			if !r.pkg.MatchString(pkg) {
				continue
			}
			for _, imp := range imports {
				if imp != pkg && r.deny.MatchString(imp) {
					violations = append(violations, Violation{pkg, imp, r.reason})
				}
			}
		}
	}
	slices.SortFunc(violations, func(a, b Violation) int { return strings.Compare(a.String(), b.String()) })
	return violations, nil
}

var inlineSQLRe = regexp.MustCompile(`(SELECT|INSERT INTO|UPDATE [A-Za-z_]+ SET|DELETE FROM) `)

// InlineSQL reports lines with SQL in the Go files under cfg.Dirs, skipping files listed in the
// baseline. fixed lists baseline files that no longer contain SQL and can be removed from it.
func InlineSQL(dir string, cfg config.InlineSQL) (found, fixed []string, err error) {
	allowed, err := readLines(filepath.Join(dir, cfg.Baseline))
	if err != nil {
		return nil, nil, err
	}
	stillThere := map[string]bool{}
	for _, d := range cfg.Dirs {
		root := filepath.Join(dir, d)
		err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			rel, _ := filepath.Rel(dir, path)
			rel = filepath.ToSlash(rel)
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(data), "\n") {
				if !inlineSQLRe.MatchString(line) {
					continue
				}
				if allowed[rel] {
					stillThere[rel] = true
					continue
				}
				found = append(found, fmt.Sprintf("%s:%d: %s", rel, i+1, strings.TrimSpace(line)))
			}
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
	}
	for file := range allowed {
		if !stillThere[file] {
			fixed = append(fixed, file)
		}
	}
	sort.Strings(fixed)
	return found, fixed, nil
}

// readLines reads a baseline of one entry per line; '#' starts a comment. A missing file is empty.
func readLines(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lines := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if text := strings.TrimSpace(scanner.Text()); text != "" && !strings.HasPrefix(text, "#") {
			lines[text] = true
		}
	}
	return lines, scanner.Err()
}
