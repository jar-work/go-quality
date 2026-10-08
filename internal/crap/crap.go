// Package crap computes CRAP (Change Risk Anti-Patterns) per function:
//
//	CRAP = complexity² × (1 − coverage)³ + complexity
//
// Complexity is cyclomatic complexity as gocyclo counts it; coverage is statement coverage as
// `go tool cover -func` reports it.
package crap

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/cover"
)

type Func struct {
	Key        string // "<file relative to the module root>:<function name>"
	Complexity int
	Coverage   float64 // 0 to 1
}

func (f Func) Score() float64 {
	c := float64(f.Complexity)
	return c*c*math.Pow(1-f.Coverage, 3) + c
}

// Analyze scores every function in the module's non-test files. profiles come from
// `go test -coverprofile ./...`; files missing from them count as 0% covered.
func Analyze(moduleDir, modulePath string, profiles []*cover.Profile) ([]Func, error) {
	byFile := make(map[string]*cover.Profile, len(profiles))
	for _, p := range profiles {
		byFile[strings.TrimPrefix(p.FileName, modulePath+"/")] = p
	}

	var funcs []Func
	seen := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(moduleDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != moduleDir && skipDir(path, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(moduleDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := rel + ":" + FuncName(fn)
			if seen[key] { // several init functions in one file: keep the first
				continue
			}
			seen[key] = true
			funcs = append(funcs, Func{
				Key:        key,
				Complexity: Complexity(fn),
				Coverage:   coverage(byFile[rel], fset.Position(fn.Pos()), fset.Position(fn.End())),
			})
		}
		return nil
	})
	return funcs, err
}

func skipDir(path, name string) bool {
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "vendor" || name == "testdata" {
		return true
	}
	_, err := os.Stat(filepath.Join(path, "go.mod")) // a nested module is analyzed on its own
	return err == nil
}

// Complexity is 1 plus one per decision point: if, for, range, non-default case, non-default
// select case, && and ||. Closures count toward the function that contains them.
func Complexity(fn *ast.FuncDecl) int {
	c := 1
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt:
			c++
		case *ast.CaseClause:
			if n.List != nil {
				c++
			}
		case *ast.CommClause:
			if n.Comm != nil {
				c++
			}
		case *ast.BinaryExpr:
			if n.Op == token.LAND || n.Op == token.LOR {
				c++
			}
		}
		return true
	})
	return c
}

// FuncName names a function like gocyclo does: "Name" or "(*Type).Name".
func FuncName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	return "(" + receiver(fn.Recv.List[0].Type) + ")." + fn.Name.Name
}

func receiver(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + receiver(t.X)
	case *ast.IndexExpr:
		return receiver(t.X)
	case *ast.IndexListExpr:
		return receiver(t.X)
	case *ast.ParenExpr:
		return receiver(t.X)
	}
	return "?"
}

// coverage is the share of the function's statements that ran, as `go tool cover -func` computes it.
func coverage(p *cover.Profile, start, end token.Position) float64 {
	if p == nil {
		return 0
	}
	var covered, total int
	for _, b := range p.Blocks {
		if b.StartLine > end.Line || (b.StartLine == end.Line && b.StartCol >= end.Column) {
			break
		}
		if b.EndLine < start.Line || (b.EndLine == start.Line && b.EndCol <= start.Column) {
			continue
		}
		total += b.NumStmt
		if b.Count > 0 {
			covered += b.NumStmt
		}
	}
	if total == 0 {
		return 0
	}
	return float64(covered) / float64(total)
}
