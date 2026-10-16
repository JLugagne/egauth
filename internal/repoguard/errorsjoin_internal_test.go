package repoguard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strconv"
	"strings"
	"testing"
)

func TestNoErrorfWrapping(t *testing.T) {
	root := repoRoot(t)
	files := collectFiles(t, root, func(path string, d fs.DirEntry) bool {
		if d.IsDir() {
			return !isSkippedDir(d.Name())
		}
		return strings.HasSuffix(path, ".go")
	})
	if len(files) == 0 {
		t.Fatal("guard found no Go files; the scan root is wrong")
	}
	for _, path := range files {
		for _, line := range errorfWrapLines(t, path, nil) {
			t.Errorf("%s:%d wraps with fmt.Errorf %%w; use errors.Join(errors.New(\"...\"), err)", relPath(t, root, path), line)
		}
	}
}

func TestErrorfWrapGuardSeesAWrap(t *testing.T) {
	src := "package x\nimport \"fmt\"\nfunc f(err error) error {\n\t_ = fmt.Errorf(\"plain %v\", err)\n\treturn fmt.Errorf(\"x: %w\", err)\n}\n"
	if got := errorfWrapLines(t, "x.go", src); len(got) != 1 || got[0] != 5 {
		t.Fatalf("errorfWrapLines = %v, want [5]", got)
	}
	aliased := "package x\nimport f \"fmt\"\nvar _ = f.Errorf(\"%w\", nil)\n"
	if got := errorfWrapLines(t, "y.go", aliased); len(got) != 1 {
		t.Fatalf("an aliased fmt import escaped the guard: %v", got)
	}
}

func errorfWrapLines(t *testing.T, path string, src any) []int {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil
	}
	fmtName := ""
	for _, imp := range f.Imports {
		if imp.Path.Value != strconv.Quote("fmt") {
			continue
		}
		fmtName = "fmt"
		if imp.Name != nil {
			fmtName = imp.Name.Name
		}
	}
	if fmtName == "" {
		return nil
	}
	var lines []int
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Errorf" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != fmtName {
			return true
		}
		for _, s := range literalStrings(call.Args[0]) {
			if strings.Contains(s, "%w") {
				lines = append(lines, fset.Position(call.Pos()).Line)
				break
			}
		}
		return true
	})
	return lines
}
