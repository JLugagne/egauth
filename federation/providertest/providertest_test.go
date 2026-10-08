package providertest_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/federation/providertest"
)

func TestBuiltins(t *testing.T) {
	providertest.Run(t)
}

func TestBuiltinsCoverEveryConstructor(t *testing.T) {
	const dir = "../providers"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]bool{}
	for _, c := range providertest.Builtins() {
		covered[strings.TrimSuffix(c.Name, "SelfHosted")] = true
	}
	fset := token.NewFileSet()
	seen := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Results == nil || len(fn.Type.Results.List) != 2 {
				continue
			}
			seen++
			if !covered[fn.Name.Name] {
				t.Errorf("constructor %s is not run by providertest.Builtins", fn.Name.Name)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no constructor found; the scan path is wrong")
	}
}
