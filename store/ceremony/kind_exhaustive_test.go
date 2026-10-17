package ceremony_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/JLugagne/egauth/store/ceremony"
)

func TestKindSwitchesNameEveryKind(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "kind.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := len(ceremony.All())
	for _, fn := range []string{"AdmitsSession", "MaxLivePerScope", "MaxLivePerTenant", "MaxAttempts"} {
		named := map[string]bool{}
		for _, d := range file.Decls {
			f, ok := d.(*ast.FuncDecl)
			if !ok || f.Name.Name != fn || f.Recv == nil {
				continue
			}
			ast.Inspect(f.Body, func(n ast.Node) bool {
				if c, ok := n.(*ast.CaseClause); ok {
					for _, e := range c.List {
						if id, ok := e.(*ast.Ident); ok {
							named[id.Name] = true
						}
					}
				}
				return true
			})
		}
		if len(named) != want {
			t.Errorf("Kind.%s names %d kinds in its switch, want all %d: a missing kind would silently fall through", fn, len(named), want)
		}
	}
}
