package ceremony_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"testing"

	"github.com/JLugagne/egauth/store/ceremony"
)

func declaredKinds(t *testing.T, f *ast.File) []string {
	t.Helper()
	var out []string
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Kind" {
				continue
			}
			for _, n := range vs.Names {
				if n.IsExported() {
					out = append(out, n.Name)
				}
			}
		}
	}
	return out
}

func TestEveryKindSwitchNamesEveryKind(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "kind.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	kinds := declaredKinds(t, f)
	if len(kinds) != len(ceremony.All()) {
		t.Fatalf("kind.go declares %d kinds, All returns %d", len(kinds), len(ceremony.All()))
	}
	switches := 0
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		if id, ok := fn.Recv.List[0].Type.(*ast.Ident); !ok || id.Name != "Kind" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			if tag, ok := sw.Tag.(*ast.Ident); !ok || tag.Name != fn.Recv.List[0].Names[0].Name {
				return true
			}
			switches++
			var named []string
			for _, st := range sw.Body.List {
				cc := st.(*ast.CaseClause)
				if cc.List == nil {
					t.Errorf("Kind.%s: a default branch would decide future kinds silently", fn.Name.Name)
				}
				for _, e := range cc.List {
					if id, ok := e.(*ast.Ident); ok {
						named = append(named, id.Name)
					}
				}
			}
			for _, k := range kinds {
				if !slices.Contains(named, k) {
					t.Errorf("Kind.%s does not name %s: a new kind would fail open through the zero fallback", fn.Name.Name, k)
				}
			}
			return true
		})
	}
	if switches < 8 {
		t.Fatalf("found %d switches over Kind, want at least the 8 per-kind constants", switches)
	}
}
