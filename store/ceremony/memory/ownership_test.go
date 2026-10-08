package memory_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func rowParam(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.StarExpr:
		return rowParam(x.X)
	case *ast.ArrayType:
		return rowParam(x.Elt)
	case *ast.Ellipsis:
		return rowParam(x.Elt)
	case *ast.Ident:
		return x.Name == "Row"
	case *ast.SelectorExpr:
		return x.Sel.Name == "Row"
	}
	return false
}

func exportedReceiver(fn *ast.FuncDecl) bool {
	if fn.Recv == nil {
		return true
	}
	t := fn.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	id, ok := t.(*ast.Ident)
	return ok && id.IsExported()
}

func TestNoMemoryPackageExportsARowToRecordConstructor(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 3 || parts[1] != "memory" {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() || !exportedReceiver(fn) {
				continue
			}
			for _, p := range fn.Type.Params.List {
				if rowParam(p.Type) {
					t.Errorf("store/%s: %s takes a raw Row and hands a Restore-built record to any importer (G6)", rel, fn.Name.Name)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
