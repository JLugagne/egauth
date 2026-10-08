package keys_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const revokePath = "github.com/JLugagne/egauth/internal/revoke"

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && strings.Contains(string(b), "module github.com/JLugagne/egauth\n") {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("core module root not found")
		}
		dir = parent
	}
}

func TestInternalKeysOwnsTheOnlyKeyCache(t *testing.T) {
	root := moduleRoot(t)
	var offenders []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", "vendor", "node_modules", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if filepath.ToSlash(filepath.Dir(rel)) == "internal/keys" {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil
		}
		for _, imp := range f.Imports {
			ip, _ := strconv.Unquote(imp.Path.Value)
			if ip != revokePath {
				continue
			}
			name := path.Base(ip)
			if imp.Name != nil {
				name = imp.Name.Name
			}
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "NewKeys" {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == name {
					offenders = append(offenders, fset.Position(sel.Pos()).String())
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("revoke.NewKeys outside internal/keys: the key manager owns the only key cache (T-15): %v", offenders)
	}
}
