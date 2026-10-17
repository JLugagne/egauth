package audit_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const eventImportPath = "github.com/JLugagne/egauth/event"

var emitterOwners = []string{"internal/audit", "event"}

const maxApplicationEmitters = 0

var applicationEmitters = []string{}

var skippedDirs = []string{"tools", "testdata", "vendor", "node_modules"}

type emitSite struct {
	rel string
	pos string
	msg string
}

func repoRoot(t *testing.T) string {
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

func underAny(rel string, prefixes []string) (string, bool) {
	for _, p := range prefixes {
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return p, true
		}
	}
	return "", false
}

func eventAlias(f *ast.File) string {
	for _, imp := range f.Imports {
		if path, _ := strconv.Unquote(imp.Path.Value); path == eventImportPath {
			if imp.Name != nil {
				return imp.Name.Name
			}
			return "event"
		}
	}
	return ""
}

func emitSites(t *testing.T, root string) []emitSite {
	t.Helper()
	var out []emitSite
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") || slices.Contains(skippedDirs, name)) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		relFile, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(filepath.Dir(relFile))
		alias := eventAlias(f)
		report := func(n ast.Node, msg string) {
			out = append(out, emitSite{rel: rel, pos: fset.Position(n.Pos()).String(), msg: msg})
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name == "EmitEvent" {
					report(x, "direct Sink.EmitEvent call")
				}
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && alias != "" && id.Name == alias && x.Sel.Name == "Emit" {
					report(x, "event.Emit reference")
				}
			case *ast.CompositeLit:
				sel, ok := x.Type.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && alias != "" && id.Name == alias && sel.Sel.Name == "Event" {
					report(x, "event.Event literal")
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAuditIsTheOnlyLibraryEmitter(t *testing.T) {
	sites := emitSites(t, repoRoot(t))
	used := map[string]bool{}
	for _, s := range sites {
		if _, ok := underAny(s.rel, emitterOwners); ok {
			continue
		}
		if p, ok := underAny(s.rel, applicationEmitters); ok {
			used[p] = true
			continue
		}
		t.Errorf("%s: %s outside internal/audit; emit through audit.Emit or a typed audit helper", s.pos, s.msg)
	}
	for _, p := range applicationEmitters {
		if !used[p] {
			t.Errorf("emitter exemption %q no longer matches any site; remove it", p)
		}
	}
}

func TestEmitterExemptionListOnlyShrinks(t *testing.T) {
	if len(applicationEmitters) > maxApplicationEmitters {
		t.Fatalf("%d emitter exemptions exceed the ratchet of %d; new exemptions are not allowed", len(applicationEmitters), maxApplicationEmitters)
	}
}
