package repoguard

import (
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/kek"
)

// TestEveryFixtureKEKIsRefused is the guard behind the published-key denylist for test fixtures:
// a 32-byte key committed under any testdata directory (any 64-hex-digit token, in any file
// format) is public, so kek.NewLocal must refuse it. Adding a fixture without adding its key
// to committedKeys in kek/policy.go fails here.
func TestEveryFixtureKEKIsRefused(t *testing.T) {
	root := repoRoot(t)
	found := 0
	for _, path := range testdataFiles(t, root) {
		rel := relPath(t, root, path)
		for _, key := range fixtureKeys(t, path) {
			found++
			if _, err := kek.NewLocal(key); !errors.Is(err, kek.ErrInvalidKey) {
				t.Errorf("%s publishes a %d-byte key that kek.NewLocal accepts; add it to committedKeys in kek/policy.go", rel, len(key))
			}
		}
	}
	if found == 0 {
		t.Fatal("guard found no fixture keys; the scan is wrong")
	}
}

func TestFixtureKeyScanSeesAKeyInAnyFormat(t *testing.T) {
	dir := t.TempDir()
	key := strings.Repeat("ab", kek.KeyLength)
	files := map[string]int{
		"k.hex":     1,
		"f.json":    2,
		"kek.txt":   1,
		"conf.yaml": 1,
		"short.hex": 0,
		"long.txt":  0,
	}
	bodies := map[string]string{
		"k.hex":     key + "\n",
		"f.json":    `{"kek":"` + key + `","nested":{"secret":"` + strings.Repeat("cd", kek.KeyLength) + `"}}`,
		"kek.txt":   key + "\n",
		"conf.yaml": "kek: " + key + "\n",
		"short.hex": "abcd",
		"long.txt":  key + "ef",
	}
	for name, want := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(bodies[name]), 0o600); err != nil {
			t.Fatal(err)
		}
		if n := len(fixtureKeys(t, path)); n != want {
			t.Errorf("%s: %d keys, want %d", name, n, want)
		}
	}
}

// TestNoKEKIsDerivedFromALiteral keeps every Go file, tests included, from building a KEK out of a
// string literal, directly or through a package-level var or const, a hex or digest decoding, or a
// helper function of the same package: such a key is public the moment the file is committed and
// would open whatever a deployment that copied it sealed. kek.LegacyLocalV016 is out of scope: it
// only opens what v0.16 sealed, so tests may hand it the committed v0.16 fixture key. Package kek is
// exempt: its tests probe the refusal of exactly those keys.
func TestNoKEKIsDerivedFromALiteral(t *testing.T) {
	root := repoRoot(t)
	files := collectFiles(t, root, func(path string, d fs.DirEntry) bool {
		return !d.IsDir() && strings.HasSuffix(path, ".go")
	})
	byDir := map[string][]string{}
	for _, path := range files {
		dir := filepath.Dir(path)
		if relPath(t, root, dir) == "kek" {
			continue
		}
		byDir[dir] = append(byDir[dir], path)
	}
	for _, paths := range byDir {
		srcs := map[string]any{}
		for _, path := range paths {
			srcs[path] = nil
		}
		for _, site := range literalKEKSites(t, srcs) {
			t.Errorf("%s:%d derives a KEK from a literal; draw it from crypto/rand", relPath(t, root, site.path), site.line)
		}
	}
}

func TestLiteralKEKScanSeesEveryDerivationForm(t *testing.T) {
	header := "package x\nimport (\n\t\"crypto/rand\"\n\t\"crypto/sha256\"\n\t\"encoding/hex\"\n\t\"github.com/JLugagne/egauth/kek\"\n)\n"
	flagged := map[string]string{
		"digest in the same func": "func a() { sum := sha256.Sum256([]byte(\"public\")); _, _ = kek.NewLocal(sum[:]) }\n",
		"literal bytes":           "func a() { _, _ = kek.NewLocal([]byte(\"0123456789abcdef0123456789abcdef\")) }\n",
		"package var":             "var devKey = sha256.Sum256([]byte(\"package level\"))\nfunc a() { _, _ = kek.NewLocal(devKey[:]) }\n",
		"hex literal":             "func a() { raw, _ := hex.DecodeString(\"0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff\"); _, _ = kek.NewLocal(raw) }\n",
		"helper func":             "func derive() []byte { s := sha256.Sum256([]byte(\"helper\")); return s[:] }\nfunc a() { _, _ = kek.NewLocal(derive()) }\n",
		"helper of a helper":      "func seed() []byte { s := sha256.Sum256([]byte(\"deep\")); return s[:] }\nfunc derive() []byte { return seed() }\nfunc a() { _, _ = kek.NewLocal(derive()) }\n",
		"named const":             "const devSecret = \"0123456789abcdef0123456789abcdef\"\nfunc a() { _, _ = kek.NewLocal([]byte(devSecret)) }\n",
	}
	for name, body := range flagged {
		if got := literalKEKSites(t, map[string]any{"x.go": header + body}); len(got) != 1 {
			t.Errorf("%s: %d sites flagged, want 1", name, len(got))
		}
	}
	clean := header + "func a(raw []byte) { _, _ = kek.NewLocal(raw) }\n" +
		"func b() { k := make([]byte, kek.KeyLength); _, _ = rand.Read(k); _, _ = kek.NewLocal(k) }\n"
	if got := literalKEKSites(t, map[string]any{"x.go": clean}); len(got) != 0 {
		t.Errorf("keys from a parameter or crypto/rand flagged: %v", got)
	}
}

func testdataFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/testdata/") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

var hexKey = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)

func fixtureKeys(t *testing.T, path string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out [][]byte
	for _, m := range hexKey.FindAllString(string(raw), -1) {
		if k := keyBytes(m); k != nil {
			out = append(out, k)
		}
	}
	return out
}

func keyBytes(s string) []byte {
	k, err := hex.DecodeString(s)
	if err != nil || len(k) != kek.KeyLength {
		return nil
	}
	return k
}

type kekSite struct {
	path string
	line int
}

var derivations = map[string]bool{"Sum256": true, "Sum512": true, "Key": true, "Expand": true, "Extract": true, "DecodeString": true}

func literalKEKSites(t *testing.T, srcs map[string]any) []kekSite {
	t.Helper()
	fset := token.NewFileSet()
	var files []*ast.File
	for path, src := range srcs {
		f, err := parser.ParseFile(fset, path, src, 0)
		if err == nil {
			files = append(files, f)
		}
	}
	tainted := map[string]bool{}
	funcs := map[string]*ast.FuncDecl{}
	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						for i, name := range vs.Names {
							if i < len(vs.Values) && hasStringLit(vs.Values[i]) || len(vs.Values) == 1 && hasStringLit(vs.Values[0]) {
								tainted[name.Name] = true
							}
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil && d.Body != nil {
					funcs[d.Name.Name] = d
				}
			}
		}
	}
	derives := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for name, fn := range funcs {
			if !derives[name] && literalDerivation(fn.Body, tainted, derives) {
				derives[name], changed = true, true
			}
		}
	}
	var out []kekSite
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			local := localTaint(fn.Body, tainted, derives)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if exprName(call.Fun) == "NewLocal" {
					if argsDerive(call.Args, local, derives) {
						out = append(out, kekSite{path: fset.Position(call.Pos()).Filename, line: fset.Position(call.Pos()).Line})
					}
				}
				return true
			})
		}
	}
	return out
}

func localTaint(body ast.Node, tainted, derives map[string]bool) map[string]bool {
	local := maps.Clone(tainted)
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || !derivesValue(as.Rhs, local, derives) {
				return true
			}
			for _, lhs := range as.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" && !local[id.Name] {
					local[id.Name], changed = true, true
				}
			}
			return true
		})
	}
	return local
}

func derivesValue(rhs []ast.Expr, tainted, derives map[string]bool) bool {
	for _, e := range rhs {
		if call, ok := e.(*ast.CallExpr); ok {
			name := exprName(call.Fun)
			if derives[name] || (derivations[name] || isByteConversion(call)) && argsDerive(call.Args, tainted, derives) {
				return true
			}
			continue
		}
		if argsDerive([]ast.Expr{e}, tainted, derives) {
			return true
		}
	}
	return false
}

func literalDerivation(body ast.Node, tainted, derives map[string]bool) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := exprName(call.Fun)
		switch {
		case derives[name]:
			found = true
		case derivations[name] || isByteConversion(call):
			found = argsDerive(call.Args, tainted, derives)
		}
		return !found
	})
	return found
}

func argsDerive(args []ast.Expr, tainted, derives map[string]bool) bool {
	found := false
	for _, arg := range args {
		ast.Inspect(arg, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				found = found || x.Kind == token.STRING
			case *ast.Ident:
				found = found || tainted[x.Name]
			case *ast.CallExpr:
				found = found || derives[exprName(x.Fun)]
			}
			return !found
		})
	}
	return found
}

func hasStringLit(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			found = true
		}
		return !found
	})
	return found
}

func isByteConversion(call *ast.CallExpr) bool {
	at, ok := call.Fun.(*ast.ArrayType)
	if !ok || at.Len != nil {
		return false
	}
	id, ok := at.Elt.(*ast.Ident)
	return ok && id.Name == "byte"
}
