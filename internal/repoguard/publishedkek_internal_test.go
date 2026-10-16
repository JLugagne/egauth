package repoguard

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/kek"
)

// TestEveryFixtureKEKIsRefused is the guard behind the published-key denylist for test fixtures:
// a 32-byte key committed under any testdata directory (a *.hex file, or a JSON member whose name
// ends in "key") is public, so kek.NewLocal must refuse it. Adding a fixture without adding its key
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

func TestFixtureKeyScanSeesHexAndJSONKeys(t *testing.T) {
	dir := t.TempDir()
	key := strings.Repeat("ab", kek.KeyLength)
	files := map[string]string{
		"k.hex":     key + "\n",
		"f.json":    `{"Key":"` + key + `","Cases":[{"Blob":"` + key + `"}],"nested":{"signingKey":"` + key + `"}}`,
		"short.hex": "abcd",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(fixtureKeys(t, filepath.Join(dir, "k.hex"))); n != 1 {
		t.Errorf("hex file: %d keys, want 1", n)
	}
	if n := len(fixtureKeys(t, filepath.Join(dir, "f.json"))); n != 2 {
		t.Errorf("json file: %d keys, want 2 (Key and signingKey, not Blob)", n)
	}
	if n := len(fixtureKeys(t, filepath.Join(dir, "short.hex"))); n != 0 {
		t.Errorf("short hex file: %d keys, want 0", n)
	}
}

// TestShippedCodeDrawsKEKsFromCryptoRand keeps every non-test Go file from deriving a KEK from a
// string literal: such a key is public the moment the file is committed, and a helper package
// (egauthtest, storetest, journeytest) hands it to whoever calls it.
func TestShippedCodeDrawsKEKsFromCryptoRand(t *testing.T) {
	root := repoRoot(t)
	files := collectFiles(t, root, func(path string, d fs.DirEntry) bool {
		if d.IsDir() {
			return !isSkippedDir(d.Name())
		}
		return strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go")
	})
	for _, path := range files {
		for _, line := range literalKEKLines(t, path, nil) {
			t.Errorf("%s:%d derives a KEK from a literal; draw it from crypto/rand", relPath(t, root, path), line)
		}
	}
}

func TestLiteralKEKScanSeesADerivedKey(t *testing.T) {
	src := "package x\nimport (\n\t\"crypto/sha256\"\n\t\"github.com/JLugagne/egauth/kek\"\n)\n" +
		"func a() { sum := sha256.Sum256([]byte(\"public\")); _, _ = kek.NewLocal(sum[:]) }\n" +
		"func b() { _, _ = kek.NewLocal([]byte(\"0123456789abcdef0123456789abcdef\")) }\n" +
		"func c(raw []byte) { _, _ = kek.NewLocal(raw) }\n" +
		"func d(seed string) { sum := sha256.Sum256([]byte(\"prefix/\" + seed)); _, _ = kek.LegacyLocalV016(sum[:]) }\n"
	if got := literalKEKLines(t, "x.go", src); len(got) != 3 || got[0] != 6 || got[1] != 7 || got[2] != 9 {
		t.Fatalf("literalKEKLines = %v, want [6 7 9]", got)
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

func fixtureKeys(t *testing.T, path string) [][]byte {
	t.Helper()
	switch filepath.Ext(path) {
	case ".hex":
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if k := keyBytes(strings.TrimSpace(string(raw))); k != nil {
			return [][]byte{k}
		}
	case ".json":
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var v any
		if json.Unmarshal(raw, &v) != nil {
			return nil
		}
		return jsonKeys(v)
	}
	return nil
}

func jsonKeys(v any) [][]byte {
	var out [][]byte
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			out = append(out, jsonKeys(e)...)
		}
	case map[string]any:
		for name, e := range x {
			if s, ok := e.(string); ok && strings.HasSuffix(strings.ToLower(name), "key") {
				if k := keyBytes(s); k != nil {
					out = append(out, k)
				}
				continue
			}
			out = append(out, jsonKeys(e)...)
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

func literalKEKLines(t *testing.T, path string, src any) []int {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil
	}
	var lines []int
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		var kekCalls []*ast.CallExpr
		literalDigest := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch exprName(call.Fun) {
			case "NewLocal", "LegacyLocalV016":
				kekCalls = append(kekCalls, call)
			case "Sum256", "Sum512", "Key", "Expand", "Extract":
				literalDigest = literalDigest || containsStringLit(call)
			}
			return true
		})
		for _, call := range kekCalls {
			if literalDigest || containsStringLit(call) {
				lines = append(lines, fset.Position(call.Pos()).Line)
			}
		}
	}
	return lines
}

func containsStringLit(call *ast.CallExpr) bool {
	found := false
	for _, arg := range call.Args {
		ast.Inspect(arg, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				found = true
			}
			return !found
		})
	}
	return found
}
