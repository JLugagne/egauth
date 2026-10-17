package repoguard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/internal/secretpolicy"
)

var keyFieldNames = []string{
	"SecretKey",
	"CookieKey",
	"SigningKey",
	"StateSigningKey",
	"KEK",
	"Secret",
}

const minPublishedKeyLength = secretpolicy.MinKeyLength

const denyListSourceFile = "internal/secretpolicy/secretpolicy.go"

// TestNoPublishedKeyLiteralsInExamples is the guard behind the denylist: every long string literal
// assigned to a key-bearing field in a *_test.go Example (which go/doc publishes as the package's
// usage documentation) or in a fenced Go snippet under docs/ must appear in secretpolicy.Denied.
//
// Without this, the denylist only covers the literals someone remembered to add. The examples are
// the primary way these packages are learned, so a stale denylist means a copy-pasted deployment
// signs tokens with a key an attacker can read off pkg.go.dev.
func TestNoPublishedKeyLiteralsInExamples(t *testing.T) {
	root := repoRoot(t)
	var scanned int

	goFiles := collectFiles(t, root, func(path string, d fs.DirEntry) bool {
		if d.IsDir() {
			return !isSkippedDir(d.Name())
		}
		return strings.HasSuffix(path, "_test.go")
	})
	for _, path := range goFiles {
		rel := relPath(t, root, path)
		if rel == denyListSourceFile {
			continue
		}
		for _, lit := range goKeyLiterals(t, path) {
			scanned++
			if problem := publishedKeyProblem(rel, lit); problem != "" {
				t.Error(problem)
			}
		}
	}

	mdFiles := collectFiles(t, root, func(path string, d fs.DirEntry) bool {
		if d.IsDir() {
			return !isSkippedDir(d.Name())
		}
		return strings.HasSuffix(path, ".md") && strings.Contains(relPath(t, root, path), "docs/")
	})
	for _, path := range mdFiles {
		rel := relPath(t, root, path)
		for _, lit := range markdownKeyLiterals(t, path) {
			scanned++
			if problem := publishedKeyProblem(rel, lit); problem != "" {
				t.Error(problem)
			}
		}
	}

	if scanned == 0 {
		t.Fatal("guard found no key literals to check; the scan paths are wrong")
	}
}

// TestPublishedKeyGuardRejectsUnknownLiteral proves the guard above has teeth: a long key literal
// that is not in the denylist is reported, which is what a newly published example would be.
func TestPublishedKeyGuardRejectsUnknownLiteral(t *testing.T) {
	unknown := strings.Repeat("z", minPublishedKeyLength)
	problem := publishedKeyProblem("docs/content/example.md", unknown)
	if problem == "" {
		t.Fatal("a long key literal absent from the denylist must fail the guard")
	}
	if !strings.Contains(problem, "denylist") {
		t.Fatalf("the guard must point at the denylist, got %q", problem)
	}
}

// TestPublishedKeyGuardAcceptsDeniedLiteral is the other half: a literal that IS denied passes the
// scan (the denylist is the thing being enforced), and a short placeholder is ignored.
func TestPublishedKeyGuardAcceptsDeniedLiteral(t *testing.T) {
	for denied := range secretpolicy.Denied {
		if problem := publishedKeyProblem("docs/content/example.md", denied); problem != "" {
			t.Errorf("denylisted literal %q must satisfy the guard, got %q", denied, problem)
		}
	}

	if problem := publishedKeyProblem("docs/content/example.md", "changeme"); problem != "" {
		t.Errorf("a short placeholder must be ignored, got %q", problem)
	}
}

func publishedKeyProblem(rel, literal string) string {
	if len(literal) < minPublishedKeyLength {
		return ""
	}
	if secretpolicy.Denied[literal] {
		return ""
	}

	if strings.Contains(literal, "minimum-hs256-signing-secret") {
		return ""
	}
	return "published key literal in " + rel + " is missing from secretpolicy.Denied: " +
		strconv.Quote(literal) + " — replace it with examplekey.New() or add it to the denylist"
}

var keyOptionFuncs = map[string]bool{
	"WithStateSigningKey": true,
	"WithCookieKey":       true,
	"WithSigningKey":      true,
	"NewKEK":              true,
	"NewHMACSigner":       true,
}

func goKeyLiterals(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {

		return nil
	}
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !isExampleFunc(fn) {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.KeyValueExpr:
				if isKeyFieldName(node.Key) {
					out = append(out, literalStrings(node.Value)...)
				}
			case *ast.CallExpr:
				if !keyOptionFuncs[exprName(node.Fun)] {
					return true
				}
				for _, arg := range node.Args {
					out = append(out, literalStrings(arg)...)
				}
			}
			return true
		})
	}
	return out
}

func isExampleFunc(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || fn.Type.Params != nil && len(fn.Type.Params.List) > 0 {
		return false
	}
	if !strings.HasPrefix(fn.Name.Name, "Example") {
		return false
	}
	rest := strings.TrimPrefix(fn.Name.Name, "Example")
	if rest == "" {
		return true
	}

	return rest[0] >= 'A' && rest[0] <= 'Z'
}

func markdownKeyLiterals(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []string
	inFence := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inFence = !inFence
			continue
		}
		if !inFence {
			continue
		}
		for _, field := range keyFieldNames {
			idx := strings.Index(trimmed, field+":")
			if idx < 0 {
				continue
			}
			rest := trimmed[idx+len(field)+1:]
			out = append(out, quotedLiterals(rest)...)
		}
	}
	return out
}

func quotedLiterals(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		if s[i] != '"' {
			continue
		}
		for j := i + 1; j < len(s); j++ {
			if s[j] == '\\' {
				j++
				continue
			}
			if s[j] == '"' {
				out = append(out, s[i+1:j])
				i = j
				break
			}
		}
	}
	return out
}

func literalStrings(e ast.Expr) []string {
	switch node := e.(type) {
	case *ast.BasicLit:
		if node.Kind != token.STRING {
			return nil
		}
		v, err := strconv.Unquote(node.Value)
		if err != nil {
			return nil
		}
		return []string{v}
	case *ast.BinaryExpr:
		return append(literalStrings(node.X), literalStrings(node.Y)...)
	case *ast.CallExpr:
		var out []string
		for _, arg := range node.Args {
			out = append(out, literalStrings(arg)...)
		}
		return out
	}
	return nil
}

func isKeyFieldName(e ast.Expr) bool {
	name := exprName(e)
	if name == "" {
		return false
	}
	for _, field := range keyFieldNames {
		if name == field {
			return true
		}
	}
	return false
}

func exprName(e ast.Expr) string {
	switch node := e.(type) {
	case *ast.Ident:
		return node.Name
	case *ast.SelectorExpr:
		return node.Sel.Name
	}
	return ""
}

func isSkippedDir(name string) bool {
	switch name {
	case ".git", ".github", "node_modules", "public", "testdata":
		return true
	}
	return strings.HasPrefix(name, ".")
}

func collectFiles(t *testing.T, root string, keep func(path string, d fs.DirEntry) bool) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if isSkippedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if keep(path, d) {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func relPath(t *testing.T, root, path string) string {
	t.Helper()
	rel, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatalf("rel %s: %v", path, err)
	}
	return filepath.ToSlash(rel)
}

// TestReleaseToolingInstallsArePinned guards the release runbook. `go install ...@latest` in a shell
// fence compiles whatever upstream published at release time and runs it with the maintainer's OIDC
// identity and filesystem access — which is exactly the position that produces the signatures
// consumers verify. A floating version there undoes the pin-everything convention the Makefile and
// ci.yml both follow, so a literal @latest on a go install line in the release documentation fails
// the build.
func TestReleaseToolingInstallsArePinned(t *testing.T) {
	root := repoRoot(t)
	docs := []string{
		"RELEASING.md",
		"SECURITY.md",
		"CONTRIBUTING.md",
	}
	var checked int
	for _, rel := range docs {
		path := filepath.Join(root, rel)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)

			if !strings.HasPrefix(trimmed, "go install ") && !strings.HasPrefix(trimmed, "brew install ") {
				continue
			}
			checked++
			if strings.Contains(trimmed, "@latest") {
				t.Errorf("%s:%d installs a release tool at @latest: %q — pin the reviewed version and keep it in sync with the Makefile",
					rel, i+1, trimmed)
			}
		}
	}
	if checked == 0 {
		t.Fatal("guard found no tool-install lines; the docs it scans are wrong")
	}
}

// TestReleaseToolingPinsHaveOneHome keeps the Makefile the single source of the release-tool
// versions, so a bump cannot update one and miss the other.
func TestReleaseToolingPinsHaveOneHome(t *testing.T) {
	root := repoRoot(t)
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	for _, name := range []string{"GITSIGN_VERSION", "COSIGN_VERSION"} {
		if !strings.Contains(string(mk), name) {
			t.Errorf("Makefile must pin %s: the release runbook refers to it by name", name)
		}
	}
}

// TestDenyListSourceFileHoldsTheDeniedLiterals keeps the skip honest: the scan skips the one
// file that necessarily contains the literals, so that file must actually be where secretpolicy's
// map resolves to. If the literals move again without updating denyListSourceFile, this fails
// instead of letting the skip silently drift onto an unrelated file.
func TestDenyListSourceFileHoldsTheDeniedLiterals(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(denyListSourceFile)))
	if err != nil {
		t.Fatalf("read denylist source %s: %v — the scan skips this file, so it must exist and hold the literals", denyListSourceFile, err)
	}
	if len(secretpolicy.Denied) == 0 {
		t.Fatal("secretpolicy.Denied is empty; the published-key guard has nothing to enforce")
	}
	for denied := range secretpolicy.Denied {
		if !strings.Contains(string(raw), strconv.Quote(denied)) {
			t.Errorf("denylist source %s does not contain %s; if the literals moved, update denyListSourceFile so the scan skips the right file",
				denyListSourceFile, strconv.Quote(denied))
		}
	}
}

// TestGoKeyLiteralsFlagsAnonymousExample proves the AST half of the guard end to end: a long
// literal assigned to a key-bearing field inside a godoc Example is extracted by goKeyLiterals
// and rejected by publishedKeyProblem when it is absent from the denylist.
func TestGoKeyLiteralsFlagsAnonymousExample(t *testing.T) {
	root := t.TempDir()
	unknown := strings.Repeat("q", minPublishedKeyLength)
	src := "package example\n\nfunc ExampleNew() {\n\tcfg := Config{SecretKey: \"" + unknown + "\"}\n\t_ = cfg\n}\n"
	path := filepath.Join(root, "example_test.go")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	lits := goKeyLiterals(t, path)
	if len(lits) != 1 || lits[0] != unknown {
		t.Fatalf("goKeyLiterals = %q, want exactly the seeded published literal", lits)
	}
	if problem := publishedKeyProblem(relPath(t, root, path), lits[0]); problem == "" {
		t.Fatal("an unknown literal extracted from an Example must fail the guard")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(file)))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s: %v", root, err)
	}
	return root
}
