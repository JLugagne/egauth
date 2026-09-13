package securitydefaults

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tokens/jwt"
)

// keyFieldNames are the struct fields and option arguments that carry secret key material in this
// module's examples and documentation. A literal assigned to any of them is published the moment
// the snippet is rendered by go/doc or committed to the docs tree.
var keyFieldNames = []string{
	"SecretKey",
	"CookieKey",
	"SigningKey",
	"StateSigningKey",
	"KEK",
	"Secret",
}

// minPublishedKeyLength is the shortest literal treated as a potential credential. It matches
// jwt.MinSecretKeyLength: anything shorter cannot be an HS256 key in this module and is far more
// likely to be a placeholder such as "changeme".
const minPublishedKeyLength = jwt.MinSecretKeyLength

// denyListSourceFile is where the denylist itself lives. It necessarily contains the very literals
// it denies, so the scan skips it.
const denyListSourceFile = "tokens/jwt/denylist.go"

// TestNoPublishedKeyLiteralsInExamples is the guard behind the denylist: every long string literal
// assigned to a key-bearing field in a *_test.go Example (which go/doc publishes as the package's
// usage documentation) or in a fenced Go snippet under docs/ must appear in jwt.DeniedSecrets.
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
	for denied := range jwt.DeniedSecrets {
		if problem := publishedKeyProblem("docs/content/example.md", denied); problem != "" {
			t.Errorf("denylisted literal %q must satisfy the guard, got %q", denied, problem)
		}
	}
	// "changeme" is a placeholder, not a key: it is below the length threshold.
	if problem := publishedKeyProblem("docs/content/example.md", "changeme"); problem != "" {
		t.Errorf("a short placeholder must be ignored, got %q", problem)
	}
}

// publishedKeyProblem returns a human-readable problem when a published literal is missing from the
// denylist, or "" when the literal is safe to publish.
func publishedKeyProblem(rel, literal string) string {
	if len(literal) < minPublishedKeyLength {
		return ""
	}
	if jwt.DeniedSecrets[literal] {
		return ""
	}
	// Mirrors the issuer's marker check: a near-copy of a published example is refused even when it
	// is not byte-identical to a denylisted entry.
	if strings.Contains(literal, "minimum-hs256-signing-secret") {
		return ""
	}
	return "published key literal in " + rel + " is missing from tokens/jwt.DeniedSecrets: " +
		strconv.Quote(literal) + " — replace it with examplekey.New() or add it to the denylist"
}

// keyOptionFuncs are the option constructors that take key material as their argument.
var keyOptionFuncs = map[string]bool{
	"WithStateSigningKey": true,
	"WithCookieKey":       true,
	"WithSigningKey":      true,
	"NewKEK":              true,
	"NewHMACSigner":       true,
}

// goKeyLiterals parses one Go file and returns every string literal assigned to a key-bearing field
// or passed to a key-bearing option constructor.
//
// Only Example functions are scanned. go/doc renders those on pkg.go.dev as the package's usage
// documentation, which is what makes a literal in one published; an ordinary test body is not
// rendered, so scanning those would flag assertion messages and unrelated fixtures.
func goKeyLiterals(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		// A file that does not parse is not this guard's business; the build will fail first.
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

// isExampleFunc reports whether a declaration is a godoc Example function: a func named Example or
// Example<Xxx>, with no receiver and no parameters.
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
	// Example<Xxx> must continue with an upper-case letter to be a godoc example.
	return rest[0] >= 'A' && rest[0] <= 'Z'
}

// markdownKeyLiterals returns long string literals assigned to a key-bearing field inside fenced
// Go snippets in a markdown file. It is deliberately line-oriented: doc snippets are read by humans
// and copied verbatim, so a simple scan is both sufficient and robust to snippet fragments that do
// not parse as a whole file.
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

// quotedLiterals extracts every double-quoted string from s.
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

// literalStrings returns the string values of an expression composed of string literals, handling
// the concatenation and single-argument conversion forms that appear in snippets.
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

// isKeyFieldName reports whether an AST expression names one of the key-bearing identifiers.
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

// exprName returns the identifier name of a simple expression (Ident or SelectorExpr).
func exprName(e ast.Expr) string {
	switch node := e.(type) {
	case *ast.Ident:
		return node.Name
	case *ast.SelectorExpr:
		return node.Sel.Name
	}
	return ""
}

// isSkippedDir reports whether a directory should be skipped by the repository walk. Worktrees and
// build output can contain copies of the module and are not published documentation.
func isSkippedDir(name string) bool {
	switch name {
	case ".git", ".github", "node_modules", "public", "testdata":
		return true
	}
	return strings.HasPrefix(name, ".")
}

// collectFiles walks root and returns every file for which keep reports true.
func collectFiles(t *testing.T, root string, keep func(path string, d fs.DirEntry) bool) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && keep(path, d) {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// relPath returns path relative to root, with forward slashes, for stable messages.
func relPath(t *testing.T, root, path string) string {
	t.Helper()
	rel, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatalf("rel %s: %v", path, err)
	}
	return filepath.ToSlash(rel)
}
