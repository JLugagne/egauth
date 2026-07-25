// Command doctest guards the project's prose against API drift. It extracts every
// ```go fenced code block from the markdown under -dir (the Hugo docs), the
// repo-root README.md and SECURITY.md, and every .llms/*.md file, and additionally
// scans every Go PACKAGE doc comment (including the root doc.go) under -root. For
// each egauth package-qualified identifier it finds (e.g. identity.NewService,
// argon2.WithTime, passkey.Config) it checks — via `go doc` — that the symbol
// actually resolves to a real exported identifier in the current source. A
// renamed function, a removed option, or a fabricated/dangling constructor
// therefore fails CI instead of silently shipping a misleading example (this is
// exactly how the old, now-deleted empty delivery package's dangling references
// slipped into three tags).
//
// It deliberately checks ONLY qualified identifiers of the egauth packages mapped
// below. Local variables (ctx, pool, userID, w, r, …), stdlib calls, business
// logic, and untracked packages are ignored, so the check has no false positives
// from the snippet style the docs use — every failure is a genuine drift.
//
// # Struct-field and method checks
//
// A bare qualified identifier (alias.Symbol) only catches a fabricated top-level
// name (a function, type, or constant that no longer exists). It does NOT catch a
// fabricated STRUCT FIELD (e.g. Config{MultiTenant: true} where MultiTenant was
// never a real field) or a fabricated METHOD on a value returned from a tracked
// constructor (e.g. svc.VerifyAccessToken() when Service only ever exposed
// VerifyAccessTokenForTenant) — exactly the class of doc-vs-code drift that let
// jwt.Config.MultiTenant and Service.VerifyAccessToken ship in the docs while
// never existing in the source.
//
// doctest additionally parses each fenced block as Go source (best-effort: import
// lines are stripped and the remaining statements wrapped in a synthetic function
// body, since these are illustrative snippets, not standalone compilable files)
// and walks the resulting AST for two patterns:
//
//   - alias.Type{Field: ...} composite literals (including &alias.Type{...} and
//     generic alias.Type[T]{...}) — each keyed field is checked as "Type.Field"
//     via the same `go doc` mechanism used for bare symbols.
//   - x := alias.Func(...) followed by x.Method(...) in the same block — Func's
//     declared return type is resolved from its `go doc` signature and, when it
//     names a type in a tracked package, x.Method is checked as "Type.Method".
//
// Both checks are deliberately conservative: anything ambiguous (an elided
// composite-literal type, a return type in an untracked package, an unparseable
// block) is silently skipped rather than guessed at, so this can miss real drift
// but must never fail a doc that is actually correct.
//
// Usage:
//
//	go run ./internal/doctest            # scan docs/content + README.md + SECURITY.md + .llms + package docs
//	go run ./internal/doctest -dir X     # scan a different markdown content root
//	go run ./internal/doctest -root Y     # scan a different repo root for README/SECURITY.md/.llms/Go package docs
//	go run ./internal/doctest -v         # list every resolved symbol too
//
// go test ./internal/doctest/... runs the identical check (see doctest_internal_test.go), so a
// drift fails `go test ./...` too, not only the separate CI step.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// goDocEnv is the environment every `go doc` subprocess this package spawns runs under. nil
// (the default) inherits the calling process's environment unchanged; run sets it to force
// GOWORK to the repo's committed go.work file, see run's comment.
var goDocEnv []string

// filteredEnviron returns os.Environ() with every entry named key removed, so callers can append
// a fresh value for that key without producing a duplicate (and therefore ambiguous) entry.
func filteredEnviron(key string) []string {
	prefix := key + "="
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, e := range env {
		if !strings.HasPrefix(e, prefix) {
			out = append(out, e)
		}
	}
	return out
}

// pkgAlias maps the package selector used in the docs (the import name or an
// alias the docs adopt) to its real import path. Only these prefixes are
// checked; anything else (context, http, fmt, log, time, a local var, …) is
// ignored. jwtissuer is the alias the docs use for tokens/jwt.
var pkgAlias = map[string]string{
	"egauth":     "github.com/JLugagne/egauth",
	"identity":   "github.com/JLugagne/egauth/identity",
	"sessions":   "github.com/JLugagne/egauth/sessions",
	"tokens":     "github.com/JLugagne/egauth/tokens",
	"jwtissuer":  "github.com/JLugagne/egauth/tokens/jwt",
	"oauth":      "github.com/JLugagne/egauth/oauth",
	"oauthpgx":   "github.com/JLugagne/egauth/adapters/pgx/oauth",
	"providers":  "github.com/JLugagne/egauth/oauth/providers",
	"passkey":    "github.com/JLugagne/egauth/passkey",
	"passkeymem": "github.com/JLugagne/egauth/passkey/memory",
	"mfa":        "github.com/JLugagne/egauth/mfa",
	"otp":        "github.com/JLugagne/egauth/otp",
	"passwords":  "github.com/JLugagne/egauth/passwords",
	"argon2":     "github.com/JLugagne/egauth/passwords/argon2",
	"policy":     "github.com/JLugagne/egauth/passwords/policy",
	"ratelimit":  "github.com/JLugagne/egauth/ratelimit",
	"event":      "github.com/JLugagne/egauth/event",
	"identitypg": "github.com/JLugagne/egauth/adapters/pgx/identity",
	"sessionspg": "github.com/JLugagne/egauth/adapters/pgx/sessions",
}

// qualifiedRef matches `alias.Symbol` where Symbol is exported (starts upper).
var qualifiedRef = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\.([A-Z][A-Za-z0-9_]*)`)

// ref is one qualified-identifier occurrence in the docs.
type ref struct {
	file   string
	line   int
	alias  string
	symbol string
}

func main() {
	dir := flag.String("dir", "docs/content", "root directory to scan for markdown")
	root := flag.String("root", ".", "repo root to scan for README.md, SECURITY.md, .llms and Go package doc comments")
	verbose := flag.Bool("v", false, "list every resolved symbol")
	flag.Parse()

	failures, resolved, err := run(*dir, *root, *verbose)
	if err != nil {
		fmt.Fprintln(os.Stderr, "doctest:", err)
		os.Exit(2)
	}
	if failures > 0 {
		fmt.Printf("\ndoctest: %d doc reference(s) point at symbols, fields or methods that no longer "+
			"exist. Update the docs (or the alias map in internal/doctest) to match the current API.\n", failures)
		os.Exit(1)
	}
	fmt.Printf("doctest: all %d distinct egauth symbol/field/method reference(s) across the docs resolve.\n", resolved)
}

// run collects every markdown surface under dir/root plus Go package doc comments, extracts every
// tracked egauth reference (bare qualified symbols, struct-literal fields, and constructor-derived
// method calls — see the package doc), resolves each via `go doc`, and prints one "DRIFT" line per
// broken reference. It returns the failure count and the number of distinct resolved
// (importPath, symbol) pairs checked; verbose additionally prints every resolved reference.
func run(dir, root string, verbose bool) (failures int, resolved int, err error) {
	// The docs reference symbols from the adapters/pgx nested module (identitypg, oauthpgx,
	// sessionspg), resolvable via `go doc` only when the repo's committed go.work is active. Force
	// it explicitly here rather than inheriting the caller's environment: `go test ./...` in this
	// repo's own Definition of Done runs with GOWORK=off (to keep the root module's own build
	// hermetic), and exec.Command inherits that by default, which would make every pgx-adapter
	// reference a false DRIFT. Setting GOWORK here — for the `go doc` subprocesses THIS package
	// spawns only — decouples doctest's correctness from whatever GOWORK the caller happens to run
	// under.
	if workPath, err := filepath.Abs(filepath.Join(root, "go.work")); err == nil && fileExists(workPath) {
		goDocEnv = append(filteredEnviron("GOWORK"), "GOWORK="+workPath)
	}

	files, err := markdownFiles(dir)
	if err != nil {
		return 0, 0, err
	}
	// Also guard the repo-root README.md and SECURITY.md (the highest-traffic surfaces) and every
	// .llms/*.md file (the LLM-agent-facing API reference, which carries the same drift risk).
	for _, name := range []string{"README.md", "SECURITY.md"} {
		if p := filepath.Join(root, name); fileExists(p) {
			files = append(files, p)
		}
	}
	if llmsFiles, err := markdownFiles(filepath.Join(root, ".llms")); err == nil {
		files = append(files, llmsFiles...)
	}
	if len(files) == 0 {
		return 0, 0, fmt.Errorf("no markdown files under %s", dir)
	}

	var refs []ref
	for _, f := range files {
		rs, err := scan(f)
		if err != nil {
			return 0, 0, err
		}
		refs = append(refs, rs...)

		blocks, err := scanBlocks(f)
		if err != nil {
			return 0, 0, err
		}
		for _, b := range blocks {
			refs = append(refs, astRefs(b)...)
		}
	}

	// Scan Go package doc comments (the root doc.go and every package's overview).
	pkgRefs, err := goPackageDocRefs(root)
	if err != nil {
		return 0, 0, err
	}
	refs = append(refs, pkgRefs...)

	// Resolve each distinct (importPath, symbol) once; report every doc site of
	// a broken one. Caching keeps `go doc` invocations to one per unique symbol.
	type key struct{ path, sym string }
	cache := map[key]bool{}
	seen := map[key]bool{}

	for _, r := range refs {
		path := pkgAlias[r.alias]
		if path == "" {
			continue // not an egauth package we track
		}
		k := key{path, r.symbol}
		ok, done := cache[k]
		if !done {
			ok = symbolExists(path, r.symbol)
			cache[k] = ok
		}
		if ok {
			if verbose && !seen[k] {
				fmt.Printf("doctest: ok    %s.%s\n", r.alias, r.symbol)
			}
			seen[k] = true
			continue
		}
		failures++
		fmt.Printf("doctest: DRIFT %s:%d  %s.%s does not exist in %s\n",
			r.file, r.line, r.alias, r.symbol, path)
	}

	return failures, len(cache), nil
}

// scan extracts ```go fences from a markdown file and returns every egauth
// qualified reference inside them, with source line numbers.
func scan(path string) ([]ref, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var out []ref
	inFence := false
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if !inFence {
			if t == "```go" {
				inFence = true
			}
			continue
		}
		if t == "```" {
			inFence = false
			continue
		}
		out = append(out, lineRefs(path, i+1, line)...)
	}
	return out, nil
}

// docBlock is one ```go fenced block, kept as raw lines (rather than pre-extracted refs) so
// astRefs can parse it as Go source.
type docBlock struct {
	file      string
	startLine int // line number (1-based) of the first line INSIDE the fence
	lines     []string
}

// scanBlocks extracts every ```go fenced block from a markdown file as a docBlock, for the
// AST-based field/method checks in astRefs. It is the block-granular counterpart to scan, which
// extracts flat line-based references from the same fences.
func scanBlocks(path string) ([]docBlock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var out []docBlock
	inFence := false
	var cur docBlock
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if !inFence {
			if t == "```go" {
				inFence = true
				cur = docBlock{file: path, startLine: i + 2}
			}
			continue
		}
		if t == "```" {
			inFence = false
			out = append(out, cur)
			continue
		}
		cur.lines = append(cur.lines, line)
	}
	return out, nil
}

// goPackageDocRefs walks root for non-test .go files and returns every egauth
// qualified reference in each file's PACKAGE doc comment (the comment attached to
// the package clause, including the root doc.go). This guards package-level
// documentation against API drift the same way the markdown scan guards the docs.
func goPackageDocRefs(root string) ([]ref, error) {
	var out []ref
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			// Skip VCS, vendored, fuzz/testdata and hidden dirs (incl. the local kanban .tasks).
			if path != root && (name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.PackageClauseOnly)
		if perr != nil || f.Doc == nil {
			return nil // unparseable or no package doc comment — nothing to check
		}
		startLine := fset.Position(f.Doc.Pos()).Line
		for i, line := range strings.Split(f.Doc.Text(), "\n") {
			out = append(out, lineRefs(path, startLine+i, line)...)
		}
		return nil
	})
	return out, err
}

// lineRefs extracts every tracked egauth qualified reference from a single line of
// code (or doc-comment text). It strips line comments first so prose-in-comments
// (e.g. "// or adapters/pgx/identity.NewStore(pool)") is not treated as a real
// call site, matching how real example code reads.
func lineRefs(file string, lineNo int, code string) []ref {
	if idx := strings.Index(code, "//"); idx >= 0 {
		code = code[:idx]
	}
	var out []ref
	for _, loc := range qualifiedRef.FindAllStringSubmatchIndex(code, -1) {
		alias := code[loc[2]:loc[3]]  // loc[2:4] = alias
		symbol := code[loc[4]:loc[5]] // loc[4:6] = symbol
		// Disqualify when the alias is preceded by an identifier char or a dot
		// (a field/selector chain like x.Foo.Bar, not a package selector).
		if loc[2] > 0 {
			prev := code[loc[2]-1]
			if prev == '.' || prev == '_' || isAlnum(prev) {
				continue
			}
		}
		if _, ok := pkgAlias[alias]; !ok {
			continue
		}
		out = append(out, ref{file: file, line: lineNo, alias: alias, symbol: symbol})
	}
	return out
}

// symbolExists reports whether importPath exports symbol, via `go doc`. `go doc` prints
// "doc: no symbol X" / "no such package" / "no method or field X.Y" (the dotted Type.Field or
// Type.Method form used for struct-field and method checks) but exits 0, so we key off the
// message text, not the exit code.
func symbolExists(importPath, symbol string) bool {
	cmd := exec.Command("go", "doc", importPath, symbol)
	cmd.Env = goDocEnv
	out, _ := cmd.CombinedOutput()
	s := string(out)
	if strings.Contains(s, "no symbol") ||
		strings.Contains(s, "no such package") ||
		strings.Contains(s, "is not in") ||
		strings.Contains(s, "no buildable Go source files") ||
		strings.Contains(s, "build constraints exclude") ||
		strings.Contains(s, "no method or field") ||
		strings.Contains(s, "unknown field or method") ||
		strings.Contains(s, "unexported field or method") {
		return false
	}
	// A successful `go doc` prints a package header / the symbol's doc; require
	// some non-empty, non-error output so an unexpected failure is not a false green.
	return strings.TrimSpace(s) != ""
}

func markdownFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".md") {
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func isAlnum(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// astRefs parses b as best-effort Go source and returns every "Type.Field" and "Type.Method"
// reference it can confidently extract (see the package doc for the two patterns). Anything it
// cannot parse, or cannot confidently attribute to a tracked package, is silently skipped: this
// check must never fail a doc block that is actually correct.
func astRefs(b docBlock) []ref {
	src, ok := wrapBlockAsFunc(b.lines)
	if !ok {
		return nil
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "block.go", src, 0)
	if err != nil {
		return nil // illustrative pseudocode that doesn't parse as a function body — skip
	}

	// varInfo tracks short variable declarations `x := alias.Func(...)` whose return type was
	// resolved to a tracked (alias, typeName) pair, so a later x.Method(...) in the same block
	// can be checked as "typeName.Method".
	type varInfo struct{ alias, typeName string }
	vars := map[string]varInfo{}
	var out []ref

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit:
			alias, typeName, ok := aliasedTypeOf(node.Type)
			if !ok {
				return true
			}
			line := fset.Position(node.Pos()).Line
			for _, elt := range node.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				out = append(out, ref{
					file: b.file, line: b.startLine + line - 1,
					alias: alias, symbol: typeName + "." + key.Name,
				})
			}
		case *ast.AssignStmt:
			if node.Tok != token.DEFINE || len(node.Lhs) == 0 || len(node.Rhs) != 1 {
				return true
			}
			ident, ok := node.Lhs[0].(*ast.Ident)
			if !ok || ident.Name == "_" {
				return true
			}
			call, ok := node.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			alias, funcName, ok := aliasedFuncOf(call.Fun)
			if !ok {
				return true
			}
			retAlias, typeName, ok := resolveReturnType(alias, funcName)
			if !ok {
				return true
			}
			vars[ident.Name] = varInfo{alias: retAlias, typeName: typeName}
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			vi, ok := vars[recv.Name]
			if !ok {
				return true
			}
			line := fset.Position(node.Pos()).Line
			out = append(out, ref{
				file: b.file, line: b.startLine + line - 1,
				alias: vi.alias, symbol: vi.typeName + "." + sel.Sel.Name,
			})
		}
		return true
	})
	return out
}

// wrapBlockAsFunc turns a fenced doc block into a parseable Go source file. Doc blocks are
// illustrative snippets, not standalone programs: they mix top-level import lines with
// function-body statements, so this strips any `import "..."` / `import alias "..."` single-line
// import and any `import (...)` group, then wraps the remaining lines in a synthetic function
// body. Returns ok=false only when nothing worth parsing remains.
func wrapBlockAsFunc(lines []string) (string, bool) {
	var body []string
	inImportGroup := false
	for _, line := range lines {
		t := strings.TrimSpace(line)
		switch {
		case inImportGroup:
			if t == ")" {
				inImportGroup = false
			}
			continue
		case t == "import (":
			inImportGroup = true
			continue
		case strings.HasPrefix(t, "import "):
			continue
		}
		body = append(body, line)
	}
	if len(strings.TrimSpace(strings.Join(body, ""))) == 0 {
		return "", false
	}
	return "package p\nfunc _() {\n" + strings.Join(body, "\n") + "\n}\n", true
}

// aliasedTypeOf reports the (alias, typeName) a composite-literal type expression names, when it
// is a direct or generic-instantiated selector on a tracked package alias (alias.Type or
// alias.Type[T, ...]). Anything else (an elided type, a local/unqualified type, an unrecognized
// alias) reports ok=false.
func aliasedTypeOf(expr ast.Expr) (alias, typeName string, ok bool) {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		return selectorParts(t)
	case *ast.IndexExpr:
		return aliasedTypeOf(t.X)
	case *ast.IndexListExpr:
		return aliasedTypeOf(t.X)
	case *ast.StarExpr:
		return aliasedTypeOf(t.X)
	default:
		return "", "", false
	}
}

// aliasedFuncOf reports the (alias, funcName) a call expression's Fun names, when it is a direct
// or generic-instantiated selector on a tracked package alias (alias.Func or alias.Func[T](...)).
func aliasedFuncOf(expr ast.Expr) (alias, funcName string, ok bool) {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		return selectorParts(t)
	case *ast.IndexExpr:
		return aliasedFuncOf(t.X)
	case *ast.IndexListExpr:
		return aliasedFuncOf(t.X)
	default:
		return "", "", false
	}
}

func selectorParts(sel *ast.SelectorExpr) (alias, name string, ok bool) {
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", "", false
	}
	if _, tracked := pkgAlias[id.Name]; !tracked {
		return "", "", false
	}
	return id.Name, sel.Sel.Name, true
}

// returnTypeCache memoizes resolveReturnType's `go doc` lookups (keyed "alias.Func") across the
// single-process run, matching symbolExists' one-call-per-symbol discipline.
var returnTypeCache = map[string]struct {
	alias, typeName string
	ok              bool
}{}

// resolveReturnType resolves alias.Func's declared return type via `go doc` and reports it as a
// (resolvedAlias, typeName) pair when that return type names an exported type in a package this
// tool tracks (resolvedAlias may differ from alias, e.g. a constructor in one tracked package
// returning a type from another). Reports ok=false for anything it cannot confidently resolve to
// a single tracked, exported type — a stdlib/third-party return type, an unqualified return type
// it cannot attribute to a package, or an unparseable `go doc` signature — so ambiguity never
// produces a false failure downstream.
func resolveReturnType(alias, funcName string) (resolvedAlias, typeName string, ok bool) {
	key := alias + "." + funcName
	if v, cached := returnTypeCache[key]; cached {
		return v.alias, v.typeName, v.ok
	}
	resolvedAlias, typeName, ok = doResolveReturnType(alias, funcName)
	returnTypeCache[key] = struct {
		alias, typeName string
		ok              bool
	}{resolvedAlias, typeName, ok}
	return resolvedAlias, typeName, ok
}

func doResolveReturnType(alias, funcName string) (string, string, bool) {
	importPath := pkgAlias[alias]
	if importPath == "" {
		return "", "", false
	}
	cmd := exec.Command("go", "doc", importPath, funcName)
	cmd.Env = goDocEnv
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", false
	}
	sigLine, ok := funcSignatureLine(string(out))
	if !ok {
		return "", "", false
	}
	retClause, ok := returnClause(sigLine)
	if !ok {
		return "", "", false
	}
	return classifyReturnType(alias, retClause)
}

// funcSignatureLine returns the first line of `go doc`'s output that is the function signature
// itself (starts with "func "), skipping the leading "package p // import ..." header line.
func funcSignatureLine(s string) (string, bool) {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "func ") {
			return line, true
		}
	}
	return "", false
}

// returnClause extracts the substring after the parameter list's matching close-paren from a
// `go doc` function-signature line, e.g. "func New[C any](cfg Config[C]) *Service[C]" ->
// "*Service[C]". Returns ok=false if the parens are unbalanced (should not happen on real `go doc`
// output, but this must never panic on unexpected input).
func returnClause(sig string) (string, bool) {
	open := strings.Index(sig, "(")
	if open < 0 {
		return "", false
	}
	depth := 0
	for i := open; i < len(sig); i++ {
		switch sig[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return strings.TrimSpace(sig[i+1:]), true
			}
		}
	}
	return "", false
}

// classifyReturnType reduces a `go doc` return clause to a single (alias, typeName) pair. A
// multi-value return "(T, error)" is reduced to its first non-error element. A leading "*" is
// stripped, and a trailing generic instantiation "[...]" is stripped. A package-qualified type
// ("tokens.Claims[C]") is attributed to that qualifier's alias when tracked; an unqualified type
// ("Service[C]") is attributed to the calling alias (the common constructor-in-same-package
// case). Anything else (multiple non-error candidates, an untracked qualifier, a lowercase/local
// type) reports ok=false.
func classifyReturnType(callAlias, retClause string) (string, string, bool) {
	retClause = strings.TrimSpace(retClause)
	retClause = strings.TrimPrefix(retClause, "(")
	retClause = strings.TrimSuffix(retClause, ")")

	var candidates []string
	depth := 0
	last := 0
	for i, r := range retClause {
		switch r {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case ',':
			if depth == 0 {
				candidates = append(candidates, strings.TrimSpace(retClause[last:i]))
				last = i + 1
			}
		}
	}
	candidates = append(candidates, strings.TrimSpace(retClause[last:]))

	var kept []string
	for _, c := range candidates {
		if c != "error" && c != "" {
			kept = append(kept, c)
		}
	}
	if len(kept) != 1 {
		return "", "", false
	}
	t := strings.TrimPrefix(kept[0], "*")
	if idx := strings.IndexByte(t, '['); idx >= 0 {
		t = t[:idx]
	}
	alias := callAlias
	if idx := strings.LastIndexByte(t, '.'); idx >= 0 {
		alias = t[:idx]
		t = t[idx+1:]
		if _, tracked := pkgAlias[alias]; !tracked {
			return "", "", false
		}
	}
	if t == "" || t[0] < 'A' || t[0] > 'Z' {
		return "", "", false
	}
	return alias, t, true
}
