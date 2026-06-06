// Command doctest guards the Hugo docs against API drift. It extracts every
// ```go fenced code block from the markdown under -dir and checks that each
// egauth package-qualified identifier it references (e.g. tokens.NewService,
// argon2.WithTime, passkey.Config) actually resolves to a real exported symbol
// in the current source — via `go doc`. A renamed function, a removed option,
// or a fabricated constructor therefore fails CI instead of silently shipping a
// misleading example.
//
// It deliberately checks ONLY qualified identifiers of the egauth packages we
// map below. Local variables (ctx, pool, userID, w, r, …), stdlib calls, and
// business logic are ignored, so the check has no false positives from the
// snippet style the docs use — every failure is a genuine drift.
//
// Usage:
//
//	go run ./internal/doctest            # scan docs/content, exit non-zero on drift
//	go run ./internal/doctest -dir X     # scan a different content root
//	go run ./internal/doctest -v         # list every resolved symbol too
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

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
	verbose := flag.Bool("v", false, "list every resolved symbol")
	flag.Parse()

	files, err := markdownFiles(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "doctest:", err)
		os.Exit(2)
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "doctest: no markdown files under %s\n", *dir)
		os.Exit(2)
	}

	var refs []ref
	for _, f := range files {
		rs, err := scan(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, "doctest:", err)
			os.Exit(2)
		}
		refs = append(refs, rs...)
	}

	// Resolve each distinct (importPath, symbol) once; report every doc site of
	// a broken one. Caching keeps `go doc` invocations to one per unique symbol.
	type key struct{ path, sym string }
	cache := map[key]bool{}
	seen := map[key]bool{}
	var failures int

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
			if verbose != nil && *verbose && !seen[k] {
				fmt.Printf("doctest: ok    %s.%s\n", r.alias, r.symbol)
			}
			seen[k] = true
			continue
		}
		failures++
		fmt.Printf("doctest: DRIFT %s:%d  %s.%s does not exist in %s\n",
			r.file, r.line, r.alias, r.symbol, path)
	}

	if failures > 0 {
		fmt.Printf("\ndoctest: %d doc reference(s) point at symbols that no longer exist. "+
			"Update the docs (or the alias map in internal/doctest) to match the current API.\n", failures)
		os.Exit(1)
	}
	fmt.Printf("doctest: all %d distinct egauth symbol(s) referenced across the docs resolve.\n", len(cache))
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
		// Strip line comments so prose-in-comments (e.g. "// see identity.Foo")
		// is not treated as a real call site.
		code := line
		if idx := strings.Index(code, "//"); idx >= 0 {
			code = code[:idx]
		}
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
			out = append(out, ref{file: path, line: i + 1, alias: alias, symbol: symbol})
		}
	}
	return out, nil
}

// symbolExists reports whether importPath exports symbol, via `go doc`. `go doc`
// prints "doc: no symbol X" / "no such package" but exits 0, so we key off the
// message text, not the exit code.
func symbolExists(importPath, symbol string) bool {
	cmd := exec.Command("go", "doc", importPath, symbol)
	out, _ := cmd.CombinedOutput()
	s := string(out)
	if strings.Contains(s, "no symbol") ||
		strings.Contains(s, "no such package") ||
		strings.Contains(s, "is not in") ||
		strings.Contains(s, "no buildable Go source files") ||
		strings.Contains(s, "build constraints exclude") {
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

func isAlnum(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}
