package egauth_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/principal"
)

const hookPrefix = "TestHook"

func hookCalls(t *testing.T, filename string, src any) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filename, src, 0)
	require.NoError(t, err)
	declared := map[*ast.Ident]bool{}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok {
			declared[fn.Name] = true
		}
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && !declared[id] && strings.HasPrefix(id.Name, hookPrefix) {
			out = append(out, id.Name)
		}
		return true
	})
	return out
}

func TestRootTestHooksAreCalledOnlyByEgauthtest(t *testing.T) {
	var offenders []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		slash := filepath.ToSlash(path)
		if d.IsDir() {
			if path != "." && (strings.HasPrefix(d.Name(), ".") || strings.HasPrefix(d.Name(), "_") || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasPrefix(slash, "egauthtest/") || slash == "testhooks.go" || slash == "testhooks_guard_test.go" {
			return nil
		}
		if len(hookCalls(t, path, nil)) > 0 {
			offenders = append(offenders, slash)
		}
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, offenders, "only egauthtest may call the root test hooks")
}

func TestHookGuardSeesACallFromAnyOtherPackage(t *testing.T) {
	src := "package x\nimport \"github.com/JLugagne/egauth\"\nvar _ = egauth.TestHookResolve[struct{}]\n"
	require.Equal(t, []string{"TestHookResolve"}, hookCalls(t, "x.go", src))
	require.Empty(t, hookCalls(t, "y.go", "package y\nfunc f() {}\n"))
}

func TestEveryExportedRootHookCarriesTheGuardedPrefix(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "testhooks.go", nil, 0)
	require.NoError(t, err)
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.IsExported() {
			require.True(t, strings.HasPrefix(fn.Name.Name, hookPrefix), "%s escapes the hook guard", fn.Name.Name)
		}
	}
}

func TestHookGuardSeesADotImportAndAnUnqualifiedReference(t *testing.T) {
	dot := "package x\nimport . \"github.com/JLugagne/egauth\"\nvar _ = TestHookResolve[struct{}]\n"
	require.Equal(t, []string{"TestHookResolve"}, hookCalls(t, "x.go", dot))
	inner := "package egauth\nfunc f() { _, _ = TestHookAPIKeyPrincipal[struct{}](APIKeyInfo{}, AppClaims[struct{}]{}) }\n"
	require.Equal(t, []string{"TestHookAPIKeyPrincipal"}, hookCalls(t, "y.go", inner))
	require.Empty(t, hookCalls(t, "z.go", "package z\nimport \"testing\"\nfunc TestHookishName(t *testing.T) {}\n"))
}

func TestRootHooksRefuseACallerOutsideEgauthtest(t *testing.T) {
	spec := egauthtest.PrincipalSpec{Machine: &egauth.APIKeyInfo{Kind: "ci", Name: "k"}}
	_, err := egauthtest.NewPrincipal[struct{}](spec)
	require.NoError(t, err, "egauthtest is the sanctioned caller")

	owner := principal.Subject{User: uuid.New()}
	info := egauth.APIKeyInfo{ID: uuid.New(), Kind: "ci", Name: "k", Owner: owner, CreatedAt: egauthtest.ReferenceTime()}
	_, err = egauth.TestHookAPIKeyPrincipal(info, egauth.AppClaims[struct{}]{Roles: []string{"admin"}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "egauthtest")

	_, err = egauth.TestHookSessionPrincipal(principal.SessionAttrs{}, egauth.AppClaims[struct{}]{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "egauthtest")

	r, errs := egauth.TestHookResolve(egauthtest.Config[struct{}]())
	require.Nil(t, r)
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Error(), "egauthtest")
}
