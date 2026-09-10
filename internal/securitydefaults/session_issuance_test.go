package securitydefaults

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loginPackages are the packages that own interactive login/session-issuance paths. Every one
// of them must mint credentials through the unified issuance pipeline; a direct call to
// tokens.Issuer.IssueTokenPair in any of them bypasses the post-authentication invariants
// (authoritative account re-load, tenant binding, must-change propagation, MFA gate, uniform
// audit event) and is rejected here.
var loginPackages = []string{
	"authflow",
	"identity",
	"mfa",
	"oauth",
	"otp",
	"passkey",
	"webapp",
}

// TestLoginPackagesMintOnlyThroughIssuancePipeline is the negative guard: it walks the login
// packages' source and fails on any direct tokens.Issuer.IssueTokenPair call. The only legal
// minting site is issuance.Pipeline.Issue, which is a different package and therefore not
// scanned.
func TestLoginPackagesMintOnlyThroughIssuancePipeline(t *testing.T) {
	root := repoRoot(t)
	var violations []string
	for _, pkg := range loginPackages {
		violations = append(violations, directIssueTokenPairCalls(t, root, pkg)...)
	}
	for _, v := range violations {
		t.Errorf("login path calls IssueTokenPair directly instead of going through the issuance pipeline: %s", v)
	}
}

// TestDirectIssueTokenPairDetection demonstrates the walker used above actually detects the
// forbidden call, so a future login path cannot pass the guard by accident of scanning.
func TestDirectIssueTokenPairDetection(t *testing.T) {
	found := issueTokenPairCallsInSource(t, "pkg/x.go", `package x

func f() {
	issuer.IssueTokenPair(ctx, claims)
}
`)
	if len(found) != 1 {
		t.Fatalf("expected the walker to detect one direct IssueTokenPair call, got %v", found)
	}
	if !strings.Contains(found[0], "IssueTokenPair") {
		t.Fatalf("detection result must name the call, got %v", found)
	}
}

// directIssueTokenPairCalls returns the file:line of every direct IssueTokenPair call in the
// non-test Go files of root/pkg.
func directIssueTokenPairCalls(t *testing.T, root, pkg string) []string {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(pkg))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading login package %s: %v", pkg, err)
	}
	var found []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading %s/%s: %v", pkg, name, err)
		}
		found = append(found, issueTokenPairCallsInSource(t, filepath.ToSlash(filepath.Join(pkg, name)), string(src))...)
	}
	return found
}

// issueTokenPairCallsInSource parses src and returns the positions of every call expression
// whose callee is a selector named IssueTokenPair. Comments and strings are ignored because the
// check operates on the AST, not raw bytes.
func issueTokenPairCallsInSource(t *testing.T, filename, src string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", filename, err)
	}
	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "IssueTokenPair" {
			return true
		}
		pos := fset.Position(call.Pos())
		found = append(found, pos.String()+": IssueTokenPair")
		return true
	})
	return found
}
