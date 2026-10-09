package flow_test

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
)

const modulePath = "github.com/JLugagne/egauth"

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	must(t, err)
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && strings.Contains(string(b), "module "+modulePath+"\n") {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("module root not found")
		}
		dir = parent
	}
}

type flowRef struct {
	pkg, name string
	allowed   []string
}

var flowRefs = []flowRef{
	{pkg: modulePath + "/internal/cookie", name: "Flow", allowed: []string{"internal/flow"}},
	{pkg: modulePath + "/internal/ceremonycodec", name: "MFAFlow", allowed: []string{"internal/flow", "internal/issuance"}},
	{pkg: modulePath + "/store/ceremony", name: "MFAFlow", allowed: []string{
		"internal/flow", "internal/issuance", "internal/ceremonycodec", "internal/lifecycle", "store/ceremony/", "adapters/pgx/store/ceremony/",
	}},
}

const flowCookieName = "egauth_flow"

func allowedIn(rel string, prefixes []string) bool {
	for _, p := range prefixes {
		if rel == strings.TrimSuffix(p, "/") || (strings.HasSuffix(p, "/") && strings.HasPrefix(rel+"/", p)) {
			return true
		}
	}
	return false
}

func walkGo(t *testing.T, root string, visit func(rel string, f *ast.File)) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		visit(filepath.ToSlash(rel), f)
		return nil
	})
	must(t, err)
}

func importNames(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := p[strings.LastIndex(p, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		out[name] = p
	}
	return out
}

// TestOnlyTheFlowReadsParkedLogins closes T-06 (and I-01, W-06) statically: outside internal/flow no
// non-test code names the flow cookie, and outside internal/flow and internal/issuance (which only
// writes the record) no code names the MFAFlow kind or codec, except the ceremony store contract and
// its implementations and internal/lifecycle, which only deletes parked flows and never reads one.
// The bypasses of a selector match are closed too: a dot import of those
// packages, the flow cookie's name as a literal outside internal/cookie, and a conversion to
// ceremony.Kind. Session gates, /session and every other endpoint therefore cannot read a parked
// login.
func TestOnlyTheFlowReadsParkedLogins(t *testing.T) {
	root := repoRoot(t)
	seen := map[string]int{}
	walkGo(t, root, func(rel string, f *ast.File) {
		names := importNames(f)
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			for _, ref := range flowRefs {
				if imp.Name != nil && imp.Name.Name == "." && p == ref.pkg && !allowedIn(rel, ref.allowed) {
					t.Errorf("%s dot-imports %s; only %v may use it", rel, p, ref.allowed)
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(lit.Value, flowCookieName) && rel != "internal/cookie" {
				t.Errorf("%s spells the flow cookie name %s; only internal/cookie may", rel, lit.Value)
			}
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && names[x.Name] == modulePath+"/store/ceremony" && sel.Sel.Name == "Kind" &&
						!allowedIn(rel, flowRefs[len(flowRefs)-1].allowed) {
						t.Errorf("%s converts to ceremony.Kind; only %v may", rel, flowRefs[len(flowRefs)-1].allowed)
					}
				}
			}
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			x, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			for _, ref := range flowRefs {
				if names[x.Name] != ref.pkg || sel.Sel.Name != ref.name {
					continue
				}
				seen[rel]++
				if !allowedIn(rel, ref.allowed) {
					t.Errorf("%s uses %s.%s; only %v may", rel, ref.pkg, ref.name, ref.allowed)
				}
			}
			return true
		})
	})
	if seen["internal/flow"] == 0 || seen["internal/issuance"] == 0 {
		t.Fatalf("the scan found no use in the owners (%v); it is not looking at the tree", seen)
	}
}

// TestIssuanceNeverReadsFlows pins the write-only side of T-06: issuance stores MFAFlow records but
// holds no reader, so it cannot resume a parked login on its own.
func TestIssuanceNeverReadsFlows(t *testing.T) {
	root := repoRoot(t)
	walkGo(t, filepath.Join(root, "internal", "issuance"), func(rel string, f *ast.File) {
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "Peek", "Consume", "RecordFailure", "MarkConsumed", "Read":
					t.Errorf("internal/issuance%s calls %s", rel, sel.Sel.Name)
				}
			}
			return true
		})
	})
}

// TestDeletedHandshakeAPIIsNotRecreated pins DESIGN §5.5 (D-06) in the packages that own the
// handshake: no interim state, no per-handler MFA gate or flow option, no step-up handler and no
// exported TOTP verifier.
func TestDeletedHandshakeAPIIsNotRecreated(t *testing.T) {
	forbidden := []string{
		"Interim", "DenyInterim", "WithDenyInterim", "WithMFAGate", "WithAuthFlow", "WithInterimTokenTTL",
		"StepUpHandler", "StepUpClaimsBuilder", "WithInsecureEchoSessionState", "VerifyTOTP",
	}
	root := repoRoot(t)
	for _, dir := range []string{"internal/flow", "internal/issuance"} {
		walkGo(t, filepath.Join(root, filepath.FromSlash(dir)), func(_ string, f *ast.File) {
			ast.Inspect(f, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				for _, bad := range forbidden {
					if id.Name == bad || (id.IsExported() && strings.Contains(id.Name, "Interim")) {
						t.Errorf("%s declares or uses %s, deleted by DESIGN §5.5", dir, id.Name)
					}
				}
				return true
			})
		})
	}
}
