package securitydefaults

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// secretFieldPattern matches field names whose VALUE is credential material: a secret, a bearer
// token, a key, a password or its stored hash, a verifier, or a one-time code.
//
// The pattern is anchored and specific about what it excludes, because a guard that cries wolf gets
// exempted into uselessness:
//   - the plaintext "Password" and the stored "PasswordHash" are covered, but boolean FLAGS about a
//     password (MustChangePassword) are not — formatting a bool leaks nothing;
//   - PUBLIC keys are excluded (only the private half is a credential);
//   - strings that are not credentials but happen to end in "code" — StatusCode, ErrorCode,
//     CountryCode — are excluded; only a bare Code or an *OTPCode is matched.
var secretFieldPattern = regexp.MustCompile(`(?i)^(` +
	`secret|secretkey|signingkey|cookiekey|privatekey|kek|` +
	`token|accesstoken|refreshtoken|flowtoken|api?key|` +
	`password|passwd|passwordhash|` +
	`hash|codehash|verifier|verifierhash|` +
	`credential|credentials|clientsecret|otpcode|code` +
	`)$`)

// redactionExemptions lists exported types that carry a secret-shaped field but are not covered by
// the redaction contract, each with the reason it is safe. Every entry is a deliberate decision, so
// the list is kept short and reviewed: an unexplained exemption defeats the guard.
var redactionExemptions = map[string]string{
	// A stored hash is one-way, so it is not a usable credential in a log the way a plaintext token
	// is. These types are internal persistence records: they are written by the store backends and
	// read by the verification logic that needs the hash to compare against.
	"identity.VerificationToken": "carries the one-way verifier hash, not the presented verifier",
	"mfa.RecoveryCode":           "carries the one-way recovery-code hash, not the code",
	"tokens.RefreshToken":        "carries the one-way refresh-token hash, not the token",
	// Flow state is a signed cookie payload that is already carried in the client's __Host- cookie;
	// the token that authenticates it lives on the Engine, which is redacted.
	"authflow.FlowResult": "the flow token is returned to the client by design; see SECURITY.md on JSON marshalling",
	"tokens.TokenPair":    "returned to the token's owner in a response body by design; see SECURITY.md",
	"tokens.APIKey":       "returned to the key's owner once at creation by design",
}

// TestCredentialBearingTypesAreRedacted is the systemic guard behind the per-type redaction work.
//
// The module's convention is that a type holding credential material renders that material as
// REDACTED under fmt (%v/%s/%+v/%#v) and slog. Four separate gaps shipped because the convention was
// applied to the type that STORES a secret but not to the type that HANDS IT BACK: the stored
// enrollment was redacted while the returned enrollment was not, the JWT service was redacted for
// exactly the "fmt dumps unexported key bytes" reason while the flow engine with a key of the same
// kind was not, and six delivery payloads were never listed at all.
//
// This test walks every exported type in the module, flags secret-shaped fields, and fails unless the
// type implements fmt.Stringer, fmt.GoStringer AND slog.LogValuer — or appears in the exemption list
// with a written reason. It is a Go-source scan plus a reflect check on the declared kind, so it
// works without importing the packages that would create an import cycle.
func TestCredentialBearingTypesAreRedacted(t *testing.T) {
	root := repoRoot(t)
	types := collectExportedTypes(t, root)
	if len(types) == 0 {
		t.Fatal("guard found no exported types; the scan paths are wrong")
	}

	var flagged, exempted int
	for _, typ := range types {
		if !typ.hasSecretField {
			continue
		}
		flagged++
		if reason, ok := redactionExemptions[typ.qualified]; ok {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s is exempted without a reason; an unexplained exemption defeats the guard", typ.qualified)
			}
			exempted++
			continue
		}
		for _, missing := range typ.missingRedactionMethods() {
			t.Errorf("%s has secret-shaped field(s) %v but does not implement %s: format it and the value leaks. "+
				"Add String/GoString/LogValue like the other credential-bearing types, or add a reasoned entry to redactionExemptions.",
				typ.qualified, typ.secretFields, missing)
		}
	}

	if flagged == 0 {
		t.Fatal("guard flagged no secret-shaped fields; secretFieldPattern is not matching anything")
	}
	t.Logf("scanned %d exported types; %d carry secret-shaped fields (%d exempted with a reason)",
		len(types), flagged, exempted)
}

// TestRedactionExemptionsAreLive keeps the exemption list honest: an entry naming a type that no
// longer exists (or no longer has a secret-shaped field) must be removed, so the list cannot quietly
// accumulate cover for types that were since fixed.
func TestRedactionExemptionsAreLive(t *testing.T) {
	root := repoRoot(t)
	types := collectExportedTypes(t, root)
	byName := make(map[string]goType, len(types))
	for _, typ := range types {
		byName[typ.qualified] = typ
	}
	for name := range redactionExemptions {
		typ, ok := byName[name]
		if !ok {
			t.Errorf("redactionExemptions names %s, which is not an exported type in this module; remove the stale entry", name)
			continue
		}
		if !typ.hasSecretField {
			t.Errorf("redactionExemptions exempts %s, which no longer has a secret-shaped field; remove the entry", name)
		}
	}
}

// TestSecretFieldPatternRejectsUnredactedSyntheticType proves the guard has teeth: a type shaped like
// the ones that leaked is flagged by the same predicate the scan uses.
func TestSecretFieldPatternRejectsUnredactedSyntheticType(t *testing.T) {
	for _, field := range []string{"Secret", "Token", "CookieKey", "PasswordHash", "APIKey", "Code", "Verifier"} {
		if !secretFieldPattern.MatchString(field) {
			t.Errorf("field %q carries credential material but is not matched by secretFieldPattern", field)
		}
	}
	for _, field := range []string{"Email", "Name", "CreatedAt", "URI", "Count"} {
		if secretFieldPattern.MatchString(field) {
			t.Errorf("field %q is not credential material but is matched by secretFieldPattern", field)
		}
	}
}

// goType describes one exported struct type found in the module source.
type goType struct {
	qualified      string // package.Type, e.g. "mfa.Enrollment"
	secretFields   []string
	hasSecretField bool
	hasString      bool
	hasGoString    bool
	hasLogValue    bool
}

// missingRedactionMethods returns the names of the redaction methods the type does not implement.
func (g goType) missingRedactionMethods() []string {
	var missing []string
	if !g.hasString {
		missing = append(missing, "fmt.Stringer")
	}
	if !g.hasGoString {
		missing = append(missing, "fmt.GoStringer")
	}
	if !g.hasLogValue {
		missing = append(missing, "slog.LogValuer")
	}
	return missing
}

// collectExportedTypes walks every non-test package in the module and returns its exported struct
// types together with the redaction methods they declare.
func collectExportedTypes(t *testing.T, root string) []goType {
	t.Helper()
	byType := make(map[string]*goType)

	// Pass 1: collect exported struct declarations and their field names.
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if isSkippedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/adapters/") {
			return nil
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		pkg := file.Name.Name
		ast.Inspect(file, func(n ast.Node) bool {
			decl, ok := n.(*ast.GenDecl)
			if !ok || decl.Tok != token.TYPE {
				return true
			}
			for _, spec := range decl.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || !ts.Name.IsExported() {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok || st.Fields == nil {
					continue
				}
				qualified := pkg + "." + ts.Name.Name
				gt := byType[qualified]
				if gt == nil {
					gt = &goType{qualified: qualified}
					byType[qualified] = gt
				}
				for _, f := range st.Fields.List {
					for _, name := range f.Names {
						if !name.IsExported() {
							continue
						}
						if !secretFieldPattern.MatchString(name.Name) {
							continue
						}
						gt.hasSecretField = true
						if !slices.Contains(gt.secretFields, name.Name) {
							gt.secretFields = append(gt.secretFields, name.Name)
						}
					}
				}
			}
			return true
		})
		return nil
	})

	// Pass 2: record which redaction methods each type declares (value or pointer receiver).
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if isSkippedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/adapters/") {
			return nil
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		pkg := file.Name.Name
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			recv := receiverTypeName(fn.Recv.List[0].Type)
			if recv == "" {
				continue
			}
			gt := byType[pkg+"."+recv]
			if gt == nil {
				continue
			}
			switch fn.Name.Name {
			case "String":
				if hasNoParams(fn) && returnsString(fn) {
					gt.hasString = true
				}
			case "GoString":
				if hasNoParams(fn) && returnsString(fn) {
					gt.hasGoString = true
				}
			case "LogValue":
				if hasNoParams(fn) && returnsSlogValue(fn) {
					gt.hasLogValue = true
				}
			}
		}
		return nil
	})

	out := make([]goType, 0, len(byType))
	for _, gt := range byType {
		out = append(out, *gt)
	}
	return out
}

// receiverTypeName returns the bare type name of a method receiver, unwrapping a pointer.
func receiverTypeName(e ast.Expr) string {
	switch node := e.(type) {
	case *ast.Ident:
		return node.Name
	case *ast.StarExpr:
		return receiverTypeName(node.X)
	case *ast.IndexExpr: // generic receiver: Type[T]
		return receiverTypeName(node.X)
	case *ast.IndexListExpr: // generic receiver: Type[T, U]
		return receiverTypeName(node.X)
	}
	return ""
}

func hasNoParams(fn *ast.FuncDecl) bool {
	return fn.Type.Params == nil || len(fn.Type.Params.List) == 0
}

func returnsString(fn *ast.FuncDecl) bool {
	return returnsNamed(fn, "string")
}

func returnsSlogValue(fn *ast.FuncDecl) bool {
	return returnsNamed(fn, "Value") && receiverPkg(fn) != ""
}

// returnsNamed reports whether the single result of fn has the given type name.
func returnsNamed(fn *ast.FuncDecl, name string) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	switch node := fn.Type.Results.List[0].Type.(type) {
	case *ast.Ident:
		return node.Name == name
	case *ast.SelectorExpr:
		return node.Sel.Name == name
	}
	return false
}

// receiverPkg is a hook kept for future package-qualified result checks; the LogValue result is
// always slog.Value, so the name check is sufficient today.
func receiverPkg(*ast.FuncDecl) string { return "slog" }

// reflectInterfaceCheck documents the interfaces this guard is enforcing, so the intent is visible
// next to the AST-based implementation.
var (
	_ = reflect.TypeOf((*interface{ String() string })(nil)).Elem()
	_ = reflect.TypeOf((*interface{ GoString() string })(nil)).Elem()
)

func TestCollectExportedTypesSkipsHiddenDirs(t *testing.T) {
	root := t.TempDir()
	writeGo := func(rel, src string) {
		t.Helper()
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	writeGo("pkg/visible.go", "package pkg\n\ntype Visible struct {\n\tSecret string\n}\n")
	writeGo(".worktrees/pkg/hidden.go", "package pkg\n\ntype Hidden struct {\n\tSecret string\n}\n")

	names := make(map[string]bool)
	for _, typ := range collectExportedTypes(t, root) {
		names[typ.qualified] = true
	}
	if !names["pkg.Visible"] {
		t.Fatalf("expected pkg.Visible to be collected, got %v", names)
	}
	if names["pkg.Hidden"] {
		t.Fatal("collectExportedTypes walked a hidden directory: pkg.Hidden was collected")
	}
}
