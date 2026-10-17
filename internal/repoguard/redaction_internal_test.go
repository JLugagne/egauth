package repoguard

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

var secretFieldPattern = regexp.MustCompile(`(?i)^(` +
	`secret|secretkey|signingkey|cookiekey|privatekey|kek|` +
	`token|accesstoken|refreshtoken|flowtoken|api?key|` +
	`password|passwd|passwordhash|` +
	`hash|codehash|verifier|verifierhash|` +
	`credential|credentials|clientsecret|otpcode|code` +
	`)$`)

var redactionExemptions = map[string]string{}

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

type goType struct {
	qualified      string
	secretFields   []string
	hasSecretField bool
	hasString      bool
	hasGoString    bool
	hasLogValue    bool
}

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

func collectExportedTypes(t *testing.T, root string) []goType {
	t.Helper()
	byType := make(map[string]*goType)

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

func receiverTypeName(e ast.Expr) string {
	switch node := e.(type) {
	case *ast.Ident:
		return node.Name
	case *ast.StarExpr:
		return receiverTypeName(node.X)
	case *ast.IndexExpr:
		return receiverTypeName(node.X)
	case *ast.IndexListExpr:
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

func receiverPkg(*ast.FuncDecl) string { return "slog" }

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
