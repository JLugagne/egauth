package lint

import (
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/tools/go/packages"
)

const loadMode = packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
	packages.NeedImports | packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax |
	packages.NeedTypesInfo

type sourceFile struct {
	fset *token.FileSet
	file *ast.File
}

// Workspace is the type-checked view of the loaded modules that every guard resolves against.
// API references resolve against the exported scope of non-test packages, dependencies included
// (and the standard library as a fallback); enforced-by targets resolve only to test functions or
// suites; embedded examples come only from compiled _test.go files. It is safe for concurrent use
// once built.
type Workspace struct {
	root    string
	roots   []*packages.Package
	api     map[string][]*types.Package
	suites  map[string][]*types.Package
	tests   map[string]map[string]struct{}
	files   map[string]sourceFile
	stdOnce sync.Once
	std     map[string][]*types.Package
	varOnce sync.Once
	vars    map[string][]types.Object
}

// Load type-checks every package of each module directory (relative to root), tests included, with
// one go/packages load per module and env appended to the process environment (for example
// GOWORK=<root>/go.work). Any package or dependency error is returned, so a tree that does not
// compile never passes.
func Load(root string, env []string, modules ...string) (*Workspace, error) {
	w := &Workspace{
		root:   canonical(root),
		api:    map[string][]*types.Package{},
		suites: map[string][]*types.Package{},
		tests:  map[string]map[string]struct{}{},
		files:  map[string]sourceFile{},
	}
	for _, m := range modules {
		pkgs, err := loadModule(filepath.Join(root, m), env)
		if err != nil {
			return nil, errors.Join(errors.New("doclint: load module "+m), err)
		}
		w.roots = append(w.roots, pkgs...)
	}
	w.index()
	return w, nil
}

func loadModule(dir string, env []string) ([]*packages.Package, error) {
	cfg := &packages.Config{Mode: loadMode, Dir: dir, Env: append(os.Environ(), env...), Tests: true}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, err
	}
	var errs []error
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			errs = append(errs, errors.New(p.ID+": "+e.Error()))
		}
	})
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return pkgs, nil
}

func (w *Workspace) index() {
	seenAPI := map[string]bool{}
	packages.Visit(w.roots, nil, func(p *packages.Package) {
		if p.Types == nil || isTestPackage(p) || seenAPI[p.PkgPath] {
			return
		}
		seenAPI[p.PkgPath] = true
		w.api[p.Name] = append(w.api[p.Name], p.Types)
	})
	seenSuite := map[string]bool{}
	for _, p := range w.roots {
		if p.Types != nil && !isTestPackage(p) && !seenSuite[p.PkgPath] {
			seenSuite[p.PkgPath] = true
			w.suites[p.Name] = append(w.suites[p.Name], p.Types)
		}
		for _, f := range p.Syntax {
			name := canonical(p.Fset.Position(f.Pos()).Filename)
			w.files[name] = sourceFile{fset: p.Fset, file: f}
			if strings.HasSuffix(name, "_test.go") {
				w.indexTests(strings.TrimSuffix(p.Name, "_test"), f)
			}
		}
	}
}

func (w *Workspace) indexTests(pkg string, f *ast.File) {
	set := w.tests[pkg]
	if set == nil {
		set = map[string]struct{}{}
		w.tests[pkg] = set
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Recv == nil && isTestName(fn.Name.Name) {
			set[fn.Name.Name] = struct{}{}
		}
	}
}

func isTestPackage(p *packages.Package) bool {
	return strings.Contains(p.ID, " [") || strings.HasSuffix(p.ID, ".test") || strings.HasSuffix(p.Name, "_test")
}

func isTestName(name string) bool {
	for _, prefix := range []string{"Test", "Example", "Benchmark", "Fuzz"} {
		if rest, ok := strings.CutPrefix(name, prefix); ok {
			r, _ := utf8.DecodeRuneInString(rest)
			return rest == "" || !unicode.IsLower(r)
		}
	}
	return false
}

func isExampleName(name string) bool {
	rest, ok := strings.CutPrefix(name, "Example")
	if !ok {
		return false
	}
	r, _ := utf8.DecodeRuneInString(rest)
	return rest == "" || r == '_' || unicode.IsUpper(r)
}

// Resolve reports whether pkg.path[0] (followed by any further field or method selectors in path)
// names an exported API symbol of a non-test package called pkg. A path element ending in "()"
// is a call: the next selector applies to the single result of that function or method. Test
// files and _test packages never satisfy it. When no loaded or standard package is called pkg and
// pkg has at most three letters, the reference is read as a variable or receiver (r.Host,
// ctx.Err): it resolves only if a variable, parameter or receiver named pkg is declared in the
// loaded modules and its type has the whole selector chain. Longer names are never read as
// variables, so a reference into a deleted package such as session.Revoke still fails even when
// some local variable is called session.
func (w *Workspace) Resolve(pkg string, path ...string) bool {
	if len(path) == 0 {
		return false
	}
	for _, p := range w.api[pkg] {
		if lookupAPI(p, path) {
			return true
		}
	}
	w.stdOnce.Do(w.loadStd)
	for _, p := range w.std[pkg] {
		if lookupAPI(p, path) {
			return true
		}
	}
	if len(w.api[pkg]) > 0 || len(w.std[pkg]) > 0 || len(pkg) > 3 {
		return false
	}
	w.varOnce.Do(w.indexVars)
	for _, v := range w.vars[pkg] {
		if lookupChain(v, path) {
			return true
		}
	}
	return false
}

func (w *Workspace) indexVars() {
	w.vars = map[string][]types.Object{}
	seen := map[string]bool{}
	for _, p := range w.roots {
		if p.TypesInfo == nil {
			continue
		}
		for id, obj := range p.TypesInfo.Defs {
			v, ok := obj.(*types.Var)
			if !ok || v.IsField() || id.Name == "_" {
				continue
			}
			key := id.Name + " " + types.TypeString(v.Type(), nil)
			if seen[key] {
				continue
			}
			seen[key] = true
			w.vars[id.Name] = append(w.vars[id.Name], v)
		}
	}
}

// ResolveTest reports whether pkg.ident names a Test, Example, Benchmark or Fuzz function declared
// in a _test.go file of a loaded package called pkg, or whether pkg.ident (or pkg.ident.sel, a
// method) is a suite: an exported function of a loaded non-test kit package (its name ends in
// "test", like storetest) whose first parameter is *testing.T and which returns nothing. Helpers
// and factories taking testing.TB or returning a value are not suites.
func (w *Workspace) ResolveTest(pkg, ident, sel string) bool {
	if _, ok := w.tests[pkg][ident]; ok && sel == "" {
		return true
	}
	if !strings.HasSuffix(pkg, "test") {
		return false
	}
	for _, p := range w.suites[pkg] {
		if lookupSuite(p, ident, sel) {
			return true
		}
	}
	return false
}

func lookupAPI(p *types.Package, path []string) bool {
	name, call := strings.CutSuffix(path[0], "()")
	obj := p.Scope().Lookup(name)
	if obj == nil || !obj.Exported() {
		return false
	}
	if call {
		if obj = callResult(obj); obj == nil {
			return false
		}
	}
	return lookupChain(obj, path[1:])
}

func callResult(obj types.Object) types.Object {
	fn, ok := obj.(*types.Func)
	if !ok {
		return nil
	}
	res := fn.Signature().Results()
	if res.Len() != 1 {
		return nil
	}
	return types.NewVar(token.NoPos, fn.Pkg(), "", res.At(0).Type())
}

func lookupChain(obj types.Object, sels []string) bool {
	for _, el := range sels {
		sel, call := strings.CutSuffix(el, "()")
		if !token.IsExported(sel) {
			return false
		}
		switch obj.(type) {
		case *types.TypeName, *types.Var:
		default:
			return false
		}
		found, _, _ := types.LookupFieldOrMethod(obj.Type(), true, obj.Pkg(), sel)
		if found == nil {
			return false
		}
		obj = found
		if call {
			if obj = callResult(obj); obj == nil {
				return false
			}
		}
	}
	return true
}

func lookupSuite(p *types.Package, ident, sel string) bool {
	obj := p.Scope().Lookup(ident)
	if obj == nil || !obj.Exported() {
		return false
	}
	if sel == "" {
		fn, ok := obj.(*types.Func)
		return ok && isSuite(fn)
	}
	tn, ok := obj.(*types.TypeName)
	if !ok || !token.IsExported(sel) {
		return false
	}
	found, _, _ := types.LookupFieldOrMethod(tn.Type(), true, tn.Pkg(), sel)
	fn, ok := found.(*types.Func)
	return ok && isSuite(fn)
}

func isSuite(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Params().Len() == 0 || sig.Results().Len() != 0 {
		return false
	}
	ptr, ok := sig.Params().At(0).Type().(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := ptr.Elem().(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "testing" && named.Obj().Name() == "T"
}

// Example returns the body of the Example function name declared in file (relative to the root),
// without the surrounding braces and dedented by one tab. The file must be a _test.go file
// compiled into one of the loaded packages, so build-constrained files, testdata and any source
// that does not type-check are refused.
func (w *Workspace) Example(file, name string) (string, error) {
	if !strings.HasSuffix(file, "_test.go") {
		return "", errors.New("embed source " + file + " is not a _test.go file")
	}
	if !isExampleName(name) {
		return "", errors.New("embed target " + name + " is not an Example function")
	}
	path := canonical(filepath.Join(w.root, filepath.FromSlash(file)))
	sf, ok := w.files[path]
	if !ok {
		return "", errors.New("embed source " + file + " is not compiled by any loaded module")
	}
	for _, d := range sf.file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name != name || fn.Body == nil {
			continue
		}
		if fn.Type.Params.NumFields() != 0 || fn.Type.Results != nil || fn.Type.TypeParams != nil {
			return "", errors.New("embed target " + name + " is not an Example function: it must take and return nothing")
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return "", errors.Join(errors.New("embed source "+file+" unreadable"), err)
		}
		body := string(src[sf.fset.Position(fn.Body.Lbrace).Offset+1 : sf.fset.Position(fn.Body.Rbrace).Offset])
		return dedent(strings.Trim(body, "\r\n")), nil
	}
	return "", errors.New("embed example " + name + " not found in " + file)
}

func dedent(s string) string {
	lines := strings.Split(strings.TrimRight(s, " \t\r\n"), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(strings.TrimPrefix(l, "\t"), "\r")
	}
	return strings.Join(lines, "\n")
}

func (w *Workspace) loadStd() {
	w.std = map[string][]*types.Package{}
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedTypes, Env: os.Environ()}
	pkgs, err := packages.Load(cfg, "std")
	if err != nil {
		return
	}
	for _, p := range pkgs {
		if p.Types == nil || strings.HasPrefix(p.PkgPath, "vendor/") || isInternalPath(p.PkgPath) {
			continue
		}
		w.std[p.Name] = append(w.std[p.Name], p.Types)
	}
}

func isInternalPath(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == "internal" {
			return true
		}
	}
	return false
}

func canonical(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return filepath.Clean(path)
}

func relPath(root, path string) string {
	rel, err := filepath.Rel(canonical(root), canonical(path))
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}
