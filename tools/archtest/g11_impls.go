package archtest

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/packages"
)

// G11 holds every implementation of a store-like interface to its compile-time assertion and its
// contract suite.
const G11 GuardID = "G11"

func init() { RegisterList(G11Exemptions()) }

const maxG11Entries = LegacyPrefixCount

var g11Exemptions = LegacyExemptions(G11)

// G11Exemptions returns the exemptions that the workspace test filters CheckG11 findings with.
func G11Exemptions() ExemptionList {
	return ExemptionList{Guard: G11, MaxEntries: maxG11Entries, Entries: g11Exemptions}
}

type suiteInterface struct {
	rel, name string
	needsLine bool
}

var storeLikeFixed = []suiteInterface{
	{rel: "kek", name: "KEK", needsLine: true},
	{rel: "limiter", name: "Limiter", needsLine: true},
	{rel: "store/limiter", name: "Limiter", needsLine: true},
	{rel: "federation", name: "Store", needsLine: true},
}

var backendInterface = suiteInterface{rel: "internal/session", name: "Backend"}

type moduleView struct {
	universe map[string]*packages.Package
	plain    []*packages.Package
	all      []*packages.Package
}

func (w *Workspace) moduleViews() []moduleView {
	var out []moduleView
	for _, m := range w.Modules {
		v := moduleView{universe: map[string]*packages.Package{}}
		seen := map[string]bool{}
		packages.Visit(m.Pkgs, nil, func(p *packages.Package) {
			if p.Types == nil {
				return
			}
			if cur, ok := v.universe[p.PkgPath]; !ok || (isTestVariant(cur) && !isTestVariant(p)) {
				v.universe[p.PkgPath] = p
			}
		})
		for _, p := range m.Pkgs {
			if strings.HasSuffix(p.PkgPath, ".test") || seen[p.ID] {
				continue
			}
			seen[p.ID] = true
			v.all = append(v.all, p)
			if !isTestVariant(p) && !strings.HasSuffix(p.PkgPath, "_test") {
				v.plain = append(v.plain, p)
			}
		}
		out = append(out, v)
	}
	return out
}

func (v moduleView) lookup(cfg Config, rel, name string) *types.Named {
	pkg := v.universe[cfg.path(rel)]
	if pkg == nil {
		return nil
	}
	tn, ok := pkg.Types.Scope().Lookup(name).(*types.TypeName)
	if !ok {
		return nil
	}
	n, ok := tn.Type().(*types.Named)
	if !ok {
		return nil
	}
	if it, ok := n.Underlying().(*types.Interface); !ok || it.NumMethods() == 0 {
		return nil
	}
	return n
}

func (v moduleView) storeLike(cfg Config) []suiteInterface {
	var out []suiteInterface
	for path := range v.universe {
		rel, ok := cfg.Rel(path)
		if !ok {
			continue
		}
		if rest, ok := strings.CutPrefix(rel, "store/"); ok && !strings.Contains(rest, "/") {
			out = append(out, suiteInterface{rel: rel, name: "Store", needsLine: true})
		}
	}
	return append(out, storeLikeFixed...)
}

type suiteCall struct {
	iface string
	typ   string
}

// CheckG11 rejects every concrete type, declared in a non-test file of any module, whose pointer
// implements a store-like interface (store/<name>.Store, kek.KEK, limiter.Limiter,
// federation.Store) without a "var _ I = (*T)(nil)" line in a non-test file of its own package or
// without a _test.go call to the interface's suite whose func literal argument returns I and whose
// return expression has exactly the type *T; only a literal whose single return statement is its
// last statement credits an implementation, so a type returned from a branch is never counted. The suite is a Run(*testing.T, func(*testing.T) I)
// function of a package below the interface's package: storetest for store/<name>.Store,
// backendtest for internal/session.Backend, a package named *test otherwise. It also rejects every
// concrete implementation of internal/session.Backend that is not returned from the func literal
// passed to backendtest.Run. An interface with implementations but no suite call at all is
// reported once. A generic type is checked through its instantiation with its constraints.
// Interfaces without methods are ignored.
func CheckG11(ws *Workspace, cfg Config) []Violation {
	var out []Violation
	for _, v := range ws.moduleViews() {
		runs, lines := v.collect(cfg)
		defs := v.storeLike(cfg)
		defs = append(defs, backendInterface)
		for _, def := range defs {
			iface := v.lookup(cfg, def.rel, def.name)
			if iface == nil {
				continue
			}
			ikey := typeSymbol(iface)
			implemented := false
			for _, impl := range v.implementations(iface) {
				implemented = true
				pkg := impl.pkg
				tkey := typeSymbol(impl.named)
				report := func(msg string) {
					out = append(out, Violation{Guard: G11, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, impl.named.Obj().Pos()), Symbols: []string{tkey}, Msg: tkey + " " + msg + " " + ikey})
				}
				if def.needsLine && !lines[suiteCall{ikey, tkey}] {
					report("lacks a var _ assertion for")
				}
				if !runs[suiteCall{ikey, tkey}] {
					report("is not passed to a Run suite as the exact type returned for")
				}
			}
			if implemented && !runs[suiteCall{ikey, ""}] {
				pkg := v.universe[iface.Obj().Pkg().Path()]
				out = append(out, Violation{Guard: G11, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, iface.Obj().Pos()), Symbols: []string{ikey}, Msg: ikey + " has implementations but no Run suite"})
			}
		}
	}
	return dedupe(out)
}

type implementation struct {
	pkg   *packages.Package
	named *types.Named
}

func (v moduleView) implementations(iface *types.Named) []implementation {
	it := iface.Underlying().(*types.Interface)
	var out []implementation
	for _, pkg := range v.plain {
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok || tn.IsAlias() || posInTestFile(pkg.Fset, tn.Pos()) {
				continue
			}
			n, ok := tn.Type().(*types.Named)
			if !ok {
				continue
			}
			if _, isIface := n.Underlying().(*types.Interface); isIface {
				continue
			}
			if types.Implements(types.NewPointer(instantiateWithConstraints(n)), it) {
				out = append(out, implementation{pkg: pkg, named: n})
			}
		}
	}
	return out
}

func instantiateWithConstraints(n *types.Named) types.Type {
	tps := n.TypeParams()
	if tps.Len() == 0 {
		return n
	}
	args := make([]types.Type, tps.Len())
	for i := range args {
		args[i] = tps.At(i).Constraint()
		if core := coreType(args[i]); core != nil {
			args[i] = core
		}
	}
	inst, err := types.Instantiate(nil, n, args, false)
	if err != nil {
		return n
	}
	return inst
}

func coreType(constraint types.Type) types.Type {
	it, ok := constraint.Underlying().(*types.Interface)
	if !ok || it.NumEmbeddeds() != 1 {
		return nil
	}
	u, ok := it.EmbeddedType(0).(*types.Union)
	if !ok || u.Len() != 1 {
		return nil
	}
	return u.Term(0).Type()
}

func (v moduleView) collect(cfg Config) (runs, lines map[suiteCall]bool) {
	runs, lines = map[suiteCall]bool{}, map[suiteCall]bool{}
	for _, pkg := range v.all {
		info := pkg.TypesInfo
		for _, f := range pkg.Syntax {
			inTest := isTestFile(pkg.Fset.Position(f.Pos()).Filename)
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.ValueSpec:
					if !inTest {
						recordAssertion(info, pkg.PkgPath, x, lines)
					}
				case *ast.CallExpr:
					if inTest {
						recordRun(cfg, info, x, runs)
					}
				}
				return true
			})
		}
	}
	return runs, lines
}

func recordAssertion(info *types.Info, pkgPath string, spec *ast.ValueSpec, out map[suiteCall]bool) {
	if len(spec.Names) != 1 || spec.Names[0].Name != "_" || spec.Type == nil || len(spec.Values) != 1 {
		return
	}
	iface, ok := types.Unalias(info.TypeOf(spec.Type)).(*types.Named)
	if !ok {
		return
	}
	call, ok := ast.Unparen(spec.Values[0]).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return
	}
	ptr, ok := types.Unalias(info.TypeOf(call.Fun)).(*types.Pointer)
	if !ok {
		return
	}
	if n, ok := types.Unalias(ptr.Elem()).(*types.Named); ok && objPkgPath(n.Obj()) == pkgPath {
		out[suiteCall{typeSymbol(iface), typeSymbol(n)}] = true
	}
}

func isSuiteRun(cfg Config, fn *types.Func, iface *types.Named) bool {
	if fn.Name() != "Run" || fn.Pkg() == nil || recvNamed(fn) != nil {
		return false
	}
	sig := fn.Type().(*types.Signature)
	if sig.Params().Len() != 2 {
		return false
	}
	if p, ok := types.Unalias(sig.Params().At(0).Type()).(*types.Pointer); !ok || !namedIs(p.Elem(), "testing", "T") {
		return false
	}
	ifacePath := objPkgPath(iface.Obj())
	if !strings.HasPrefix(fn.Pkg().Path(), ifacePath+"/") {
		return false
	}
	name := fn.Pkg().Name()
	rel, _ := cfg.Rel(ifacePath)
	switch {
	case strings.HasPrefix(rel, "store/"):
		return name == "storetest"
	case rel == backendInterface.rel && iface.Obj().Name() == backendInterface.name:
		return name == "backendtest"
	}
	return strings.HasSuffix(name, "test")
}

func recordRun(cfg Config, info *types.Info, call *ast.CallExpr, out map[suiteCall]bool) {
	var id *ast.Ident
	switch f := call.Fun.(type) {
	case *ast.SelectorExpr:
		id = f.Sel
	case *ast.Ident:
		id = f
	default:
		return
	}
	fn, ok := info.Uses[id].(*types.Func)
	if !ok {
		return
	}
	for _, arg := range call.Args {
		lit, ok := arg.(*ast.FuncLit)
		if !ok {
			continue
		}
		sig, ok := info.TypeOf(lit).(*types.Signature)
		if !ok || sig.Results().Len() != 1 {
			continue
		}
		iface, ok := types.Unalias(sig.Results().At(0).Type()).(*types.Named)
		if !ok || !isSuiteRun(cfg, fn, iface) {
			continue
		}
		ikey := typeSymbol(iface)
		out[suiteCall{ikey, ""}] = true
		r := soleFinalReturn(lit.Body)
		if r == nil || len(r.Results) != 1 {
			continue
		}
		if ptr, ok := types.Unalias(info.TypeOf(r.Results[0])).(*types.Pointer); ok {
			if tn, ok := types.Unalias(ptr.Elem()).(*types.Named); ok {
				out[suiteCall{ikey, typeSymbol(tn)}] = true
			}
		}
	}
}

func soleFinalReturn(body *ast.BlockStmt) *ast.ReturnStmt {
	if body == nil || len(body.List) == 0 {
		return nil
	}
	last, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	if !ok {
		return nil
	}
	returns := 0
	ast.Inspect(body, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			returns++
		}
		return true
	})
	if returns != 1 {
		return nil
	}
	return last
}
