package archtest

import (
	"go/types"
	"regexp"

	"golang.org/x/tools/go/packages"
)

// G07a is the lexical first pass that keeps insecure opt-outs in one place.
const G07a GuardID = "G07a"

func init() { RegisterList(G07aExemptions()) }

const maxG07aEntries = LegacyPrefixCount + 4

var g07aEventTypes = []string{"AccountDisabled", "MFADisabled", "InsecureCookieMisuse", "InsecureConfiguration"}

var g07aExemptions = g07aBuildExemptions()

func g07aBuildExemptions() []Exemption {
	out := LegacyExemptions(G07a)
	for _, name := range g07aEventTypes {
		out = append(out, Exemption{Guard: G07a, Symbol: ModulePath + "/event." + name, RemovedBy: Permanent})
	}
	return out
}

// G07aExemptions returns the exemptions that the workspace test filters CheckG07a findings with.
// Besides the legacy prefixes it names, one by one, the event.Type constants whose observation name
// reads like an opt-out; a new such constant needs its own reviewed entry.
func G07aExemptions() ExemptionList {
	return ExemptionList{Guard: G07a, MaxEntries: maxG07aEntries, Entries: g07aExemptions}
}

var optOutName = regexp.MustCompile(`^(Insecure|Allow|Without|Skip|Disable|No|Trust|Permit|Unsafe|Lax|Relax|Legacy|Bypass|Ignore|Expose|Export)[A-Z]|(Disabled|Insecure|Unsafe|Bypass)$`)

// OptOutAllowance is a typed, permanent permission to declare an opt-out-looking name: Name is a
// package-level name or "Type.Member" in the package at Rel (relative to the root package, empty
// for the root). It is not an exemption: the set is fixed by DESIGN.md section 9.2, pinned by a
// test, and its symbols may not exist yet.
type OptOutAllowance struct {
	Rel       string
	Name      string
	RemovedBy WorkPackage
}

var optOutAllowances = []OptOutAllowance{
	{Rel: "adapters/otel", Name: "Options.ExportPII", RemovedBy: Permanent},
	{Rel: "kek", Name: "LegacyOpener", RemovedBy: WPV018},
	{Rel: "kek", Name: "LegacyLocalV016", RemovedBy: WPV018},
	{Rel: "", Name: "UpgradeSecretsV016", RemovedBy: WPV018},
}

// OptOutAllowances returns the typed entries of G07a.
func OptOutAllowances() []OptOutAllowance {
	out := make([]OptOutAllowance, len(optOutAllowances))
	copy(out, optOutAllowances)
	return out
}

var optOutHomes = []string{"InsecureOptOuts", "ResourceInsecure"}

// CheckG07a rejects exported names of non-internal packages that look like an opt-out (a leading
// Insecure, Allow, Without, Skip, Disable, No, Trust, Permit, Unsafe, Lax, Relax, Legacy, Bypass,
// Ignore, Expose or Export before a capital, or a trailing Disabled, Insecure, Unsafe or Bypass):
// package-level objects, the exported fields (nested anonymous structs included) and methods of
// exported types, the fields of anonymous structs reachable from exported objects, and the exported
// members of every type reachable from that API, unexported or internal types included. Accepted:
// the types egauth.InsecureOptOuts and egauth.ResourceInsecure with everything they declare, a field
// named Insecure of one of those types and the OptOutAllowances. Package main is skipped. An event.Type
// constant gets no blanket acceptance: it is exempted by name in G07aExemptions.
func CheckG07a(ws *Workspace, cfg Config) []Violation {
	var out []Violation
	allowed := map[string]bool{}
	for _, a := range optOutAllowances {
		allowed[cfg.path(a.Rel)+"."+a.Name] = true
	}
	homes := map[string]bool{}
	for _, h := range optOutHomes {
		homes[cfg.Root+"."+h] = true
	}
	report := func(pkg *packages.Package, pkgPath string, exposers []string, obj types.Object, sym string) {
		if allowed[sym] || !optOutName.MatchString(obj.Name()) || holdsHome(obj, homes) {
			return
		}
		out = append(out, Violation{
			Guard: G07a, Pkg: pkgPath, Pos: ws.relPos(pkg.Fset, obj.Pos()), Symbols: []string{sym}, Exposers: exposers,
			Msg: "opt-out looking name " + obj.Name() + " outside InsecureOptOuts and ResourceInsecure",
		})
	}
	visited := map[*types.TypeName]bool{}
	members := func(pkg *packages.Package, named *types.Named, exposers []string) {
		obj := named.Obj()
		sym := typeSymbol(named)
		if visited[obj] || homes[sym] {
			return
		}
		visited[obj] = true
		pkgPath := objPkgPath(obj)
		emit := func(o types.Object, s string) { report(pkg, pkgPath, exposers, o, s) }
		switch u := named.Underlying().(type) {
		case *types.Struct:
			optOutFields(u, sym, emit)
		case *types.Interface:
			for i := 0; i < u.NumExplicitMethods(); i++ {
				if m := u.ExplicitMethod(i); m.Exported() {
					emit(m, sym+"."+m.Name())
					optOutAnon(m.Type(), sym+"."+m.Name(), emit)
				}
			}
		default:
			optOutAnon(u, sym, emit)
		}
		for i := 0; i < named.NumMethods(); i++ {
			if m := named.Method(i); m.Exported() && !posInTestFile(pkg.Fset, m.Pos()) {
				emit(m, sym+"."+m.Name())
				optOutAnon(m.Type(), sym+"."+m.Name(), emit)
			}
		}
	}
	ws.eachObject(func(pkg *packages.Package, obj types.Object) {
		sym := pkg.PkgPath + "." + obj.Name()
		if isInternalPath(pkg.PkgPath) || !obj.Exported() || homes[sym] {
			return
		}
		emit := func(o types.Object, s string) { report(pkg, pkg.PkgPath, nil, o, s) }
		emit(obj, sym)
		tn, ok := obj.(*types.TypeName)
		if !ok {
			optOutAnon(obj.Type(), sym, emit)
			return
		}
		if tn.IsAlias() {
			return
		}
		if named, ok := tn.Type().(*types.Named); ok {
			members(pkg, named, nil)
		}
	})
	for _, st := range ws.surfaceTypes(false, false) {
		if st.own {
			members(st.pkg, st.named.Origin(), st.exposers)
		}
	}
	return dedupe(out)
}

func optOutFields(st *types.Struct, prefix string, emit func(types.Object, string)) {
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if !f.Exported() {
			continue
		}
		emit(f, prefix+"."+f.Name())
		optOutAnon(f.Type(), prefix+"."+f.Name(), emit)
	}
}

func optOutAnon(t types.Type, prefix string, emit func(types.Object, string)) {
	switch u := types.Unalias(t).(type) {
	case *types.Struct:
		optOutFields(u, prefix, emit)
	case *types.Pointer:
		optOutAnon(u.Elem(), prefix, emit)
	case *types.Slice:
		optOutAnon(u.Elem(), prefix, emit)
	case *types.Array:
		optOutAnon(u.Elem(), prefix, emit)
	case *types.Chan:
		optOutAnon(u.Elem(), prefix, emit)
	case *types.Map:
		optOutAnon(u.Key(), prefix, emit)
		optOutAnon(u.Elem(), prefix, emit)
	case *types.Signature:
		for _, tuple := range []*types.Tuple{u.Params(), u.Results()} {
			for i := 0; i < tuple.Len(); i++ {
				optOutAnon(tuple.At(i).Type(), prefix, emit)
			}
		}
	}
}

func holdsHome(obj types.Object, homes map[string]bool) bool {
	f, ok := obj.(*types.Var)
	if !ok || !f.IsField() || f.Name() != "Insecure" {
		return false
	}
	n := derefNamed(f.Type())
	return n != nil && homes[typeSymbol(n)]
}
