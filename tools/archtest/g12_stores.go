package archtest

import (
	"go/types"
	"strings"
)

// G12 enforces the method-set obligations of every store interface.
const G12 GuardID = "G12"

func init() { RegisterList(G12Exemptions()) }

const maxG12Entries = LegacyPrefixCount

var g12Exemptions = LegacyExemptions(G12)

// G12Exemptions returns the exemptions that the workspace test filters CheckG12 findings with.
func G12Exemptions() ExemptionList {
	return ExemptionList{Guard: G12, MaxEntries: maxG12Entries, Entries: g12Exemptions}
}

var eraseMethods = []string{"DeleteForSubject", "EraseUser"}

// StoreInterfaces returns the Store interfaces of the packages store/<name> of the workspace, which
// G11 and G12 hold to their obligations.
func StoreInterfaces(ws *Workspace, cfg Config) []*types.Named {
	var out []*types.Named
	for _, pkg := range ws.roots() {
		rel, ok := cfg.Rel(pkg.PkgPath)
		if !ok || pkg.Types == nil {
			continue
		}
		if rest, ok := strings.CutPrefix(rel, "store/"); !ok || strings.Contains(rest, "/") {
			continue
		}
		if n := lookupStoreInterface(pkg.Types); n != nil {
			out = append(out, n)
		}
	}
	return out
}

func lookupStoreInterface(p *types.Package) *types.Named {
	tn, ok := p.Scope().Lookup("Store").(*types.TypeName)
	if !ok {
		return nil
	}
	n, ok := tn.Type().(*types.Named)
	if !ok {
		return nil
	}
	if _, ok := n.Underlying().(*types.Interface); !ok {
		return nil
	}
	return n
}

// CheckG12 rejects a store/<name>.Store interface that does not embed store.Base, whose records
// carry an ExpiresAt field or method while it does not embed store.Reaper, or that is scoped to a
// user without a DeleteForSubject or EraseUser method. The records are the structs of the store's
// package, or of any other package under the root, reachable from its method signatures, through pointers, slices, arrays, maps, channels,
// functions, type arguments (iter.Seq) and the fields of other records. A store is user-scoped
// when a method other than the erase methods takes a parameter, or one of its records has a field,
// whose name or type name has a camel-case word naming a user: user, uid, sub, subject, account,
// owner, identity, member, person, customer or principal (userID, accountID, OwnerID, Subject...).
// Since an unnamed parameter hides a user key, a method not declared by the store package that
// takes an unnamed parameter other than a context.Context is rejected too. Embedding is transitive
// through embedded interfaces.
func CheckG12(ws *Workspace, cfg Config) []Violation {
	var out []Violation
	storePath := cfg.path("store")
	for _, n := range StoreInterfaces(ws, cfg) {
		iface := n.Underlying().(*types.Interface)
		pkg := ws.Package(n.Obj().Pkg().Path())
		report := func(msg string) {
			out = append(out, Violation{Guard: G12, Pkg: n.Obj().Pkg().Path(), Pos: ws.relPos(pkg.Fset, n.Obj().Pos()), Symbols: []string{typeSymbol(n)}, Msg: msg})
		}
		if !embeds(iface, storePath, "Base") {
			report("Store does not embed store.Base")
		}
		if hasExpiringRecord(cfg, iface, n.Obj().Pkg()) && !embeds(iface, storePath, "Reaper") {
			report("Store has records with ExpiresAt but does not embed store.Reaper")
		}
		for _, m := range unnamedParamMethods(iface, storePath) {
			report("Store." + m + " has an unnamed parameter; name every non-context parameter so a user key is visible")
		}
		if isUserScoped(cfg, iface, n.Obj().Pkg()) && !hasAnyMethod(iface, eraseMethods) {
			report("Store is user-scoped but has neither DeleteForSubject nor EraseUser")
		}
	}
	return dedupe(out)
}

func embeds(iface *types.Interface, pkgPath, name string) bool {
	for i := 0; i < iface.NumEmbeddeds(); i++ {
		t := types.Unalias(iface.EmbeddedType(i))
		if namedIs(t, pkgPath, name) {
			return true
		}
		if n, ok := t.(*types.Named); ok {
			if inner, ok := n.Underlying().(*types.Interface); ok && embeds(inner, pkgPath, name) {
				return true
			}
		}
	}
	return false
}

func hasAnyMethod(iface *types.Interface, names []string) bool {
	for i := 0; i < iface.NumMethods(); i++ {
		for _, n := range names {
			if iface.Method(i).Name() == n {
				return true
			}
		}
	}
	return false
}

func storeSignatures(iface *types.Interface, visit func(m *types.Func, t types.Type)) {
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		sig := m.Type().(*types.Signature)
		for _, tuple := range []*types.Tuple{sig.Params(), sig.Results()} {
			for j := 0; j < tuple.Len(); j++ {
				visit(m, tuple.At(j).Type())
			}
		}
	}
}

func unnamedParamMethods(iface *types.Interface, storePath string) []string {
	var out []string
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if m.Pkg() != nil && m.Pkg().Path() == storePath {
			continue
		}
		params := m.Type().(*types.Signature).Params()
		for j := 0; j < params.Len(); j++ {
			p := params.At(j)
			if (p.Name() == "" || p.Name() == "_") && !namedIs(p.Type(), "context", "Context") {
				out = append(out, m.Name())
				break
			}
		}
	}
	return out
}

func recordPackage(cfg Config, p, home *types.Package) bool {
	if p == home {
		return true
	}
	if p == nil {
		return false
	}
	_, inRoot := cfg.Rel(p.Path())
	return inRoot
}

func storeRecords(cfg Config, iface *types.Interface, home *types.Package) []*types.Named {
	var out []*types.Named
	seen := map[types.Type]bool{}
	var visit func(t types.Type)
	visit = func(t types.Type) {
		if seen[t] {
			return
		}
		seen[t] = true
		switch u := types.Unalias(t).(type) {
		case *types.Pointer:
			visit(u.Elem())
		case *types.Slice:
			visit(u.Elem())
		case *types.Array:
			visit(u.Elem())
		case *types.Chan:
			visit(u.Elem())
		case *types.Map:
			visit(u.Key())
			visit(u.Elem())
		case *types.Signature:
			for _, tuple := range []*types.Tuple{u.Params(), u.Results()} {
				for i := 0; i < tuple.Len(); i++ {
					visit(tuple.At(i).Type())
				}
			}
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				visit(u.Field(i).Type())
			}
		case *types.Named:
			for i := 0; i < u.TypeArgs().Len(); i++ {
				visit(u.TypeArgs().At(i))
			}
			if !recordPackage(cfg, u.Obj().Pkg(), home) {
				if _, isFunc := u.Underlying().(*types.Signature); isFunc {
					visit(u.Underlying())
				}
				return
			}
			if st, ok := u.Underlying().(*types.Struct); ok {
				out = append(out, u)
				visit(st)
			}
		}
	}
	storeSignatures(iface, func(_ *types.Func, t types.Type) { visit(t) })
	return out
}

func hasExpiringRecord(cfg Config, iface *types.Interface, home *types.Package) bool {
	for _, n := range storeRecords(cfg, iface, home) {
		if memberSuffixed(n, "ExpiresAt") {
			return true
		}
	}
	return false
}

func memberSuffixed(n *types.Named, suffix string) bool {
	if st, ok := n.Underlying().(*types.Struct); ok {
		for i := 0; i < st.NumFields(); i++ {
			if strings.HasSuffix(st.Field(i).Name(), suffix) {
				return true
			}
		}
	}
	ms := types.NewMethodSet(types.NewPointer(n))
	for i := 0; i < ms.Len(); i++ {
		if strings.HasSuffix(ms.At(i).Obj().Name(), suffix) {
			return true
		}
	}
	return false
}

var userKeyWords = []string{"user", "uid", "sub", "subject", "account", "owner", "identity", "member", "person", "customer", "principal"}

func hasUserWord(name string) bool {
	for _, w := range camelWords(name) {
		if inList(userKeyWords, strings.ToLower(w)) {
			return true
		}
	}
	return false
}

func isUserKey(name string, t types.Type) bool {
	if name != "" && hasUserWord(name) {
		return true
	}
	n := derefNamed(t)
	return n != nil && n.Obj().Pkg() != nil && hasUserWord(n.Obj().Name())
}

func isUserScoped(cfg Config, iface *types.Interface, home *types.Package) bool {
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if inList(eraseMethods, m.Name()) {
			continue
		}
		params := m.Type().(*types.Signature).Params()
		for j := 0; j < params.Len(); j++ {
			if p := params.At(j); isUserKey(p.Name(), p.Type()) {
				return true
			}
		}
	}
	for _, n := range storeRecords(cfg, iface, home) {
		st := n.Underlying().(*types.Struct)
		for i := 0; i < st.NumFields(); i++ {
			if f := st.Field(i); isUserKey(f.Name(), f.Type()) {
				return true
			}
		}
	}
	return false
}

func inList(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
