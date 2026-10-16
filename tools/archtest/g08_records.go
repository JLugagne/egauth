package archtest

import (
	"go/types"
	"regexp"
	"slices"

	"golang.org/x/tools/go/packages"
)

// G08 keeps session state in sealed form in the store records.
const G08 GuardID = "G08"

func init() { RegisterList(G08Exemptions()) }

const maxG08Entries = LegacyPrefixCount

var g08Exemptions = LegacyExemptions(G08)

// G08Exemptions returns the exemptions that the workspace test filters CheckG08 findings with.
func G08Exemptions() ExemptionList {
	return ExemptionList{Guard: G08, MaxEntries: maxG08Entries, Entries: g08Exemptions}
}

// RecordType names a record type of a store package by package path relative to the root.
type RecordType struct {
	Rel  string
	Name string
}

var sealedFreeRecords = []RecordType{{Rel: "store/tokens", Name: "APIKey"}}

// SealedFreeRecords returns the record types that may be written without a principal.Sealed field.
// They are listed by type, never by name. The set is fixed by DESIGN.md section 9.2 and pinned by
// a test.
func SealedFreeRecords() []RecordType {
	return slices.Clone(sealedFreeRecords)
}

var sealedStorePackages = []string{"store/tokens", "store/sessions"}

var readMethod = regexp.MustCompile(`^(Get|List|Find|Lookup|Count|Has|Is|Exists|Load|Fetch|Read|Ping|Durability)([A-Z0-9]|$)`)

var forbiddenRecordFields = []string{"AMR", "RememberMe", "AuthTime", "MustChangePassword", "Interim", "ReturnTo", "Factors", "Epoch"}

// ForbiddenRecordFields returns the field names that a struct of a non-internal package may not
// carry: session state is read through the sealed record, never stored in clear.
func ForbiddenRecordFields() []string {
	return slices.Clone(forbiddenRecordFields)
}

// CheckG08 enforces two rules over the store record types. Forward: every struct that a write
// method of tokens.Store or sessions.Store takes as a parameter (through pointers, slices, arrays,
// maps, channels and func signatures), whatever package declares it, has a field of type
// principal.Sealed, or wraps such records next to nothing but value types and at most one []byte or
// byte array (a lookup hash), unless it is one of SealedFreeRecords or a value
// type of the time, uuid, principal, store or internal/core packages; and ceremony.Record has a
// Pending field of type principal.Sealed. A write method takes no raw session state either: its
// other parameters are a context.Context, scalars and fixed-size arrays, value types, a sealed
// value and at most one []byte (a lookup hash). Every method is a write method except one whose name
// starts with a read verb (Get, List, Find, Lookup, Count, Has, Is, Exists, Load, Fetch, Read,
// Ping, Durability), carries no conjunction or write verb (GetOrCreate and LoadOrStore are
// writes) and returns something besides an error, so a new verb is checked by default; a read method still writes every record type it
// takes that a method of the store also returns. Inverse: no exported struct of a non-internal
// package, nor an exported variable, function or non-struct type of such a package holding an
// anonymous struct, nor any type reachable from that exported API (unexported and internal types
// included), has a field named by ForbiddenRecordFields, promoted fields of embedded structs and
// fields of nested anonymous structs included.
func CheckG08(ws *Workspace, cfg Config) []Violation {
	var out []Violation
	for _, rel := range sealedStorePackages {
		pkg := ws.Package(cfg.path(rel))
		if pkg == nil || pkg.Types == nil {
			continue
		}
		obj, ok := pkg.Types.Scope().Lookup("Store").(*types.TypeName)
		if !ok {
			continue
		}
		iface, ok := obj.Type().Underlying().(*types.Interface)
		if !ok {
			continue
		}
		returned := map[*types.TypeName]bool{}
		for i := 0; i < iface.NumMethods(); i++ {
			res := iface.Method(i).Type().(*types.Signature).Results()
			for j := 0; j < res.Len(); j++ {
				for _, rec := range recordParams(cfg, res.At(j).Type()) {
					returned[rec.Obj()] = true
				}
			}
		}
		checked := map[*types.TypeName]bool{}
		for i := 0; i < iface.NumMethods(); i++ {
			m := iface.Method(i)
			read := isReadMethod(m)
			sig := m.Type().(*types.Signature)
			hashes := 0
			for j := 0; j < sig.Params().Len(); j++ {
				p := sig.Params().At(j)
				recs := recordParams(cfg, p.Type())
				for _, rec := range recs {
					if (read && !returned[rec.Obj()]) || checked[rec.Obj()] {
						continue
					}
					checked[rec.Obj()] = true
					if isSealedFree(cfg, rec) || sealedRecord(cfg, rec, map[*types.TypeName]bool{}) {
						continue
					}
					recPkg := ws.Package(objPkgPath(rec.Obj()))
					if recPkg == nil {
						recPkg = pkg
					}
					out = append(out, Violation{
						Guard: G08, Pkg: objPkgPath(rec.Obj()), Pos: ws.relPos(recPkg.Fset, rec.Obj().Pos()), Symbols: []string{typeSymbol(rec)},
						Msg: rec.Obj().Name() + " is written by " + obj.Name() + "." + m.Name() + " but has no principal.Sealed field",
					})
				}
				if len(recs) > 0 || read || rawParamOK(cfg, p.Type(), &hashes) {
					continue
				}
				out = append(out, Violation{
					Guard: G08, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, p.Pos()), Symbols: []string{funcSymbol(m)},
					Msg: obj.Name() + "." + m.Name() + " takes the raw value " + p.Name() + " " + types.TypeString(p.Type(), shortQualifier) + "; session state is written through a sealed record",
				})
			}
		}
	}
	if pkg := ws.Package(cfg.path("store/ceremony")); pkg != nil && pkg.Types != nil {
		if obj, ok := pkg.Types.Scope().Lookup("Record").(*types.TypeName); ok {
			if n, ok := obj.Type().(*types.Named); ok && !hasSealedField(cfg, n, "Pending") {
				out = append(out, Violation{
					Guard: G08, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, obj.Pos()), Symbols: []string{typeSymbol(n)},
					Msg: "ceremony.Record has no principal.Sealed field named Pending",
				})
			}
		}
	}
	inverse := func(pkg *packages.Package, t types.Type, prefix string) {
		forbiddenIn(t, prefix, map[*types.TypeName]bool{}, func(f *types.Var, sym string) {
			out = append(out, Violation{
				Guard: G08, Pkg: objPkgPath(f), Pos: ws.relPos(pkg.Fset, f.Pos()), Symbols: []string{sym},
				Msg: "the session-state field " + f.Name() + " (" + sym + ") is reachable from the exported API of a non-internal package",
			})
		})
	}
	ws.eachObject(func(pkg *packages.Package, obj types.Object) {
		if !obj.Exported() || isInternalPath(pkg.PkgPath) {
			return
		}
		sym := pkg.PkgPath + "." + obj.Name()
		switch o := obj.(type) {
		case *types.TypeName:
			if o.IsAlias() {
				return
			}
			inverse(pkg, o.Type().Underlying(), sym)
			if n, ok := o.Type().(*types.Named); ok {
				for _, m := range exportedMethods(n) {
					inverse(pkg, m.Type(), sym+"."+m.Name())
				}
			}
		case *types.Var, *types.Func:
			inverse(pkg, o.Type(), sym)
		}
	})
	for _, st := range ws.surfaceTypes(false, false) {
		if !st.own {
			continue
		}
		origin := st.named.Origin()
		sym := typeSymbol(origin)
		inverse(st.pkg, origin.Underlying(), sym)
		for _, m := range exportedMethods(origin) {
			inverse(st.pkg, m.Type(), sym+"."+m.Name())
		}
	}
	return dedupe(out)
}

var compoundWords = []string{
	"Or", "And", "Then", "Create", "Insert", "Put", "Save", "Set", "Store", "Update", "Upsert", "Add", "Write",
	"Delete", "Remove", "Touch", "Replace", "Swap", "Mark", "Consume", "Revoke", "Rotate", "Reissue", "Persist",
	"Ensure", "Append", "Register", "Bind", "Link", "Assign", "Issue", "Grant", "Start", "Begin", "Commit",
	"Apply", "Push", "Enqueue", "Claim", "Lock", "Acquire", "Extend", "Renew", "Refresh", "Reset", "Clear", "Purge",
	"Expire", "Invalidate", "Increment", "Decrement", "Bump", "Merge", "Attach", "Detach", "Move", "Import", "Restore",
	"Migrate", "Upgrade", "Seal", "Enroll", "Activate", "Deactivate",
}

func isReadMethod(m *types.Func) bool {
	if !readMethod.MatchString(m.Name()) {
		return false
	}
	words := camelWords(m.Name())
	for _, w := range words[1:] {
		if slices.Contains(compoundWords, w) {
			return false
		}
	}
	res := m.Type().(*types.Signature).Results()
	for i := 0; i < res.Len(); i++ {
		if !types.Identical(res.At(i).Type(), types.Universe.Lookup("error").Type()) {
			return true
		}
	}
	return false
}

func camelWords(name string) []string {
	var out []string
	start := 0
	for i := 1; i < len(name); i++ {
		if name[i] >= 'A' && name[i] <= 'Z' && (name[i-1] < 'A' || name[i-1] > 'Z') {
			out = append(out, name[start:i])
			start = i
		}
	}
	return append(out, name[start:])
}

func forbiddenIn(t types.Type, prefix string, seen map[*types.TypeName]bool, report func(*types.Var, string)) {
	switch u := types.Unalias(t).(type) {
	case *types.Struct:
		forbiddenFields(u, prefix, seen, report)
	case *types.Pointer:
		forbiddenIn(u.Elem(), prefix, seen, report)
	case *types.Slice:
		forbiddenIn(u.Elem(), prefix, seen, report)
	case *types.Array:
		forbiddenIn(u.Elem(), prefix, seen, report)
	case *types.Chan:
		forbiddenIn(u.Elem(), prefix, seen, report)
	case *types.Map:
		forbiddenIn(u.Key(), prefix, seen, report)
		forbiddenIn(u.Elem(), prefix, seen, report)
	case *types.Signature:
		for _, tuple := range []*types.Tuple{u.Params(), u.Results()} {
			for i := 0; i < tuple.Len(); i++ {
				forbiddenIn(tuple.At(i).Type(), prefix, seen, report)
			}
		}
	}
}

func valueStruct(cfg Config, n *types.Named) bool {
	p := objPkgPath(n.Obj())
	return p == "time" || p == cfg.uuidPath() || p == cfg.path("principal") || p == cfg.path("store") || p == cfg.path("internal/core")
}

func rawParamOK(cfg Config, t types.Type, hashes *int) bool {
	if namedIs(t, "context", "Context") {
		return true
	}
	if n := derefNamed(t); n != nil && valueStruct(cfg, n) {
		return true
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return true
	case *types.Array:
		_, basic := u.Elem().Underlying().(*types.Basic)
		return basic
	case *types.Pointer:
		return rawParamOK(cfg, u.Elem(), hashes)
	case *types.Slice:
		if b, ok := u.Elem().Underlying().(*types.Basic); ok && b.Kind() == types.Byte && *hashes == 0 {
			*hashes++
			return true
		}
	}
	return false
}

func forbiddenFields(st *types.Struct, prefix string, seen map[*types.TypeName]bool, report func(*types.Var, string)) {
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Embedded() {
			n := derefNamed(f.Type())
			if n == nil {
				continue
			}
			if seen[n.Obj()] {
				continue
			}
			seen[n.Obj()] = true
			if inner, ok := n.Underlying().(*types.Struct); ok {
				forbiddenFields(inner, prefix, seen, report)
			}
			continue
		}
		if slices.Contains(forbiddenRecordFields, f.Name()) {
			report(f, prefix+"."+f.Name())
		}
		if inner := anonStruct(f.Type()); inner != nil {
			forbiddenFields(inner, prefix+"."+f.Name(), seen, report)
		}
	}
}

func anonStruct(t types.Type) *types.Struct {
	for {
		switch u := types.Unalias(t).(type) {
		case *types.Struct:
			return u
		case *types.Pointer:
			t = u.Elem()
		case *types.Slice:
			t = u.Elem()
		case *types.Array:
			t = u.Elem()
		case *types.Map:
			t = u.Elem()
		case *types.Chan:
			t = u.Elem()
		default:
			return nil
		}
	}
}

func recordParams(cfg Config, t types.Type) []*types.Named {
	switch u := types.Unalias(t).(type) {
	case *types.Pointer:
		return recordParams(cfg, u.Elem())
	case *types.Slice:
		return recordParams(cfg, u.Elem())
	case *types.Array:
		return recordParams(cfg, u.Elem())
	case *types.Chan:
		return recordParams(cfg, u.Elem())
	case *types.Map:
		return append(recordParams(cfg, u.Key()), recordParams(cfg, u.Elem())...)
	case *types.Signature:
		var out []*types.Named
		for _, tuple := range []*types.Tuple{u.Params(), u.Results()} {
			for i := 0; i < tuple.Len(); i++ {
				out = append(out, recordParams(cfg, tuple.At(i).Type())...)
			}
		}
		return out
	case *types.Named:
		if u.Obj().Pkg() == nil || valueStruct(cfg, u) {
			return nil
		}
		if _, ok := u.Underlying().(*types.Struct); ok {
			return []*types.Named{u}
		}
	}
	return nil
}

func sealedRecord(cfg Config, n *types.Named, seen map[*types.TypeName]bool) bool {
	if hasSealedField(cfg, n, "") {
		return true
	}
	if seen[n.Obj()] {
		return false
	}
	seen[n.Obj()] = true
	st := n.Underlying().(*types.Struct)
	nested, hashes := 0, 0
	for i := 0; i < st.NumFields(); i++ {
		recs := recordParams(cfg, st.Field(i).Type())
		if len(recs) == 0 && !wrapperFieldOK(cfg, st.Field(i).Type(), &hashes) {
			return false
		}
		for _, inner := range recs {
			nested++
			if !isSealedFree(cfg, inner) && !sealedRecord(cfg, inner, seen) {
				return false
			}
		}
	}
	return nested > 0
}

func wrapperFieldOK(cfg Config, t types.Type, hashes *int) bool {
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	if n := derefNamed(t); n != nil && valueStruct(cfg, n) {
		return true
	}
	var elem types.Type
	switch u := t.Underlying().(type) {
	case *types.Slice:
		elem = u.Elem()
	case *types.Array:
		elem = u.Elem()
	default:
		return false
	}
	if b, ok := elem.Underlying().(*types.Basic); ok && b.Kind() == types.Byte && *hashes == 0 {
		*hashes++
		return true
	}
	return false
}

func isSealedFree(cfg Config, n *types.Named) bool {
	for _, r := range sealedFreeRecords {
		if namedIs(n, cfg.path(r.Rel), r.Name) {
			return true
		}
	}
	return false
}

func hasSealedField(cfg Config, n *types.Named, name string) bool {
	st, ok := n.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if name != "" && f.Name() != name {
			continue
		}
		if t, ok := types.Unalias(f.Type()).(*types.Named); ok && t.Obj().Name() == "Sealed" && t.Obj().Pkg() != nil {
			if p := t.Obj().Pkg().Path(); p == cfg.path("principal") || p == cfg.path("internal/core") {
				return true
			}
		}
	}
	return false
}
