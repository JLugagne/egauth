package archtest

import (
	"go/token"
	"go/types"

	"golang.org/x/tools/go/packages"
)

// G03 forbids adjacent parameters or results of the same confusable type.
const G03 GuardID = "G03"

// CheckG03 rejects two adjacent parameters, or two results anywhere in the tuple, of an identical
// type among string, integer kinds, uuid.UUID, []byte, byte arrays and principal.TenantID (defined
// types whose underlying type is a string, an integer, []byte or a byte array included), or of the same type parameter whose
// constraint admits one of them. It inspects the signatures of exported funcs, exported methods of
// every named type reachable from the exported API (unexported and internal types included), every
// interface method, exported named func types and aliases, exported fields of reachable structs,
// and exported package vars. Func types are followed through unexported names, aliases, pointers,
// slices, arrays, maps, channels, anonymous structs and anonymous interfaces, and through the
// params and results of the signatures above. Generic instances reachable from the exported API,
// such as Fn[string] or atomic.Pointer[uuid.UUID], are checked with their type arguments
// substituted; instances of generics from outside the workspace are reported at the exported
// symbol that exposes them. Package main is skipped: its exports cannot be imported.
func CheckG03(ws *Workspace, cfg Config) []Violation {
	var out []Violation
	var check func(at Violation, sig *types.Signature)
	checkType := func(at Violation, t types.Type) {
		for _, sig := range nestedSignatures(t) {
			check(at, sig)
		}
	}
	active := map[*types.Signature]bool{}
	check = func(at Violation, sig *types.Signature) {
		if active[sig] {
			return
		}
		active[sig] = true
		defer delete(active, sig)
		report := func(kind string, a, b *types.Var) {
			v := at
			v.Guard, v.Msg = G03, kind+" "+a.Name()+" and "+b.Name()+" share type "+a.Type().String()
			out = append(out, v)
		}
		params := sig.Params()
		for i := 0; i+1 < params.Len(); i++ {
			a, b := params.At(i), params.At(i+1)
			if confusable(cfg, a.Type()) && types.Identical(a.Type(), b.Type()) {
				report("adjacent parameters", a, b)
			}
		}
		results := sig.Results()
		for i := 0; i < results.Len(); i++ {
			for j := i + 1; j < results.Len(); j++ {
				a, b := results.At(i), results.At(j)
				if confusable(cfg, a.Type()) && types.Identical(a.Type(), b.Type()) {
					report("results", a, b)
				}
			}
		}
		for _, tuple := range []*types.Tuple{params, results} {
			for i := 0; i < tuple.Len(); i++ {
				checkType(at, tuple.At(i).Type())
			}
		}
	}
	direct := func(pkg *packages.Package, pos token.Pos, sym string) Violation {
		return Violation{Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, pos), Symbols: []string{sym}}
	}
	ws.eachObject(func(pkg *packages.Package, obj types.Object) {
		switch o := obj.(type) {
		case *types.Func:
			if o.Exported() {
				check(direct(pkg, o.Pos(), funcSymbol(o)), o.Type().(*types.Signature))
			}
		case *types.Var:
			if o.Exported() {
				checkType(direct(pkg, o.Pos(), pkg.PkgPath+"."+o.Name()), o.Type())
			}
		case *types.TypeName:
			if o.IsAlias() {
				if o.Exported() {
					checkType(direct(pkg, o.Pos(), pkg.PkgPath+"."+o.Name()), types.Unalias(o.Type()))
				}
				return
			}
			named, ok := o.Type().(*types.Named)
			if !ok {
				return
			}
			if iface, ok := named.Underlying().(*types.Interface); ok {
				for i := 0; i < iface.NumExplicitMethods(); i++ {
					m := iface.ExplicitMethod(i)
					check(direct(pkg, m.Pos(), typeSymbol(named)+"."+m.Name()), m.Type().(*types.Signature))
				}
			}
			if sig, ok := named.Underlying().(*types.Signature); ok && o.Exported() {
				check(direct(pkg, o.Pos(), typeSymbol(named)), sig)
			}
		}
	})
	for _, st := range ws.surfaceTypes(true, false) {
		named := st.named
		instance := named != named.Origin()
		switch u := named.Underlying().(type) {
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if f := u.Field(i); f.Exported() && !f.Embedded() {
					checkType(ws.locate(st, f.Pos(), f.Name()), f.Type())
				}
			}
		case *types.Signature:
			if instance {
				check(ws.locate(st, named.Obj().Pos(), ""), u)
			}
		case *types.Interface:
			if instance {
				for i := 0; i < u.NumMethods(); i++ {
					if m := u.Method(i); m.Exported() {
						check(ws.locate(st, m.Pos(), m.Name()), m.Type().(*types.Signature))
					}
				}
			}
			continue
		}
		for i := 0; i < named.NumMethods(); i++ {
			m := named.Method(i)
			if m.Exported() && !posInTestFile(st.pkg.Fset, m.Pos()) {
				check(ws.locate(st, m.Pos(), m.Name()), m.Type().(*types.Signature))
			}
		}
	}
	return dedupe(out)
}

func nestedSignatures(t types.Type) []*types.Signature {
	var out []*types.Signature
	seen := map[types.Type]bool{}
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if seen[t] {
			return
		}
		seen[t] = true
		switch u := t.(type) {
		case *types.Alias:
			walk(types.Unalias(u))
		case *types.Named:
			if sig, ok := u.Underlying().(*types.Signature); ok && !u.Obj().Exported() {
				out = append(out, sig)
			}
		case *types.Signature:
			out = append(out, u)
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Chan:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if f := u.Field(i); f.Exported() {
					walk(f.Type())
				}
			}
		case *types.Interface:
			for i := 0; i < u.NumMethods(); i++ {
				if m := u.Method(i); m.Exported() {
					walk(m.Type())
				}
			}
		}
	}
	walk(t)
	return out
}

func confusable(cfg Config, t types.Type) bool {
	t = types.Unalias(t)
	switch u := t.(type) {
	case *types.TypeParam:
		return constraintConfusable(cfg, u.Constraint(), map[types.Type]bool{})
	case *types.Basic:
		return u.Info()&(types.IsString|types.IsInteger) != 0 && u.Info()&types.IsUntyped == 0
	case *types.Slice:
		return isByte(u.Elem())
	case *types.Array:
		return isByte(u.Elem())
	case *types.Named:
		o := u.Obj()
		if o.Pkg() != nil && o.Pkg().Path() == cfg.uuidPath() && o.Name() == "UUID" {
			return true
		}
		if o.Pkg() != nil && o.Name() == "TenantID" {
			if p := o.Pkg().Path(); p == cfg.path("principal") || p == cfg.path("internal/core") {
				return true
			}
		}
		switch under := u.Underlying().(type) {
		case *types.Basic:
			return under.Info()&(types.IsString|types.IsInteger) != 0
		case *types.Slice:
			return isByte(under.Elem())
		case *types.Array:
			return isByte(under.Elem())
		}
	}
	return false
}

func isByte(t types.Type) bool {
	b, ok := types.Unalias(t).(*types.Basic)
	return ok && b.Kind() == types.Byte
}

func constraintConfusable(cfg Config, c types.Type, seen map[types.Type]bool) bool {
	if seen[c] {
		return false
	}
	seen[c] = true
	iface, ok := c.Underlying().(*types.Interface)
	if !ok {
		return confusable(cfg, c)
	}
	for i := 0; i < iface.NumEmbeddeds(); i++ {
		e := iface.EmbeddedType(i)
		u, ok := types.Unalias(e).(*types.Union)
		if !ok {
			if constraintConfusable(cfg, e, seen) {
				return true
			}
			continue
		}
		for j := 0; j < u.Len(); j++ {
			if constraintConfusable(cfg, u.Term(j).Type(), seen) {
				return true
			}
		}
	}
	return false
}
