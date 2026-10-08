package archtest

import (
	"go/token"
	"go/types"

	"golang.org/x/tools/go/packages"
)

// G01 forbids public handler-shaped API outside the route builders.
const G01 GuardID = "G01"

// CheckG01 rejects any exported func, method, func type, interface or package var outside
// internal/ that returns or holds a handler or a middleware, hands one to the caller through a
// parameter (an out-param such as *http.Handler, a callback such as func(http.Handler), an
// integrator-implemented interface whose methods receive one), or takes both an
// http.ResponseWriter and an *http.Request in any order or position. A handler is http.Handler,
// http.HandlerFunc, any func taking those two, named or not, or any type whose method set (or its
// pointer's) has ServeHTTP, so unexported and anonymous handler types count. Handlers are found
// through pointers, slices, arrays, maps, channels, anonymous structs, anonymous interfaces and
// funcs, following the direction in which values flow. Methods and exported fields of every named
// type reachable from that exported API are checked too, whether or not the type is exported or
// internal, including generic instances such as Box[http.Handler] or atomic.Pointer[http.Handler]
// (the latter reported at the exported symbol that exposes it); exported fields and vars are
// checked in both directions since the integrator can read and assign them, and promoted methods
// count as the embedding type's own. Exported fields and methods of types from outside the workspace
// are followed too (an *http.Server hands out a settable Handler), unless the type is a handler
// itself, which the exposing signature already answers for. Methods of Routes, APIRoutes and
// PrincipalHandler in the root package are the only exceptions. Package main is skipped: its exports
// cannot be imported.
func CheckG01(ws *Workspace, cfg Config) []Violation {
	var out []Violation
	report := func(pkgPath, pos, sym, msg string) {
		out = append(out, Violation{Guard: G01, Pkg: pkgPath, Pos: pos, Symbols: []string{sym}, Msg: msg})
	}
	ws.eachObject(func(pkg *packages.Package, obj types.Object) {
		if isInternalPath(pkg.PkgPath) || !obj.Exported() {
			return
		}
		switch o := obj.(type) {
		case *types.Func:
			if why := handlerShape(o.Type().(*types.Signature)); why != "" {
				report(pkg.PkgPath, ws.relPos(pkg.Fset, o.Pos()), funcSymbol(o), "exported func "+o.Name()+" "+why)
			}
		case *types.Var:
			if holdsHandler(o.Type()) {
				report(pkg.PkgPath, ws.relPos(pkg.Fset, o.Pos()), pkg.PkgPath+"."+o.Name(), "exported var "+o.Name()+" is or holds a handler or middleware")
			}
		}
	})
	reportAt := func(st surfaceType, pos token.Pos, member, msg string) {
		v := ws.locate(st, pos, member)
		v.Guard, v.Msg = G01, msg
		out = append(out, v)
	}
	for _, st := range ws.surfaceTypes(false, true) {
		named, obj := st.named, st.named.Obj()
		if isG01ExemptType(cfg, named) {
			continue
		}
		label := st.label()
		switch u := named.Underlying().(type) {
		case *types.Signature:
			if why := handlerShape(u); why != "" && obj.Exported() {
				reportAt(st, obj.Pos(), "", "exported type "+label+" "+why)
			}
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if f.Exported() && holdsHandler(f.Type()) {
					reportAt(st, f.Pos(), f.Name(), "exported field "+label+"."+f.Name()+" holds a handler or middleware")
				}
			}
		case *types.Interface:
		default:
			if exposesHandler(u, map[polarType]bool{}) {
				reportAt(st, obj.Pos(), "", "type "+label+" holds a handler or middleware")
			}
		}
		for _, m := range exportedMethods(named) {
			if m.Pkg() == obj.Pkg() && posInTestFile(st.pkg.Fset, m.Pos()) {
				continue
			}
			why := handlerShape(m.Type().(*types.Signature))
			if why == "" {
				continue
			}
			pos := m.Pos()
			if m.Pkg() != obj.Pkg() || !pos.IsValid() {
				pos = obj.Pos()
			}
			reportAt(st, pos, m.Name(), "exported method "+label+"."+m.Name()+" "+why)
		}
	}
	return dedupe(out)
}

func exportedMethods(named *types.Named) []*types.Func {
	var out []*types.Func
	if iface, ok := named.Underlying().(*types.Interface); ok {
		for i := 0; i < iface.NumMethods(); i++ {
			if m := iface.Method(i); m.Exported() {
				out = append(out, m)
			}
		}
		return out
	}
	ms := types.NewMethodSet(types.NewPointer(named))
	for i := 0; i < ms.Len(); i++ {
		if m, ok := ms.At(i).Obj().(*types.Func); ok && m.Exported() {
			out = append(out, m)
		}
	}
	return out
}

func isG01ExemptType(cfg Config, n *types.Named) bool {
	o := n.Obj()
	if o.Pkg() == nil || o.Pkg().Path() != cfg.Root {
		return false
	}
	switch o.Name() {
	case "Routes", "APIRoutes", "PrincipalHandler":
		return true
	}
	return false
}

type polarType struct {
	t  types.Type
	in bool
}

func handlerShape(sig *types.Signature) string {
	res := sig.Results()
	for i := 0; i < res.Len(); i++ {
		if exposesHandler(res.At(i).Type(), map[polarType]bool{}) {
			return "returns a handler or middleware"
		}
	}
	if takesWR(sig) {
		return "takes (http.ResponseWriter, *http.Request)"
	}
	params := sig.Params()
	for i := 0; i < params.Len(); i++ {
		if receivesHandler(params.At(i).Type(), map[polarType]bool{}) {
			return "hands a handler or middleware to the caller through parameter " + params.At(i).Name()
		}
	}
	return ""
}

func holdsHandler(t types.Type) bool {
	return holdsHandlerSeen(t, map[polarType]bool{})
}

func holdsHandlerSeen(t types.Type, seen map[polarType]bool) bool {
	return exposesHandler(t, seen) || receivesHandler(t, seen)
}

func takesWR(sig *types.Signature) bool {
	p := sig.Params()
	writer, request := false, false
	for i := 0; i < p.Len(); i++ {
		t := p.At(i).Type()
		writer = writer || namedIs(t, "net/http", "ResponseWriter")
		request = request || isRequestPtr(t)
	}
	return writer && request
}

func exposesHandler(t types.Type, seen map[polarType]bool) bool {
	if isHandlerType(t) {
		return true
	}
	key := polarType{t: t}
	if seen[key] {
		return false
	}
	seen[key] = true
	switch u := types.Unalias(t).(type) {
	case *types.Named:
		if sig, ok := u.Underlying().(*types.Signature); ok {
			return exposesHandler(sig, seen)
		}
	case *types.Pointer:
		return holdsHandlerSeen(u.Elem(), seen)
	case *types.Slice:
		return holdsHandlerSeen(u.Elem(), seen)
	case *types.Array:
		return exposesHandler(u.Elem(), seen)
	case *types.Chan:
		return holdsHandlerSeen(u.Elem(), seen)
	case *types.Map:
		return holdsHandlerSeen(u.Key(), seen) || holdsHandlerSeen(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if f := u.Field(i); f.Exported() && exposesHandler(f.Type(), seen) {
				return true
			}
		}
	case *types.Interface:
		for i := 0; i < u.NumMethods(); i++ {
			if m := u.Method(i); m.Exported() && exposesHandler(m.Type(), seen) {
				return true
			}
		}
	case *types.Signature:
		if takesWR(u) {
			return true
		}
		res := u.Results()
		for i := 0; i < res.Len(); i++ {
			if exposesHandler(res.At(i).Type(), seen) {
				return true
			}
		}
		params := u.Params()
		for i := 0; i < params.Len(); i++ {
			if receivesHandler(params.At(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func receivesHandler(t types.Type, seen map[polarType]bool) bool {
	if isHandlerValue(t) {
		return false
	}
	key := polarType{t: t, in: true}
	if seen[key] {
		return false
	}
	seen[key] = true
	switch u := types.Unalias(t).(type) {
	case *types.Named:
		switch under := u.Underlying().(type) {
		case *types.Signature:
			return receivesHandler(under, seen)
		case *types.Interface:
			return receivesHandler(under, seen)
		}
	case *types.Pointer:
		return holdsHandlerSeen(u.Elem(), seen)
	case *types.Slice:
		return holdsHandlerSeen(u.Elem(), seen)
	case *types.Array:
		return receivesHandler(u.Elem(), seen)
	case *types.Chan:
		return holdsHandlerSeen(u.Elem(), seen)
	case *types.Map:
		return holdsHandlerSeen(u.Key(), seen) || holdsHandlerSeen(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if f := u.Field(i); f.Exported() && receivesHandler(f.Type(), seen) {
				return true
			}
		}
	case *types.Interface:
		for i := 0; i < u.NumMethods(); i++ {
			if m := u.Method(i); m.Exported() && receivesHandler(m.Type(), seen) {
				return true
			}
		}
	case *types.Signature:
		params := u.Params()
		for i := 0; i < params.Len(); i++ {
			if exposesHandler(params.At(i).Type(), seen) {
				return true
			}
		}
		res := u.Results()
		for i := 0; i < res.Len(); i++ {
			if receivesHandler(res.At(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func isRequestPtr(t types.Type) bool {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	return ok && namedIs(ptr.Elem(), "net/http", "Request")
}

func isHandlerType(t types.Type) bool {
	if isHandlerValue(t) {
		return true
	}
	sig, ok := t.Underlying().(*types.Signature)
	if !ok || sig.Params().Len() != 1 || sig.Results().Len() != 1 {
		return false
	}
	return isHandlerValue(sig.Params().At(0).Type()) && isHandlerValue(sig.Results().At(0).Type())
}

func isHandlerValue(t types.Type) bool {
	if namedIs(t, "net/http", "Handler") || namedIs(t, "net/http", "HandlerFunc") {
		return true
	}
	if sig, ok := t.Underlying().(*types.Signature); ok && takesWR(sig) {
		return true
	}
	if servesHTTP(types.NewMethodSet(t)) {
		return true
	}
	if _, isPtr := t.Underlying().(*types.Pointer); isPtr || types.IsInterface(t) {
		return false
	}
	return servesHTTP(types.NewMethodSet(types.NewPointer(t)))
}

func servesHTTP(ms *types.MethodSet) bool {
	sel := ms.Lookup(nil, "ServeHTTP")
	if sel == nil {
		return false
	}
	sig, ok := sel.Type().(*types.Signature)
	if !ok || sig.Results().Len() != 0 || sig.Params().Len() != 2 {
		return false
	}
	return namedIs(sig.Params().At(0).Type(), "net/http", "ResponseWriter") && isRequestPtr(sig.Params().At(1).Type())
}
