package archtest

import (
	"go/types"
	"regexp"
	"slices"

	"golang.org/x/tools/go/packages"
)

// G02 forbids functional options and sealed variadic option interfaces.
const G02 GuardID = "G02"

var optionConstructorName = regexp.MustCompile(`^(Require|Accept)`)

// CheckG02 rejects the functional-options pattern and sealed variadic option interfaces, in
// internal packages too. Option types are named types or aliases whose underlying type is func(*T)
// or func(*T) error: exported ones are always rejected, unexported ones once an exported func accepts
// them variadically or returns them. Structs holding such a func (exported field or not) are option
// types too once an exported func accepts them, or pointers to them, variadically. Sealed option
// types are interfaces with only unexported methods accepted variadically by an exported func,
// whether exported or not, except RouteOption and APIRouteOption of the root package; interfaces
// whose every method has the func(*T) or func(*T) error shape are option types on the same terms,
// even when their methods are exported. An exported
// func taking a variadic unnamed func(*T) is rejected itself. Every exported func returning an
// option type, a sealed option type, a concrete type whose value or pointer implements a sealed
// option type (such as ClaimRequirement), or a variadically accepted unnamed func(*T), or a slice,
// array or pointer of them, must be named Require* or Accept*. Package main is skipped: its exports
// cannot be imported.
func CheckG02(ws *Workspace, cfg Config) []Violation {
	var out []Violation
	optionTypes := map[string]bool{}
	flagged := map[string]bool{}
	var unnamedShapes []types.Type
	var sealed []*types.Interface
	flagType := func(pkg *packages.Package, obj types.Object, key, msg string) {
		if flagged[key] {
			return
		}
		flagged[key] = true
		out = append(out, Violation{Guard: G02, Pkg: objPkgPath(obj), Pos: ws.relPos(pkg.Fset, obj.Pos()), Symbols: []string{key}, Msg: msg})
	}

	ws.eachObject(func(pkg *packages.Package, obj types.Object) {
		tn, ok := obj.(*types.TypeName)
		if !ok || !tn.Exported() || !isOptionShape(tn.Type()) {
			return
		}
		key := optionKey(tn.Type())
		optionTypes[key] = true
		flagType(pkg, tn, key, "exported functional option type "+tn.Name())
	})

	eachExportedFunc(ws, true, func(pkg *packages.Package, fn *types.Func) {
		sig := fn.Type().(*types.Signature)
		if !sig.Variadic() || sig.Params().Len() == 0 {
			return
		}
		elem := sig.Params().At(sig.Params().Len() - 1).Type().(*types.Slice).Elem()
		base := elem
		if p, ok := types.Unalias(elem).(*types.Pointer); ok {
			base = p.Elem()
		}
		key := optionKey(elem)
		switch {
		case key == "" && isOptionShape(elem):
			unnamedShapes = append(unnamedShapes, elem)
			out = append(out, Violation{Guard: G02, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, fn.Pos()), Symbols: []string{funcSymbol(fn)}, Msg: "func " + fn.Name() + " accepts functional options variadically"})
		case key != "" && isOptionShape(elem):
			optionTypes[key] = true
			flagType(pkg, optionObj(elem), key, "functional option type "+optionObj(elem).Name()+" accepted variadically")
		case key != "" && isSealedOption(elem):
			optionTypes[key] = true
			sealed = append(sealed, types.Unalias(elem).Underlying().(*types.Interface))
			if n, ok := elem.(*types.Named); !ok || !isG02ExemptType(cfg, n) {
				flagType(pkg, optionObj(elem), key, "sealed interface "+optionObj(elem).Name()+" accepted variadically")
			}
		case key != "" && isOptionInterface(elem):
			optionTypes[key] = true
			sealed = append(sealed, types.Unalias(elem).Underlying().(*types.Interface))
			if n, ok := elem.(*types.Named); !ok || !isG02ExemptType(cfg, n) {
				flagType(pkg, optionObj(elem), key, "option interface "+optionObj(elem).Name()+" accepted variadically")
			}
		case optionKey(base) != "" && isWrappedOption(base):
			optionTypes[optionKey(base)] = true
			flagType(pkg, optionObj(base), optionKey(base), "struct-wrapped functional option type "+optionObj(base).Name()+" accepted variadically")
		}
	})

	eachExportedFunc(ws, true, func(pkg *packages.Package, fn *types.Func) {
		res := fn.Type().(*types.Signature).Results()
		for i := 0; i < res.Len(); i++ {
			carrier, ok := optionCarrier(res.At(i).Type())
			if !ok || optionConstructorName.MatchString(fn.Name()) {
				continue
			}
			key := optionKey(carrier)
			isOption := optionTypes[key]
			if !isOption && key != "" && isOptionShape(carrier) {
				isOption = true
				flagType(pkg, optionObj(carrier), key, "functional option type "+optionObj(carrier).Name()+" returned by an exported func")
			}
			if !isOption && key == "" {
				isOption = slices.ContainsFunc(unnamedShapes, func(s types.Type) bool { return types.Identical(s, carrier) })
			}
			if !isOption && key != "" {
				isOption = implementsSealed(carrier, sealed)
			}
			if !isOption {
				continue
			}
			out = append(out, Violation{Guard: G02, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, fn.Pos()), Symbols: []string{funcSymbol(fn)}, Msg: "func " + fn.Name() + " returns option type " + carrier.String() + " but is not named Require* or Accept*"})
		}
	})
	return dedupe(out)
}

func implementsSealed(t types.Type, sealed []*types.Interface) bool {
	if types.IsInterface(t) {
		return false
	}
	return slices.ContainsFunc(sealed, func(iface *types.Interface) bool {
		return types.Implements(t, iface) || types.Implements(types.NewPointer(t), iface)
	})
}

func isWrappedOption(t types.Type) bool {
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		if isOptionShape(st.Field(i).Type()) {
			return true
		}
	}
	return false
}

func optionCarrier(t types.Type) (types.Type, bool) {
	for {
		switch u := t.(type) {
		case *types.Slice:
			t = u.Elem()
		case *types.Array:
			t = u.Elem()
		case *types.Pointer:
			t = u.Elem()
		case *types.Alias, *types.Named:
			return u, true
		case *types.Signature:
			return u, isFuncOption(u)
		default:
			return nil, false
		}
	}
}

func optionObj(t types.Type) *types.TypeName {
	switch u := t.(type) {
	case *types.Alias:
		return u.Obj()
	case *types.Named:
		return u.Origin().Obj()
	}
	return nil
}

func optionKey(t types.Type) string {
	obj := optionObj(t)
	if obj == nil {
		return ""
	}
	if obj.Pkg() == nil {
		return obj.Name()
	}
	return obj.Pkg().Path() + "." + obj.Name()
}

func isOptionShape(t types.Type) bool {
	sig, ok := t.Underlying().(*types.Signature)
	return ok && isFuncOption(sig)
}

func isSealedOption(t types.Type) bool {
	n, ok := types.Unalias(t).(*types.Named)
	return ok && isSealedInterface(n)
}

func isG02ExemptType(cfg Config, n *types.Named) bool {
	o := n.Obj()
	return o.Pkg() != nil && o.Pkg().Path() == cfg.Root && (o.Name() == "RouteOption" || o.Name() == "APIRouteOption")
}

func isFuncOption(sig *types.Signature) bool {
	return sig.Recv() == nil && isOptionSignature(sig)
}

func isOptionSignature(sig *types.Signature) bool {
	if sig.Params().Len() != 1 {
		return false
	}
	if _, ok := types.Unalias(sig.Params().At(0).Type()).(*types.Pointer); !ok {
		return false
	}
	switch sig.Results().Len() {
	case 0:
		return true
	case 1:
		return types.Identical(sig.Results().At(0).Type(), types.Universe.Lookup("error").Type())
	}
	return false
}

func isOptionInterface(t types.Type) bool {
	n, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return false
	}
	iface, ok := n.Underlying().(*types.Interface)
	if !ok || iface.NumMethods() == 0 {
		return false
	}
	for i := 0; i < iface.NumMethods(); i++ {
		if !isOptionSignature(iface.Method(i).Type().(*types.Signature)) {
			return false
		}
	}
	return true
}

func isSealedInterface(n *types.Named) bool {
	iface, ok := n.Underlying().(*types.Interface)
	if !ok || iface.NumMethods() == 0 {
		return false
	}
	for i := 0; i < iface.NumMethods(); i++ {
		if iface.Method(i).Exported() {
			return false
		}
	}
	return true
}

func eachExportedFunc(ws *Workspace, includeInternal bool, fn func(pkg *packages.Package, f *types.Func)) {
	ws.eachObject(func(pkg *packages.Package, obj types.Object) {
		if !includeInternal && isInternalPath(pkg.PkgPath) {
			return
		}
		switch o := obj.(type) {
		case *types.Func:
			if o.Exported() {
				fn(pkg, o)
			}
		case *types.TypeName:
			named, ok := types.Unalias(o.Type()).(*types.Named)
			if !ok || !o.Exported() {
				return
			}
			for i := 0; i < named.NumMethods(); i++ {
				m := named.Method(i)
				if m.Exported() && !posInTestFile(pkg.Fset, m.Pos()) {
					fn(pkg, m)
				}
			}
		}
	})
}
