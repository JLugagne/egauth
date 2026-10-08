package archtest

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/packages"
)

// G14 forbids capability sniffing through interface type assertions.
const G14 GuardID = "G14"

// CheckG14 rejects, in non-test code, type assertions and type-switch cases whose target is an
// interface type, and errors.As calls whose target is a pointer to an interface type. An
// instantiation of a generic func or type with an interface type argument counts as such an
// assertion when the generic asserts to that type parameter, directly or through another generic;
// errors.AsType counts as errors.As. The candidate exemption symbols are the interface type and, for
// errors.As, "errors.As".
func CheckG14(ws *Workspace, _ Config) []Violation {
	var out []Violation
	generic := genericAssertions(ws)
	ws.eachFile(false, func(pkg *packages.Package, file *ast.File, _ string) {
		info := pkg.TypesInfo
		report := func(pos ast.Node, t types.Type, extra, via string) {
			syms := []string{enclosingSymbol(pkg, file, pos.Pos())}
			if extra != "" {
				syms = append(syms, extra)
			}
			if n, ok := types.Unalias(t).(*types.Named); ok {
				syms = append(syms, typeSymbol(n))
			}
			out = append(out, Violation{Guard: G14, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, pos.Pos()), Symbols: syms, Msg: "interface type assertion to " + t.String() + via})
		}
		ast.Inspect(file, func(n ast.Node) bool {
			for _, a := range assertionTargets(info, n) {
				if isInterfaceTarget(a.target) {
					report(a.node, a.target, a.kind, "")
				}
			}
			return true
		})
		for _, id := range fileInstanceIdents(info, file) {
			owner := instanceOwner(info, id)
			args := info.Instances[id].TypeArgs
			for i := 0; i < args.Len(); i++ {
				kind, ok := generic[typeParamSite{owner: owner, index: i}]
				if ok && isInterfaceTarget(args.At(i)) {
					report(id, args.At(i), kind, " through generic "+owner)
				}
			}
		}
	})
	return dedupe(out)
}

func isInterfaceTarget(t types.Type) bool {
	if t == nil {
		return false
	}
	if _, ok := types.Unalias(t).(*types.TypeParam); ok {
		return false
	}
	_, ok := t.Underlying().(*types.Interface)
	return ok
}

func isErrorsAs(info *types.Info, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "errors" && fn.Name() == "As"
}
