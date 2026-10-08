package archtest

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/packages"
)

// G10 keeps audit attribute keys inside the closed, classified registry.
const G10 GuardID = "G10"

func init() { RegisterList(G10Exemptions()) }

const maxG10Entries = LegacyPrefixCount

var g10Exemptions = LegacyExemptions(G10)

// G10Exemptions returns the exemptions that the workspace test filters CheckG10 findings with.
func G10Exemptions() ExemptionList {
	return ExemptionList{Guard: G10, MaxEntries: maxG10Entries, Entries: g10Exemptions}
}

// CheckG10 rejects, in non-test code of every package: a constant expression of type event.AttrKey
// that is not a declared constant of the event package (a literal or converted key, wherever it is
// built: a variable, a composite literal, a map key or a comparison), a conversion of a non-constant
// value to event.AttrKey outside package event (a generic function or type instantiated with
// event.AttrKey for a type parameter whose constraint only admits string-convertible types counts
// as one), and a plain string constant passed straight to internal/audit.Emit. The constant
// declarations of package event are the registry itself. It also reports every constant of
// event.AttrKey that the Sensitivity method of the type does not classify in an explicit case. Constants of other named types, such as event.Type, are not attribute keys.
func CheckG10(ws *Workspace, cfg Config) []Violation {
	var out []Violation
	eventPath := cfg.path("event")
	if pkg := ws.Package(eventPath); pkg != nil && pkg.Types != nil {
		out = append(out, unclassifiedAttrKeys(ws, pkg)...)
	}
	auditPath := cfg.path("internal/audit")
	ws.eachFile(false, func(pkg *packages.Package, file *ast.File, _ string) {
		info := pkg.TypesInfo
		report := func(e ast.Expr, msg string) {
			out = append(out, Violation{
				Guard: G10, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, e.Pos()), Symbols: []string{enclosingSymbol(pkg, file, e.Pos())},
				Msg: msg,
			})
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if gd, ok := n.(*ast.GenDecl); ok && gd.Tok == token.CONST && pkg.PkgPath == eventPath {
				return false
			}
			if call, ok := n.(*ast.CallExpr); ok && callsFunc(info, call, auditPath, "Emit") {
				for _, arg := range call.Args {
					if plainStringKey(info, arg, eventPath) {
						report(arg, "audit.Emit takes a literal attribute key; declare an event.AttrKey constant with a Sensitivity")
					}
				}
			}
			if id, ok := n.(*ast.Ident); ok && pkg.PkgPath != eventPath && genericAttrKeyConversion(info, id, eventPath) {
				report(id, "generic conversion to event.AttrKey through "+id.Name+" bypasses the registry")
			}
			x, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			tv, ok := info.Types[x]
			if !ok || tv.IsType() || !namedIs(tv.Type, eventPath, "AttrKey") {
				return true
			}
			if declaredAttrConst(info, x, eventPath) != nil {
				return false
			}
			if tv.Value != nil {
				report(x, "literal event.AttrKey outside the registry; declare an event.AttrKey constant with a Sensitivity")
				return false
			}
			if pkg.PkgPath != eventPath && isConversion(info, x) {
				report(x, "runtime conversion to event.AttrKey bypasses the registry")
				return false
			}
			return true
		})
	})
	return dedupe(out)
}

func genericAttrKeyConversion(info *types.Info, id *ast.Ident, eventPath string) bool {
	inst, ok := info.Instances[id]
	if !ok {
		return false
	}
	var tparams *types.TypeParamList
	switch o := info.Uses[id].(type) {
	case *types.Func:
		if sig, ok := o.Type().(*types.Signature); ok {
			tparams = sig.TypeParams()
		}
	case *types.TypeName:
		if n, ok := o.Type().(*types.Named); ok {
			tparams = n.TypeParams()
		}
	}
	if tparams == nil {
		return false
	}
	for i := 0; i < tparams.Len() && i < inst.TypeArgs.Len(); i++ {
		if namedIs(inst.TypeArgs.At(i), eventPath, "AttrKey") && convertsFromString(tparams.At(i).Constraint(), map[types.Type]bool{}) {
			return true
		}
	}
	return false
}

func convertsFromString(constraint types.Type, seen map[types.Type]bool) bool {
	if seen[constraint] {
		return false
	}
	seen[constraint] = true
	it, ok := constraint.Underlying().(*types.Interface)
	if !ok {
		return stringLike(constraint)
	}
	for i := 0; i < it.NumEmbeddeds(); i++ {
		switch e := it.EmbeddedType(i).(type) {
		case *types.Union:
			all := e.Len() > 0
			for j := 0; j < e.Len(); j++ {
				all = all && stringLike(e.Term(j).Type())
			}
			if all {
				return true
			}
		default:
			if convertsFromString(e, seen) {
				return true
			}
		}
	}
	return false
}

func stringLike(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Info()&types.IsString != 0
	case *types.Slice:
		b, ok := u.Elem().Underlying().(*types.Basic)
		return ok && (b.Kind() == types.Byte || b.Kind() == types.Rune)
	}
	return false
}

func isConversion(info *types.Info, e ast.Expr) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	tv, ok := info.Types[call.Fun]
	return ok && tv.IsType()
}

func plainStringKey(info *types.Info, arg ast.Expr, eventPath string) bool {
	tv, ok := info.Types[arg]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	if _, named := types.Unalias(tv.Type).(*types.Named); named {
		return false
	}
	if call, ok := ast.Unparen(arg).(*ast.CallExpr); ok && isConversion(info, call) && declaredAttrConst(info, ast.Unparen(call.Args[0]), eventPath) != nil {
		return false
	}
	return true
}

func callsFunc(info *types.Info, call *ast.CallExpr, pkgPath, name string) bool {
	var id *ast.Ident
	switch f := call.Fun.(type) {
	case *ast.Ident:
		id = f
	case *ast.SelectorExpr:
		id = f.Sel
	default:
		return false
	}
	fn, ok := info.Uses[id].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == pkgPath && fn.Name() == name
}

func declaredAttrConst(info *types.Info, e ast.Expr, eventPath string) *types.Const {
	var id *ast.Ident
	switch x := e.(type) {
	case *ast.Ident:
		id = x
	case *ast.SelectorExpr:
		id = x.Sel
	default:
		return nil
	}
	c, ok := info.Uses[id].(*types.Const)
	if !ok || c.Pkg() == nil || c.Pkg().Path() != eventPath || !namedIs(c.Type(), eventPath, "AttrKey") {
		return nil
	}
	return c
}

func unclassifiedAttrKeys(ws *Workspace, pkg *packages.Package) []Violation {
	scope := pkg.Types.Scope()
	keyType, ok := scope.Lookup("AttrKey").(*types.TypeName)
	if !ok {
		return nil
	}
	declared := map[types.Object]bool{}
	for _, f := range pkg.Syntax {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name.Name != "Sensitivity" || fd.Body == nil {
				continue
			}
			if o, ok := pkg.TypesInfo.Defs[fd.Name].(*types.Func); !ok || recvNamed(o) == nil || recvNamed(o).Obj() != keyType {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				cc, ok := n.(*ast.CaseClause)
				if !ok {
					return true
				}
				for _, e := range cc.List {
					ast.Inspect(e, func(m ast.Node) bool {
						if id, ok := m.(*ast.Ident); ok {
							if c, ok := pkg.TypesInfo.Uses[id].(*types.Const); ok {
								declared[c] = true
							}
						}
						return true
					})
				}
				return true
			})
		}
	}
	var out []Violation
	for _, name := range scope.Names() {
		c, ok := scope.Lookup(name).(*types.Const)
		if !ok || posInTestFile(pkg.Fset, c.Pos()) || !namedIs(c.Type(), pkg.PkgPath, "AttrKey") || declared[c] {
			continue
		}
		out = append(out, Violation{
			Guard: G10, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, c.Pos()), Symbols: []string{pkg.PkgPath + "." + c.Name()},
			Msg: "attribute key " + c.Name() + " has no declared Sensitivity",
		})
	}
	return out
}
