package archtest

import (
	"go/ast"
	"go/types"
	"slices"

	"golang.org/x/tools/go/packages"
)

// G09 keeps the event.Type catalogue honest: every type is emitted or explicitly reserved, and
// Type.Severity classifies every type.
const G09 GuardID = "G09"

func init() { RegisterList(G09Exemptions()) }

const maxG09Entries = 0

var g09Exemptions []Exemption

// G09Exemptions returns the reserved event types: constants kept in the catalogue although nothing
// emits them yet. The list is empty; an entry names "<event path>.<Constant>".
func G09Exemptions() ExemptionList {
	return ExemptionList{Guard: G09, MaxEntries: maxG09Entries, Entries: g09Exemptions}
}

// CheckG09 reports, for the event package: a Type constant that no non-test call of internal/audit
// emits and that reserved does not list, a reserved constant that does have an emitter, and a Type
// constant that the Severity method of Type does not classify in an explicit case. A constant counts
// as emitted when non-test code passes it to an event.Type parameter that flows into internal/audit
// (audit.Emit directly, or through a wrapper whose own event.Type parameter reaches it), or when an
// audit helper that emits it is itself called from non-test code outside internal/audit. Filters,
// lookups and harness assertions that merely take an event.Type are not emissions.
func CheckG09(ws *Workspace, cfg Config, reserved []Exemption) []Violation {
	eventPath := cfg.path("event")
	pkg := ws.Package(eventPath)
	if pkg == nil || pkg.Types == nil {
		return nil
	}
	emitted := emittedTypeConsts(ws, eventPath, cfg.path("internal/audit"))
	var out []Violation
	classified, hasSeverity := severityCases(pkg, eventPath)
	if !hasSeverity {
		out = append(out, Violation{
			Guard: G09, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, pkg.Syntax[0].Pos()), Symbols: []string{eventPath + ".Type.Severity"},
			Msg: "event.Type has no Severity method",
		})
	}
	scope := pkg.Types.Scope()
	for _, name := range scope.Names() {
		c, ok := scope.Lookup(name).(*types.Const)
		if !ok || posInTestFile(pkg.Fset, c.Pos()) || !namedIs(c.Type(), eventPath, "Type") {
			continue
		}
		symbol := eventPath + "." + name
		isReserved := slices.ContainsFunc(reserved, func(e Exemption) bool { return e.Guard == G09 && e.Symbol == symbol })
		pos := ws.relPos(pkg.Fset, c.Pos())
		switch {
		case !emitted[c] && !isReserved:
			out = append(out, Violation{Guard: G09, Pkg: pkg.PkgPath, Pos: pos, Symbols: []string{symbol},
				Msg: "event type " + name + " has no non-test audit emit site and no reserved entry"})
		case emitted[c] && isReserved:
			out = append(out, Violation{Guard: G09, Pkg: pkg.PkgPath, Pos: pos, Symbols: []string{symbol},
				Msg: "reserved event type " + name + " has an emitter; drop its reserved entry"})
		}
		if hasSeverity && !classified[c] {
			out = append(out, Violation{Guard: G09, Pkg: pkg.PkgPath, Pos: pos, Symbols: []string{symbol},
				Msg: "event type " + name + " is not classified by an explicit Severity case"})
		}
	}
	return dedupe(out)
}

type emitParam struct {
	fn  *types.Func
	idx int
}

type typeCall struct {
	callee *types.Func
	idx    int
	arg    ast.Expr
	info   *types.Info
	owner  *types.Func
	inAud  bool
}

func emittedTypeConsts(ws *Workspace, eventPath, auditPath string) map[*types.Const]bool {
	emitted := map[*types.Const]bool{}
	viaHelper := map[*types.Func][]*types.Const{}
	usedHelper := map[*types.Func]bool{}
	emitting := map[emitParam]bool{}
	var calls []typeCall
	ws.eachFile(false, func(pkg *packages.Package, file *ast.File, _ string) {
		info := pkg.TypesInfo
		inAudit := pkg.PkgPath == auditPath
		for _, d := range file.Decls {
			fd, _ := d.(*ast.FuncDecl)
			var owner *types.Func
			if fd != nil {
				owner, _ = info.Defs[fd.Name].(*types.Func)
				if inAudit && owner != nil {
					sig, _ := owner.Type().(*types.Signature)
					for i := 0; sig != nil && i < sig.Params().Len(); i++ {
						if namedIs(sig.Params().At(i).Type(), eventPath, "Type") {
							emitting[emitParam{owner, i}] = true
						}
					}
				}
			}
			ast.Inspect(d, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					callee := calleeFunc(info, x)
					for i, arg := range x.Args {
						if callee != nil && paramIsEventType(info, x, i, eventPath) {
							calls = append(calls, typeCall{callee, i, arg, info, owner, inAudit})
						}
					}
				case *ast.Ident:
					if fn, ok := info.Uses[x].(*types.Func); ok && !inAudit && fn.Pkg() != nil && fn.Pkg().Path() == auditPath {
						usedHelper[fn] = true
					}
				}
				return true
			})
		}
	})
	for changed := true; changed; {
		changed = false
		for _, c := range calls {
			if c.inAud || !isEmitting(emitting, c.callee, c.idx) {
				continue
			}
			if k := eventTypeConst(c.info, c.arg, eventPath); k != nil {
				emitted[k] = true
				continue
			}
			if j := ownerParamIndex(c.info, c.arg, c.owner); j >= 0 && !emitting[emitParam{c.owner, j}] {
				emitting[emitParam{c.owner, j}] = true
				changed = true
			}
		}
	}
	for _, c := range calls {
		if !c.inAud || c.owner == nil || !isEmitting(emitting, c.callee, c.idx) {
			continue
		}
		if k := eventTypeConst(c.info, c.arg, eventPath); k != nil {
			viaHelper[c.owner] = append(viaHelper[c.owner], k)
		}
	}
	for fn, consts := range viaHelper {
		if usedHelper[fn] {
			for _, c := range consts {
				emitted[c] = true
			}
		}
	}
	return emitted
}

func isEmitting(emitting map[emitParam]bool, fn *types.Func, idx int) bool {
	if emitting[emitParam{fn, idx}] {
		return true
	}
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || sig.Recv() == nil || !types.IsInterface(sig.Recv().Type()) {
		return false
	}
	for k := range emitting {
		if k.idx == idx && k.fn.Name() == fn.Name() && isMethod(k.fn) {
			return true
		}
	}
	return false
}

func isMethod(fn *types.Func) bool {
	sig, _ := fn.Type().(*types.Signature)
	return sig != nil && sig.Recv() != nil
}

func calleeFunc(info *types.Info, call *ast.CallExpr) *types.Func {
	switch f := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		fn, _ := info.Uses[f].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		fn, _ := info.Uses[f.Sel].(*types.Func)
		return fn
	case *ast.IndexExpr:
		return calleeFunc(info, &ast.CallExpr{Fun: f.X})
	}
	return nil
}

func ownerParamIndex(info *types.Info, arg ast.Expr, owner *types.Func) int {
	id, ok := ast.Unparen(arg).(*ast.Ident)
	if !ok || owner == nil {
		return -1
	}
	v, ok := info.Uses[id].(*types.Var)
	if !ok {
		return -1
	}
	sig, _ := owner.Type().(*types.Signature)
	for i := 0; sig != nil && i < sig.Params().Len(); i++ {
		if sig.Params().At(i) == v {
			return i
		}
	}
	return -1
}

func paramIsEventType(info *types.Info, call *ast.CallExpr, i int, eventPath string) bool {
	sig, ok := info.TypeOf(call.Fun).(*types.Signature)
	if !ok || sig == nil {
		return false
	}
	params := sig.Params()
	if sig.Variadic() && i >= params.Len()-1 {
		return false
	}
	return i < params.Len() && namedIs(params.At(i).Type(), eventPath, "Type")
}

func eventTypeConst(info *types.Info, e ast.Expr, eventPath string) *types.Const {
	var id *ast.Ident
	switch x := ast.Unparen(e).(type) {
	case *ast.Ident:
		id = x
	case *ast.SelectorExpr:
		id = x.Sel
	default:
		return nil
	}
	c, ok := info.Uses[id].(*types.Const)
	if !ok || c.Pkg() == nil || c.Pkg().Path() != eventPath || !namedIs(c.Type(), eventPath, "Type") {
		return nil
	}
	return c
}

func severityCases(pkg *packages.Package, eventPath string) (map[*types.Const]bool, bool) {
	classified := map[*types.Const]bool{}
	found := false
	for _, f := range pkg.Syntax {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name.Name != "Severity" || fd.Body == nil {
				continue
			}
			o, ok := pkg.TypesInfo.Defs[fd.Name].(*types.Func)
			if !ok || recvNamed(o) == nil || !namedIs(recvNamed(o), eventPath, "Type") {
				continue
			}
			found = true
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				cc, ok := n.(*ast.CaseClause)
				if !ok {
					return true
				}
				for _, e := range cc.List {
					if c := eventTypeConst(pkg.TypesInfo, e, eventPath); c != nil {
						classified[c] = true
					}
				}
				return true
			})
		}
	}
	return classified, found
}
