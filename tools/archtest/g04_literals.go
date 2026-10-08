package archtest

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

// G04 forbids misconfiguration strings, error fields, Must helpers and panics in public API.
const G04 GuardID = "G04"

var misconfigPattern = regexp.MustCompile(`(?i)misconfigur|not configured|no .* configured`)

var mustName = regexp.MustCompile(`^Must([A-Z0-9_]|$)`)

// CheckG04 rejects, in non-test code, string literals and concatenations matching misconfiguration
// phrasing (constant operands folded, other operands read as a placeholder word); fields
// holding an error (the error interface or any type whose value or pointer implements it) directly
// or through a slice, array, pointer, map, channel or anonymous struct, in struct types that are not
// errors themselves and are exported or reachable from the exported API (generic instances such as
// Res[error] included, with instances of generics from outside the workspace reported at the
// exported symbol that exposes them); exported Must* funcs, methods, interface methods, func-typed
// package vars and func-typed struct fields other than bool predicates; and panic calls inside
// exported funcs and methods or inside the initializers (func literals included) of exported vars.
func CheckG04(ws *Workspace, cfg Config) []Violation {
	var out []Violation
	errIface := types.Universe.Lookup("error").Type().Underlying().(*types.Interface)

	ws.eachFile(false, func(pkg *packages.Package, file *ast.File, _ string) {
		var visit func(n ast.Node) bool
		visit = func(n ast.Node) bool {
			expr, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			val, rest, ok := stringValue(pkg.TypesInfo, expr)
			if !ok {
				return true
			}
			if misconfigPattern.MatchString(val) {
				out = append(out, Violation{Guard: G04, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, expr.Pos()), Symbols: []string{enclosingSymbol(pkg, file, expr.Pos())}, Msg: "misconfiguration string literal " + strconv.Quote(val)})
			}
			for _, r := range rest {
				ast.Inspect(r, visit)
			}
			return false
		}
		ast.Inspect(file, visit)
		for _, d := range file.Decls {
			switch decl := d.(type) {
			case *ast.FuncDecl:
				out = append(out, mustAndPanicInFunc(ws, pkg, decl)...)
			case *ast.GenDecl:
				if decl.Tok == token.VAR {
					out = append(out, mustAndPanicInVars(ws, pkg, decl)...)
				}
			}
		}
	})

	ws.eachObject(func(pkg *packages.Package, obj types.Object) {
		tn, ok := obj.(*types.TypeName)
		if !ok || tn.IsAlias() {
			return
		}
		named, ok := tn.Type().(*types.Named)
		if !ok {
			return
		}
		switch u := named.Underlying().(type) {
		case *types.Interface:
			for i := 0; i < u.NumExplicitMethods(); i++ {
				m := u.ExplicitMethod(i)
				if m.Exported() && isMustHelper(m.Name(), m.Type()) {
					out = append(out, Violation{Guard: G04, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, m.Pos()), Symbols: []string{typeSymbol(named) + "." + m.Name()}, Msg: "exported Must helper method " + m.Name()})
				}
			}
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if f.Exported() && isMustHelper(f.Name(), f.Type()) {
					out = append(out, Violation{Guard: G04, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, f.Pos()), Symbols: []string{typeSymbol(named) + "." + f.Name()}, Msg: "exported Must helper field " + f.Name()})
				}
			}
		}
	})

	for _, st := range ws.surfaceTypes(true, false) {
		named := st.named
		structType, ok := named.Underlying().(*types.Struct)
		if !ok || types.Implements(types.NewPointer(named), errIface) {
			continue
		}
		for i := 0; i < structType.NumFields(); i++ {
			f := structType.Field(i)
			if f.Embedded() || !carriesError(f.Type(), errIface, map[types.Type]bool{}) {
				continue
			}
			v := ws.locate(st, f.Pos(), f.Name())
			v.Guard, v.Msg = G04, "error-carrying field "+st.label()+"."+f.Name()+" in a type that is not an error"
			out = append(out, v)
		}
	}
	return dedupe(out)
}

func stringValue(info *types.Info, expr ast.Expr) (string, []ast.Expr, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", nil, false
		}
		v, err := strconv.Unquote(e.Value)
		return v, nil, err == nil
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", nil, false
		}
		tv, ok := info.Types[e]
		if !ok || !isStringType(tv.Type) {
			return "", nil, false
		}
		if tv.Value != nil && tv.Value.Kind() == constant.String {
			return constant.StringVal(tv.Value), nil, true
		}
		var b strings.Builder
		var rest []ast.Expr
		for _, leaf := range concatLeaves(e) {
			if lv, ok := info.Types[leaf]; ok && lv.Value != nil && lv.Value.Kind() == constant.String {
				b.WriteString(constant.StringVal(lv.Value))
				continue
			}
			b.WriteString("x")
			rest = append(rest, leaf)
		}
		return b.String(), rest, true
	}
	return "", nil, false
}

func concatLeaves(e ast.Expr) []ast.Expr {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return concatLeaves(x.X)
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			return append(concatLeaves(x.X), concatLeaves(x.Y)...)
		}
	}
	return []ast.Expr{e}
}

func isStringType(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsString != 0
}

func carriesError(t types.Type, errIface *types.Interface, seen map[types.Type]bool) bool {
	if isErrorValue(t, errIface) {
		return true
	}
	if seen[t] {
		return false
	}
	seen[t] = true
	switch u := types.Unalias(t).(type) {
	case *types.Slice:
		return carriesError(u.Elem(), errIface, seen)
	case *types.Array:
		return carriesError(u.Elem(), errIface, seen)
	case *types.Pointer:
		return carriesError(u.Elem(), errIface, seen)
	case *types.Map:
		return carriesError(u.Elem(), errIface, seen)
	case *types.Chan:
		return carriesError(u.Elem(), errIface, seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if carriesError(u.Field(i).Type(), errIface, seen) {
				return true
			}
		}
	}
	return false
}

func isErrorValue(t types.Type, errIface *types.Interface) bool {
	t = types.Unalias(t)
	if _, ok := t.(*types.TypeParam); ok {
		return false
	}
	if types.Implements(t, errIface) {
		return true
	}
	if _, ok := t.Underlying().(*types.Interface); ok {
		return false
	}
	if _, ok := t.(*types.Pointer); ok {
		return false
	}
	return types.Implements(types.NewPointer(t), errIface)
}

func isMustHelper(name string, t types.Type) bool {
	sig, ok := t.Underlying().(*types.Signature)
	if !ok || !mustName.MatchString(name) {
		return false
	}
	res := sig.Results()
	if res.Len() != 1 {
		return true
	}
	b, ok := res.At(0).Type().(*types.Basic)
	return !ok || b.Kind() != types.Bool
}

func mustAndPanicInFunc(ws *Workspace, pkg *packages.Package, fd *ast.FuncDecl) []Violation {
	if !fd.Name.IsExported() || fd.Body == nil {
		return nil
	}
	obj, _ := pkg.TypesInfo.Defs[fd.Name].(*types.Func)
	if obj == nil {
		return nil
	}
	var out []Violation
	sym := funcSymbol(obj)
	if isMustHelper(fd.Name.Name, obj.Type()) {
		out = append(out, Violation{Guard: G04, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, fd.Pos()), Symbols: []string{sym}, Msg: "exported Must helper " + fd.Name.Name})
	}
	return append(out, panicCalls(ws, pkg, fd.Body, sym, "panic in exported func "+fd.Name.Name)...)
}

func mustAndPanicInVars(ws *Workspace, pkg *packages.Package, gd *ast.GenDecl) []Violation {
	var out []Violation
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, name := range vs.Names {
			if !name.IsExported() {
				continue
			}
			sym := pkg.PkgPath + "." + name.Name
			if obj, ok := pkg.TypesInfo.Defs[name].(*types.Var); ok && isMustHelper(name.Name, obj.Type()) {
				out = append(out, Violation{Guard: G04, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, name.Pos()), Symbols: []string{sym}, Msg: "exported Must helper var " + name.Name})
			}
			values := vs.Values
			if len(values) == len(vs.Names) {
				values = values[i : i+1]
			}
			for _, v := range values {
				out = append(out, panicCalls(ws, pkg, v, sym, "panic in exported var "+name.Name)...)
			}
		}
	}
	return out
}

func panicCalls(ws *Workspace, pkg *packages.Package, root ast.Node, sym, msg string) []Violation {
	var out []Violation
	ast.Inspect(root, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if b, ok := pkg.TypesInfo.Uses[id].(*types.Builtin); ok && b.Name() == "panic" {
			out = append(out, Violation{Guard: G04, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, call.Pos()), Symbols: []string{sym}, Msg: msg})
		}
		return true
	})
	return out
}
