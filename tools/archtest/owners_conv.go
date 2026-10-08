package archtest

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"
)

type ownerShared struct {
	carriers         []types.Type
	carriersResolved bool
}

func shortQualifier(p *types.Package) string { return p.Name() }

func rowByID(id string) OwnerRow {
	for _, r := range ownerRows {
		if r.ID == id {
			return r
		}
	}
	return OwnerRow{ID: id}
}

func (c *ownerCtx) kekType() *types.Named {
	if c.kekResolved {
		return c.kek
	}
	c.kekResolved = true
	kekPath := c.cfg.path("kek")
	var kp *types.Package
	if c.pkg.Types != nil {
		kp = findImported(c.pkg.Types, kekPath)
	}
	if kp == nil && c.ws != nil {
		if p := c.ws.Package(kekPath); p != nil {
			kp = p.Types
		}
	}
	if kp == nil {
		return nil
	}
	tn, ok := kp.Scope().Lookup("KEK").(*types.TypeName)
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
	c.kek = n
	return n
}

func (c *ownerCtx) implementsKEK(t types.Type) bool {
	k := c.kekType()
	if k == nil || t == nil {
		return false
	}
	it := k.Underlying().(*types.Interface)
	return types.Implements(t, it) || (!types.IsInterface(t) && types.Implements(types.NewPointer(t), it))
}

func (c *ownerCtx) ownedMethod(fn *types.Func, holder types.Type) (OwnerRow, string, bool) {
	if n := recvNamed(fn); n != nil {
		pkgPath, key := objPkgPath(n.Obj()), n.Obj().Name()+"."+fn.Name()
		for _, row := range ownerRows {
			for _, ref := range row.Objects {
				if strings.Contains(ref.Name, ".") && ref.matches(c.cfg, pkgPath, key) {
					return row, pkgPath + "." + key, true
				}
			}
		}
	}
	if (fn.Name() == "Seal" || fn.Name() == "Open") && c.implementsKEK(holder) {
		return rowByID("kek"), "kek.KEK " + fn.Name(), true
	}
	return OwnerRow{}, "", false
}

func (c *ownerCtx) declaresOwned(fn *types.Func) bool {
	return fn.Pkg() != nil && fn.Pkg().Path() == c.pkg.PkgPath
}

func (c *ownerCtx) conversionLeak(v, t types.Type) (OwnerRow, string, bool) {
	row, what, ok := c.hiddenOwned(v, t)
	if !ok {
		return OwnerRow{}, "", false
	}
	return row, "conversion of " + types.TypeString(v, shortQualifier) + " to " + types.TypeString(t, shortQualifier) + " hides " + what, true
}

func (c *ownerCtx) hiddenOwned(v, t types.Type) (OwnerRow, string, bool) {
	if v == nil || t == nil {
		return OwnerRow{}, "", false
	}
	if _, isTuple := v.(*types.Tuple); isTuple {
		return OwnerRow{}, "", false
	}
	ti, ok := t.Underlying().(*types.Interface)
	if !ok || ti.NumMethods() == 0 || types.Identical(v, t) {
		return OwnerRow{}, "", false
	}
	for i := 0; i < ti.NumMethods(); i++ {
		m := ti.Method(i)
		obj, _, _ := types.LookupFieldOrMethod(v, false, m.Pkg(), m.Name())
		fn, ok := obj.(*types.Func)
		if !ok {
			continue
		}
		row, what, ok := c.ownedMethod(fn, v)
		if !ok || c.declaresOwned(fn) {
			continue
		}
		if c.targetKeepsOwnership(row, m, t) {
			continue
		}
		return row, what, true
	}
	return OwnerRow{}, "", false
}

func (c *ownerCtx) targetKeepsOwnership(row OwnerRow, m *types.Func, t types.Type) bool {
	if row.ID == "kek" {
		k := c.kekType()
		return k != nil && types.Identical(t, k)
	}
	tRow, _, ok := c.ownedMethod(m, t)
	return ok && tRow.ID == row.ID
}

func (c *ownerCtx) carrierTypes() []types.Type {
	if c.shared == nil {
		c.shared = &ownerShared{}
	}
	if c.shared.carriersResolved {
		return c.shared.carriers
	}
	c.shared.carriersResolved = true
	if c.ws == nil {
		return nil
	}
	paths := make([]string, 0, len(c.ws.byPath))
	for path := range c.ws.byPath {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	seen := map[types.Type]bool{}
	add := func(t types.Type) {
		if !seen[t] {
			seen[t] = true
			c.shared.carriers = append(c.shared.carriers, t)
		}
	}
	for _, path := range paths {
		p := c.ws.byPath[path]
		if p.Types == nil {
			continue
		}
		for _, row := range ownerRows {
			for _, ref := range row.Objects {
				typeName, _, isMember := strings.Cut(ref.Name, ".")
				if !isMember || strings.Contains(typeName, "*") || !ref.matchesPkg(c.cfg, path) {
					continue
				}
				if tn, ok := p.Types.Scope().Lookup(typeName).(*types.TypeName); ok {
					add(tn.Type())
					if !types.IsInterface(tn.Type()) {
						add(types.NewPointer(tn.Type()))
					}
				}
			}
		}
	}
	if k := c.kekType(); k != nil {
		add(k)
	}
	return c.shared.carriers
}

func (c *ownerCtx) assertionLeak(t types.Type) (OwnerRow, string, bool) {
	if t == nil || !types.IsInterface(t) {
		return OwnerRow{}, "", false
	}
	for _, carrier := range c.carrierTypes() {
		ti := t.Underlying().(*types.Interface)
		if !types.Implements(carrier, ti) {
			continue
		}
		if row, what, ok := c.hiddenOwned(carrier, t); ok {
			return row, "type assertion to " + types.TypeString(t, shortQualifier) + " can recover " + what, true
		}
	}
	return OwnerRow{}, "", false
}

type conversionVisit func(at ast.Node, v, t types.Type)

func eachConversion(info *types.Info, file *ast.File, visit conversionVisit) {
	single := func(t types.Type, e ast.Expr) {
		if t != nil {
			visit(e, info.TypeOf(e), t)
		}
	}
	many := func(targets []types.Type, values []ast.Expr) {
		if len(values) == 1 && len(targets) > 1 {
			if tup, ok := info.TypeOf(values[0]).(*types.Tuple); ok {
				for i := 0; i < tup.Len() && i < len(targets); i++ {
					if targets[i] != nil {
						visit(values[0], tup.At(i).Type(), targets[i])
					}
				}
			}
			return
		}
		for i, v := range values {
			if i < len(targets) {
				single(targets[i], v)
			}
		}
	}
	returns := func(sig *types.Signature, body *ast.BlockStmt) {
		if sig == nil || body == nil {
			return
		}
		targets := make([]types.Type, sig.Results().Len())
		for i := range targets {
			targets[i] = sig.Results().At(i).Type()
		}
		ast.Inspect(body, func(n ast.Node) bool {
			switch r := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.ReturnStmt:
				many(targets, r.Results)
			}
			return true
		})
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			if fn, ok := info.Defs[x.Name].(*types.Func); ok {
				returns(fn.Type().(*types.Signature), x.Body)
			}
		case *ast.FuncLit:
			sig, _ := info.TypeOf(x).(*types.Signature)
			returns(sig, x.Body)
		case *ast.AssignStmt:
			if x.Tok == token.ASSIGN {
				targets := make([]types.Type, len(x.Lhs))
				for i, l := range x.Lhs {
					targets[i] = info.TypeOf(l)
				}
				many(targets, x.Rhs)
			}
		case *ast.ValueSpec:
			if x.Type != nil {
				t := info.TypeOf(x.Type)
				targets := make([]types.Type, len(x.Names))
				for i := range targets {
					targets[i] = t
				}
				many(targets, x.Values)
			}
		case *ast.CallExpr:
			callConversions(info, x, single, many)
		case *ast.CompositeLit:
			literalConversions(info, x, single)
		case *ast.SendStmt:
			if ch, ok := coreUnder(info.TypeOf(x.Chan)).(*types.Chan); ok {
				single(ch.Elem(), x.Value)
			}
		case *ast.IndexExpr:
			if m, ok := coreUnder(info.TypeOf(x.X)).(*types.Map); ok {
				single(m.Key(), x.Index)
			}
		}
		return true
	})
}

func coreUnder(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	return t.Underlying()
}

func callConversions(info *types.Info, call *ast.CallExpr, single func(types.Type, ast.Expr), many func([]types.Type, []ast.Expr)) {
	tv, ok := info.Types[call.Fun]
	if !ok {
		return
	}
	if tv.IsType() {
		if len(call.Args) == 1 {
			single(tv.Type, call.Args[0])
		}
		return
	}
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
		if b, ok := info.Uses[id].(*types.Builtin); ok {
			if b.Name() == "append" && !call.Ellipsis.IsValid() {
				if s, ok := coreUnder(info.TypeOf(call)).(*types.Slice); ok {
					for _, a := range call.Args[1:] {
						single(s.Elem(), a)
					}
				}
			}
			return
		}
	}
	sig, ok := coreUnder(tv.Type).(*types.Signature)
	if !ok {
		return
	}
	if len(call.Args) == 0 {
		return
	}
	params := sig.Params()
	n := params.Len()
	targets := make([]types.Type, 0, len(call.Args))
	for i := range call.Args {
		switch {
		case sig.Variadic() && i >= n-1 && !call.Ellipsis.IsValid():
			if s, ok := params.At(n - 1).Type().(*types.Slice); ok {
				targets = append(targets, s.Elem())
			}
		case i < n:
			targets = append(targets, params.At(i).Type())
		}
	}
	if _, isTuple := info.TypeOf(call.Args[0]).(*types.Tuple); len(call.Args) == 1 && isTuple {
		targets = targets[:0]
		for i := 0; i < n; i++ {
			targets = append(targets, params.At(i).Type())
		}
	}
	many(targets, call.Args)
}

func literalConversions(info *types.Info, lit *ast.CompositeLit, single func(types.Type, ast.Expr)) {
	t := info.TypeOf(lit)
	if t == nil {
		return
	}
	if p, ok := t.Underlying().(*types.Pointer); ok {
		t = p.Elem()
	}
	switch u := t.Underlying().(type) {
	case *types.Struct:
		for i, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				id, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				for j := 0; j < u.NumFields(); j++ {
					if u.Field(j).Name() == id.Name {
						single(u.Field(j).Type(), kv.Value)
					}
				}
				continue
			}
			if i < u.NumFields() {
				single(u.Field(i).Type(), elt)
			}
		}
	case *types.Slice:
		elementConversions(lit.Elts, nil, u.Elem(), single)
	case *types.Array:
		elementConversions(lit.Elts, nil, u.Elem(), single)
	case *types.Map:
		elementConversions(lit.Elts, u.Key(), u.Elem(), single)
	}
}

func elementConversions(elts []ast.Expr, key, elem types.Type, single func(types.Type, ast.Expr)) {
	for _, elt := range elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if key != nil {
				single(key, kv.Key)
			}
			single(elem, kv.Value)
			continue
		}
		single(elem, elt)
	}
}

func (c *ownerCtx) instantiationLeaks(id *ast.Ident, visit conversionVisit) {
	inst, ok := c.info.Instances[id]
	if !ok {
		return
	}
	var tparams *types.TypeParamList
	switch o := c.info.Uses[id].(type) {
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
		return
	}
	for i := 0; i < tparams.Len() && i < inst.TypeArgs.Len(); i++ {
		visit(id, inst.TypeArgs.At(i), tparams.At(i).Constraint())
	}
}

func (c *ownerCtx) assertedTypes(n ast.Node) []ast.Expr {
	switch x := n.(type) {
	case *ast.TypeAssertExpr:
		if x.Type != nil {
			return []ast.Expr{x.Type}
		}
	case *ast.TypeSwitchStmt:
		var out []ast.Expr
		for _, s := range x.Body.List {
			if cc, ok := s.(*ast.CaseClause); ok {
				out = append(out, cc.List...)
			}
		}
		return out
	}
	return nil
}
