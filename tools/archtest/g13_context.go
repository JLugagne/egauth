package archtest

import (
	"go/token"
	"go/types"
	"regexp"

	"golang.org/x/tools/go/packages"
)

// G13 forbids public context accessors.
const G13 GuardID = "G13"

var contextAccessor = regexp.MustCompile(`FromContext$|^ContextWith`)

// CheckG13 rejects exported funcs, methods and func-typed package vars named *FromContext or
// ContextWith* outside internal/ packages. Methods and func-typed exported fields of every named
// type reachable from the exported API count too, whether or not the type is exported or internal,
// as do func-typed exported fields of anonymous structs held by exported vars. Package main is
// skipped: its exports cannot be imported.
func CheckG13(ws *Workspace, _ Config) []Violation {
	var out []Violation
	report := func(pkgPath, pos, sym, msg string) {
		out = append(out, Violation{Guard: G13, Pkg: pkgPath, Pos: pos, Symbols: []string{sym}, Msg: msg})
	}
	eachExportedFunc(ws, false, func(pkg *packages.Package, fn *types.Func) {
		if contextAccessor.MatchString(fn.Name()) {
			report(pkg.PkgPath, ws.relPos(pkg.Fset, fn.Pos()), funcSymbol(fn), "exported context accessor "+fn.Name())
		}
	})
	ws.eachObject(func(pkg *packages.Package, obj types.Object) {
		v, ok := obj.(*types.Var)
		if !ok || !v.Exported() || isInternalPath(pkg.PkgPath) {
			return
		}
		if _, ok := v.Type().Underlying().(*types.Signature); ok && contextAccessor.MatchString(v.Name()) {
			report(pkg.PkgPath, ws.relPos(pkg.Fset, v.Pos()), pkg.PkgPath+"."+v.Name(), "exported context accessor var "+v.Name())
		}
		if u, ok := types.Unalias(v.Type()).(*types.Struct); ok {
			for _, f := range accessorFields(u) {
				report(pkg.PkgPath, ws.relPos(pkg.Fset, f.Pos()), pkg.PkgPath+"."+v.Name()+"."+f.Name(), "exported context accessor field "+v.Name()+"."+f.Name())
			}
		}
	})
	reportAt := func(st surfaceType, pos token.Pos, member, msg string) {
		v := ws.locate(st, pos, member)
		v.Guard, v.Msg = G13, msg
		out = append(out, v)
	}
	for _, st := range ws.surfaceTypes(false, false) {
		named, obj := st.named, st.named.Obj()
		for _, m := range exportedMethods(named) {
			if !contextAccessor.MatchString(m.Name()) || m.Pkg() == obj.Pkg() && posInTestFile(st.pkg.Fset, m.Pos()) {
				continue
			}
			pos := m.Pos()
			if m.Pkg() != obj.Pkg() || !pos.IsValid() {
				pos = obj.Pos()
			}
			reportAt(st, pos, m.Name(), "exported context accessor "+st.label()+"."+m.Name())
		}
		if u, ok := named.Underlying().(*types.Struct); ok {
			for _, f := range accessorFields(u) {
				reportAt(st, f.Pos(), f.Name(), "exported context accessor field "+st.label()+"."+f.Name())
			}
		}
	}
	return dedupe(out)
}

func accessorFields(s *types.Struct) []*types.Var {
	var out []*types.Var
	for i := 0; i < s.NumFields(); i++ {
		f := s.Field(i)
		if !f.Exported() || !contextAccessor.MatchString(f.Name()) {
			continue
		}
		if _, ok := f.Type().Underlying().(*types.Signature); ok {
			out = append(out, f)
		}
	}
	return out
}
