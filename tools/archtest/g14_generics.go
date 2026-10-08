package archtest

import (
	"go/ast"
	"go/types"
	"sort"

	"golang.org/x/tools/go/packages"
)

type typeParamSite struct {
	owner string
	index int
}

type siteEdge struct {
	from, to typeParamSite
}

type assertionTarget struct {
	node   ast.Node
	target types.Type
	kind   string
}

const errorsAsKind = "errors.As"

func genericAssertions(ws *Workspace) map[typeParamSite]string {
	out := map[typeParamSite]string{{owner: "errors.AsType", index: 0}: errorsAsKind}
	mark := func(s typeParamSite, kind string) bool {
		if prev, ok := out[s]; ok && (prev == "" || prev == kind) {
			return false
		}
		out[s] = kind
		return true
	}
	var edges []siteEdge
	ws.eachFile(false, func(pkg *packages.Package, file *ast.File, _ string) {
		info := pkg.TypesInfo
		sites := declaredTypeParams(info, file)
		ast.Inspect(file, func(n ast.Node) bool {
			for _, a := range assertionTargets(info, n) {
				if tp, ok := types.Unalias(a.target).(*types.TypeParam); ok {
					if s, ok := sites[tp]; ok {
						mark(s, a.kind)
					}
				}
			}
			return true
		})
		for _, id := range fileInstanceIdents(info, file) {
			owner := instanceOwner(info, id)
			if owner == "" {
				continue
			}
			args := info.Instances[id].TypeArgs
			for i := 0; i < args.Len(); i++ {
				if tp, ok := types.Unalias(args.At(i)).(*types.TypeParam); ok {
					if s, ok := sites[tp]; ok {
						edges = append(edges, siteEdge{from: typeParamSite{owner: owner, index: i}, to: s})
					}
				}
			}
		}
	})
	for changed := true; changed; {
		changed = false
		for _, e := range edges {
			if kind, ok := out[e.from]; ok && mark(e.to, kind) {
				changed = true
			}
		}
	}
	return out
}

func declaredTypeParams(info *types.Info, file *ast.File) map[*types.TypeParam]typeParamSite {
	sites := map[*types.TypeParam]typeParamSite{}
	for _, d := range file.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		fn, ok := info.Defs[fd.Name].(*types.Func)
		if !ok {
			continue
		}
		sig := fn.Type().(*types.Signature)
		for i := 0; i < sig.TypeParams().Len(); i++ {
			sites[sig.TypeParams().At(i)] = typeParamSite{owner: funcSymbol(fn), index: i}
		}
		if rn := recvNamed(fn); rn != nil {
			for i := 0; i < sig.RecvTypeParams().Len(); i++ {
				sites[sig.RecvTypeParams().At(i)] = typeParamSite{owner: typeSymbol(rn.Origin()), index: i}
			}
		}
	}
	return sites
}

func assertionTargets(info *types.Info, n ast.Node) []assertionTarget {
	switch x := n.(type) {
	case *ast.TypeAssertExpr:
		if x.Type != nil {
			return []assertionTarget{{node: x, target: info.TypeOf(x.Type)}}
		}
	case *ast.TypeSwitchStmt:
		var out []assertionTarget
		for _, c := range x.Body.List {
			if cc, ok := c.(*ast.CaseClause); ok {
				for _, e := range cc.List {
					out = append(out, assertionTarget{node: e, target: info.TypeOf(e)})
				}
			}
		}
		return out
	case *ast.CallExpr:
		if !isErrorsAs(info, x) || len(x.Args) != 2 {
			return nil
		}
		if ptr, ok := types.Unalias(info.TypeOf(x.Args[1])).(*types.Pointer); ok {
			return []assertionTarget{{node: x, target: ptr.Elem(), kind: errorsAsKind}}
		}
	}
	return nil
}

func fileInstanceIdents(info *types.Info, file *ast.File) []*ast.Ident {
	var out []*ast.Ident
	for id := range info.Instances {
		if id.Pos() >= file.FileStart && id.Pos() < file.FileEnd {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pos() < out[j].Pos() })
	return out
}

func instanceOwner(info *types.Info, id *ast.Ident) string {
	switch o := info.Uses[id].(type) {
	case *types.Func:
		return funcSymbol(o.Origin())
	case *types.TypeName:
		if n, ok := types.Unalias(o.Type()).(*types.Named); ok {
			return typeSymbol(n.Origin())
		}
	}
	return ""
}
