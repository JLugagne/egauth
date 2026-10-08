package archtest

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

// G06 enforces the single-owner table of DESIGN.md section 9.2.
const G06 GuardID = "G06"

func init() { RegisterList(G06Exemptions()) }

const maxG06Entries = LegacyPrefixCount + 3

type g06Typed struct {
	rel, name, row string
	removedBy      WorkPackage
}

var g06TypedEntries = []g06Typed{
	{rel: "event", name: "KeyAMR", row: "jwt", removedBy: WP5},
	{rel: "", name: "ActorFromContext", row: "ctxvalue", removedBy: WP16},
	{rel: "", name: "ContextWithActor", row: "ctxvalue", removedBy: WP16},
}

var g06Exemptions = g06BuildExemptions()

func g06BuildExemptions() []Exemption {
	out := LegacyExemptions(G06)
	cfg := DefaultConfig()
	for _, e := range g06TypedEntries {
		out = append(out, Exemption{Guard: G06, Symbol: cfg.path(e.rel) + "." + e.name, RemovedBy: e.removedBy})
	}
	return out
}

func g06Candidates(cfg Config, enclosing, row string) []string {
	for _, e := range g06TypedEntries {
		sym := cfg.path(e.rel) + "." + e.name
		if (enclosing == sym || strings.HasPrefix(enclosing, sym+".")) && e.row != row {
			return nil
		}
	}
	return []string{enclosing}
}

// G06Exemptions returns the exemptions that the workspace test filters CheckG06 findings with.
func G06Exemptions() ExemptionList {
	return ExemptionList{Guard: G06, MaxEntries: maxG06Entries, Entries: g06Exemptions}
}

// CheckG06 rejects, in non-test code, every use of an object, literal or composite literal of
// OwnerRows by a package that is not one of the row's owners. The package that declares an object
// may always use it. An owned method cannot be reached through a structural interface either: an
// implicit or explicit conversion (assignment, argument, return, composite literal element, send,
// append, map key), a generic instantiation or a type assertion that turns a value carrying an
// owned method (context.Context, *http.Request, session.Backend, event.Sink, a kek.KEK
// implementation...) into a non-owned interface with that method is reported where it happens. The
// candidate exemption symbol is the enclosing top-level symbol of the use, except when a typed G06
// exemption binds that symbol to another row: a typed exemption only waives the row it was granted
// for.
func CheckG06(ws *Workspace, cfg Config) []Violation {
	var out []Violation
	shared := &ownerShared{}
	ws.eachFile(false, func(pkg *packages.Package, file *ast.File, _ string) {
		rel, inRoot := cfg.Rel(pkg.PkgPath)
		if !inRoot {
			return
		}
		report := func(row OwnerRow, pos token.Pos, what string) {
			enclosing := enclosingSymbol(pkg, file, pos)
			out = append(out, Violation{
				Guard: G06, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, pos), Symbols: g06Candidates(cfg, enclosing, row.ID),
				Msg: row.ID + ": " + what + " is owned by " + strings.Join(row.Owners, ", "),
			})
		}
		allowed := func(row OwnerRow, pos token.Pos) bool {
			for _, owner := range row.Owners {
				if !isSymbolOwner(owner) {
					if matchOwnerPath(owner, rel) {
						return true
					}
					continue
				}
				ownerRel, name := splitSymbolOwner(owner)
				sym := cfg.path(ownerRel) + "." + name
				enclosing := enclosingSymbol(pkg, file, pos)
				if pkg.PkgPath == cfg.path(ownerRel) && (enclosing == sym || strings.HasPrefix(enclosing, sym+".")) {
					return true
				}
			}
			return false
		}
		handled := map[*ast.Ident]bool{}
		ctx := &ownerCtx{info: pkg.TypesInfo, cfg: cfg, ws: ws, pkg: pkg, file: file, shared: shared}
		leak := func(at ast.Node, v, t types.Type) {
			if row, what, ok := ctx.conversionLeak(v, t); ok && !allowed(row, at.Pos()) {
				report(row, at.Pos(), what)
			}
		}
		eachConversion(pkg.TypesInfo, file, leak)
		check := func(sel *ast.SelectorExpr, id *ast.Ident) {
			pkgPath, key, ok := objectKey(pkg.TypesInfo, sel, pkg.TypesInfo.Uses[id])
			if !ok || pkgPath == pkg.PkgPath {
				return
			}
			for _, row := range ownerRows {
				for _, ref := range row.Objects {
					if ref.matches(cfg, pkgPath, key) {
						if !allowed(row, id.Pos()) {
							report(row, id.Pos(), pkgPath+"."+key)
						}
						break
					}
				}
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				handled[x.Sel] = true
				check(x, x.Sel)
			case *ast.Ident:
				ctx.instantiationLeaks(x, leak)
				if !handled[x] {
					check(nil, x)
				}
			case *ast.CompositeLit:
				named, ok := types.Unalias(pkg.TypesInfo.TypeOf(x)).(*types.Named)
				if !ok || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() == pkg.PkgPath {
					break
				}
				for _, row := range ownerRows {
					for _, ref := range row.Composites {
						if ref.matches(cfg, named.Obj().Pkg().Path(), named.Obj().Name()) && !allowed(row, x.Pos()) {
							report(row, x.Pos(), "literal of "+named.Obj().Pkg().Path()+"."+named.Obj().Name())
						}
					}
				}
			case *ast.BasicLit:
				if x.Kind != token.STRING {
					break
				}
				val, err := strconv.Unquote(x.Value)
				if err != nil {
					break
				}
				for _, row := range ownerRows {
					if literalOwned(row, val) && !allowed(row, x.Pos()) {
						report(row, x.Pos(), "literal "+strconv.Quote(val))
					}
				}
			}
			for _, e := range ctx.assertedTypes(n) {
				if row, what, ok := ctx.assertionLeak(pkg.TypesInfo.TypeOf(e)); ok && !allowed(row, e.Pos()) {
					report(row, e.Pos(), what)
				}
			}
			for _, row := range ownerRows {
				if row.custom == nil {
					continue
				}
				if what := row.custom(ctx, n); what != "" && !allowed(row, n.Pos()) {
					report(row, n.Pos(), what)
				}
			}
			return true
		})
	})
	return dedupe(out)
}

func literalOwned(row OwnerRow, val string) bool {
	for _, l := range row.ExactLiteral {
		if val == l {
			return true
		}
	}
	for _, l := range row.Literals {
		if prefix, ok := strings.CutSuffix(l, "*"); ok {
			if len(val) >= len(prefix) && strings.EqualFold(val[:len(prefix)], prefix) {
				return true
			}
			continue
		}
		if strings.EqualFold(val, l) {
			return true
		}
	}
	return false
}
