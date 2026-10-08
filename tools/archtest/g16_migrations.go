package archtest

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

// G16 is the static part of the migration guards of DESIGN.md section 4.9.
const G16 GuardID = "G16"

func init() { RegisterList(G16Exemptions()) }

const maxG16Entries = LegacyPrefixCount

var g16Exemptions = LegacyExemptions(G16)

// G16Exemptions returns the exemptions that the workspace test filters CheckG16 findings with.
func G16Exemptions() ExemptionList {
	return ExemptionList{Guard: G16, MaxEntries: maxG16Entries, Entries: g16Exemptions}
}

type embeddedFS struct {
	pkg      *packages.Package
	name     string
	pos      token.Pos
	dir      string
	patterns []string
	regs     int
}

func (e *embeddedFS) key() string { return e.pkg.PkgPath + "." + e.name }

// CheckG16 rejects, in the packages of every module: an embedded migrations directory (a
// //go:embed pattern with a "migrations" path element) that is not referenced by exactly one
// migrate.Module literal or FS field assignment of a register_*.go file; a migrate.Module literal or
// FS field assignment (tuple and range assignments included) outside register_*.go that sets an
// FS; the address of a migrate.Module FS field, anywhere; a conversion of another struct to
// migrate.Module; a register_*.go Module whose FS is set but is not an embedded migrations FS (a
// zero or non-embedded variable, os.DirFS...); a register_*.go Module without an FS (omitted, nil
// or a conversion of nil) when version does not end in "-dev"; and, in every embedded SQL file, a
// DROP or a statement outside the idempotent allowlist (CREATE TABLE/INDEX/EXTENSION/SEQUENCE/SCHEMA
// IF NOT EXISTS but never CREATE TABLE ... AS, ALTER TABLE ... ADD COLUMN IF NOT EXISTS and guarded
// DO blocks). A guarded DO block is a sequence of IF [NOT] EXISTS (SELECT ...) THEN ... END IF
// blocks, whose SELECT reads only pg_catalog or information_schema relations and calls no function
// beyond the unqualified and unquoted to_regclass, to_regtype, to_regnamespace, current_schema,
// lower and upper, or statements followed by one EXCEPTION WHEN
// duplicate_object|table|column|schema|function THEN NULL handler (never others); its statements are only schema additions (CREATE, ALTER TABLE ... ADD COLUMN or
// ADD CONSTRAINT, ALTER TYPE ... ADD VALUE, COMMENT ON, NULL). String literals are masked,
// E-prefixed escape strings included, so a keyword inside a string never counts, and dynamic SQL
// (EXECUTE) is never accepted. A migrate.Module is a type named Module of a package named migrate.
func CheckG16(ws *Workspace, cfg Config, version string) []Violation {
	var out []Violation
	for _, v := range ws.moduleViews() {
		var fss []*embeddedFS
		byKey := map[string]*embeddedFS{}
		for _, pkg := range v.plain {
			if _, ok := cfg.Rel(pkg.PkgPath); !ok {
				continue
			}
			for _, f := range pkg.Syntax {
				filename := pkg.Fset.Position(f.Pos()).Filename
				if isTestFile(filename) {
					continue
				}
				for _, e := range embeddedMigrations(pkg, f, filename) {
					if byKey[e.key()] == nil {
						byKey[e.key()] = e
						fss = append(fss, e)
					}
				}
			}
		}
		stubOK := strings.HasSuffix(version, "-dev")
		for _, pkg := range v.plain {
			if _, ok := cfg.Rel(pkg.PkgPath); !ok {
				continue
			}
			for _, f := range pkg.Syntax {
				filename := pkg.Fset.Position(f.Pos()).Filename
				if isTestFile(filename) {
					continue
				}
				isRegister := strings.HasPrefix(filepath.Base(filename), "register_")
				handle := func(at ast.Node, refs []string, kind fsKind) {
					report := func(sym, msg string) {
						out = append(out, Violation{Guard: G16, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, at.Pos()), Symbols: []string{sym}, Msg: msg})
					}
					embedded := false
					for _, key := range refs {
						e := byKey[key]
						if e == nil {
							continue
						}
						embedded = true
						if isRegister {
							e.regs++
						} else {
							out = append(out, Violation{Guard: G16, Pkg: e.pkg.PkgPath, Pos: ws.relPos(pkg.Fset, at.Pos()), Symbols: []string{e.key()}, Msg: "migrations FS " + e.name + " is registered outside register_*.go"})
						}
					}
					switch {
					case embedded:
					case kind == fsStub && isRegister && !stubOK:
						report(enclosingSymbol(pkg, f, at.Pos()), "nil-FS stub module outside a -dev version")
					case kind == fsSet && isRegister:
						report(enclosingSymbol(pkg, f, at.Pos()), "module FS is not an embedded migrations FS")
					case kind == fsSet:
						report(enclosingSymbol(pkg, f, at.Pos()), "migrate.Module with an FS outside register_*.go")
					}
				}
				info := pkg.TypesInfo
				ast.Inspect(f, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.CompositeLit:
						if isMigrateModule(info.TypeOf(x)) {
							refs, kind := moduleFSRefs(info, x)
							handle(x, refs, kind)
						}
					case *ast.AssignStmt:
						for i, lhs := range x.Lhs {
							if !isModuleFSField(info, lhs) || len(x.Rhs) == 0 {
								continue
							}
							rhs := x.Rhs[0]
							if len(x.Lhs) == len(x.Rhs) {
								rhs = x.Rhs[i]
							}
							refs, kind := fsValueRefs(info, rhs)
							handle(rhs, refs, kind)
						}
					case *ast.RangeStmt:
						for _, lhs := range []ast.Expr{x.Key, x.Value} {
							if lhs != nil && isModuleFSField(info, lhs) {
								refs, kind := fsValueRefs(info, x.X)
								handle(x.X, refs, kind)
							}
						}
					case *ast.UnaryExpr:
						if x.Op == token.AND && isModuleFSField(info, x.X) {
							out = append(out, Violation{Guard: G16, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, x.Pos()), Symbols: []string{enclosingSymbol(pkg, f, x.Pos())}, Msg: "address of migrate.Module.FS bypasses the assignment check"})
						}
					case *ast.CallExpr:
						tv, ok := info.Types[x.Fun]
						if ok && tv.IsType() && isMigrateModule(tv.Type) && len(x.Args) == 1 && !types.Identical(info.TypeOf(x.Args[0]), tv.Type) {
							out = append(out, Violation{Guard: G16, Pkg: pkg.PkgPath, Pos: ws.relPos(pkg.Fset, x.Pos()), Symbols: []string{enclosingSymbol(pkg, f, x.Pos())}, Msg: "conversion to migrate.Module bypasses the literal check"})
						}
					}
					return true
				})
			}
		}
		for _, e := range fss {
			pos := ws.relPos(e.pkg.Fset, e.pos)
			switch {
			case e.regs == 0:
				out = append(out, Violation{Guard: G16, Pkg: e.pkg.PkgPath, Pos: pos, Symbols: []string{e.key()}, Msg: "orphan migrations FS " + e.name + " is not registered in any register_*.go"})
			case e.regs > 1:
				out = append(out, Violation{Guard: G16, Pkg: e.pkg.PkgPath, Pos: pos, Symbols: []string{e.key()}, Msg: "migrations FS " + e.name + " is registered " + strconv.Itoa(e.regs) + " times"})
			}
			out = append(out, checkMigrationFiles(ws, e)...)
		}
	}
	return dedupe(out)
}

func embeddedMigrations(pkg *packages.Package, f *ast.File, filename string) []*embeddedFS {
	var out []*embeddedFS
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			doc := vs.Doc
			if doc == nil && len(gd.Specs) == 1 {
				doc = gd.Doc
			}
			patterns := embedPatterns(doc)
			if len(patterns) == 0 || len(vs.Names) != 1 || !hasMigrationsElement(patterns) {
				continue
			}
			out = append(out, &embeddedFS{pkg: pkg, name: vs.Names[0].Name, pos: vs.Names[0].Pos(), dir: filepath.Dir(filename), patterns: patterns})
		}
	}
	return out
}

func embedPatterns(doc *ast.CommentGroup) []string {
	if doc == nil {
		return nil
	}
	var out []string
	for _, c := range doc.List {
		rest, ok := strings.CutPrefix(c.Text, "//go:embed")
		if !ok || (rest != "" && rest[0] != ' ' && rest[0] != '\t') {
			continue
		}
		out = append(out, splitEmbedFields(rest)...)
	}
	return out
}

func splitEmbedFields(s string) []string {
	var out []string
	for s = strings.TrimSpace(s); s != ""; s = strings.TrimSpace(s) {
		if q := s[0]; q == '"' || q == '`' {
			end := strings.IndexByte(s[1:], q)
			if end < 0 {
				return out
			}
			lit := s[:end+2]
			if u, err := strconv.Unquote(lit); err == nil {
				out = append(out, u)
			}
			s = s[end+2:]
			continue
		}
		end := strings.IndexAny(s, " \t")
		if end < 0 {
			end = len(s)
		}
		out = append(out, s[:end])
		s = s[end:]
	}
	return out
}

func hasMigrationsElement(patterns []string) bool {
	for _, p := range patterns {
		for _, seg := range strings.Split(strings.TrimPrefix(p, "all:"), "/") {
			if seg == "migrations" {
				return true
			}
		}
	}
	return false
}

func isMigrateModule(t types.Type) bool {
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Name() != "Module" || n.Obj().Pkg() == nil {
		return false
	}
	_, isStruct := n.Underlying().(*types.Struct)
	return isStruct && (n.Obj().Pkg().Name() == "migrate" || n.Obj().Pkg().Name() == "pgxmigrate")
}

type fsKind int

const (
	fsStub fsKind = iota
	fsSet
)

func isNilFS(info *types.Info, e ast.Expr) bool {
	e = ast.Unparen(e)
	if id, ok := e.(*ast.Ident); ok {
		return info.Uses[id] == types.Universe.Lookup("nil")
	}
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	if tv, ok := info.Types[call.Fun]; !ok || !tv.IsType() {
		return false
	}
	return isNilFS(info, call.Args[0])
}

func moduleFSRefs(info *types.Info, lit *ast.CompositeLit) (refs []string, kind fsKind) {
	st, _ := info.TypeOf(lit).Underlying().(*types.Struct)
	var value ast.Expr
	for i, elt := range lit.Elts {
		switch e := elt.(type) {
		case *ast.KeyValueExpr:
			if id, ok := e.Key.(*ast.Ident); ok && id.Name == "FS" {
				value = e.Value
			}
		default:
			if st != nil && i < st.NumFields() && st.Field(i).Name() == "FS" {
				value = e
			}
		}
	}
	return fsValueRefs(info, value)
}

func fsValueRefs(info *types.Info, value ast.Expr) (refs []string, kind fsKind) {
	if value == nil || isNilFS(info, value) {
		return nil, fsStub
	}
	ast.Inspect(value, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if v, ok := info.Uses[id].(*types.Var); ok && v.Pkg() != nil && !v.IsField() {
				refs = append(refs, v.Pkg().Path()+"."+v.Name())
			}
		}
		return true
	})
	return refs, fsSet
}

func isModuleFSField(info *types.Info, e ast.Expr) bool {
	sel, ok := ast.Unparen(e).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "FS" {
		return false
	}
	s := info.Selections[sel]
	if s == nil || s.Kind() != types.FieldVal {
		return false
	}
	n := fieldOwner(s)
	return n != nil && isMigrateModule(n)
}
