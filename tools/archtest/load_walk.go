package archtest

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Config tells the guards where the egauth root package and the uuid library live, so fixtures can
// mimic the layout under other import paths. An empty UUIDPath means DefaultUUIDPath.
type Config struct {
	Root     string
	UUIDPath string
}

// DefaultUUIDPath is the import path of the uuid library the core module depends on.
const DefaultUUIDPath = "github.com/google/uuid"

// DefaultConfig is the configuration for the real repository.
func DefaultConfig() Config { return Config{Root: ModulePath, UUIDPath: DefaultUUIDPath} }

func (c Config) uuidPath() string {
	if c.UUIDPath == "" {
		return DefaultUUIDPath
	}
	return c.UUIDPath
}

// Rel returns the path of pkgPath relative to the root package ("" for the root itself) and
// whether pkgPath belongs to it.
func (c Config) Rel(pkgPath string) (string, bool) {
	if pkgPath == c.Root {
		return "", true
	}
	if rest, ok := strings.CutPrefix(pkgPath, c.Root+"/"); ok {
		return rest, true
	}
	return "", false
}

func (c Config) path(rel string) string {
	if rel == "" {
		return c.Root
	}
	return c.Root + "/" + rel
}

func (c Config) isAdapter(pkgPath string) bool {
	rel, ok := c.Rel(pkgPath)
	return ok && (rel == "adapters" || strings.HasPrefix(rel, "adapters/"))
}

func isInternalPath(pkgPath string) bool {
	return strings.HasSuffix(pkgPath, "/internal") || strings.Contains(pkgPath, "/internal/")
}

func isTestFile(name string) bool { return strings.HasSuffix(name, "_test.go") }

func (w *Workspace) roots() []*packages.Package {
	seen := map[string]bool{}
	var out []*packages.Package
	for _, m := range w.Modules {
		for _, p := range m.Pkgs {
			if strings.HasSuffix(p.PkgPath, ".test") || seen[p.ID] {
				continue
			}
			seen[p.ID] = true
			out = append(out, p)
		}
	}
	return out
}

func (w *Workspace) relPos(fset *token.FileSet, pos token.Pos) string {
	p := fset.Position(pos)
	name := p.Filename
	if rel, err := filepath.Rel(w.Root, name); err == nil && !strings.HasPrefix(rel, "..") {
		name = rel
	}
	return name + ":" + strconv.Itoa(p.Line)
}

func posInTestFile(fset *token.FileSet, pos token.Pos) bool {
	return isTestFile(fset.Position(pos).Filename)
}

type fileVisit func(pkg *packages.Package, file *ast.File, filename string)

func (w *Workspace) eachFile(includeTests bool, fn fileVisit) {
	for _, pkg := range w.roots() {
		for _, f := range pkg.Syntax {
			name := pkg.Fset.Position(f.Pos()).Filename
			if !includeTests && isTestFile(name) {
				continue
			}
			fn(pkg, f, name)
		}
	}
}

type scopeVisit func(pkg *packages.Package, obj types.Object)

func (w *Workspace) eachObject(fn scopeVisit) {
	for _, pkg := range w.roots() {
		if pkg.Types == nil || isMainPackage(pkg) {
			continue
		}
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if posInTestFile(pkg.Fset, obj.Pos()) {
				continue
			}
			fn(pkg, obj)
		}
	}
}

func recvNamed(fn *types.Func) *types.Named {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil
	}
	t := sig.Recv().Type()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, _ := t.(*types.Named)
	return n
}

func typeSymbol(n *types.Named) string {
	o := n.Obj()
	if o.Pkg() == nil {
		return o.Name()
	}
	return o.Pkg().Path() + "." + o.Name()
}

func funcSymbol(fn *types.Func) string {
	if n := recvNamed(fn); n != nil {
		return typeSymbol(n.Origin()) + "." + fn.Name()
	}
	if fn.Pkg() == nil {
		return fn.Name()
	}
	return fn.Pkg().Path() + "." + fn.Name()
}

func namedIs(t types.Type, pkgPath, name string) bool {
	n, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return false
	}
	o := n.Obj()
	return o.Pkg() != nil && o.Pkg().Path() == pkgPath && o.Name() == name
}

func derefNamed(t types.Type) *types.Named {
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	n, _ := t.(*types.Named)
	return n
}

func enclosingSymbol(pkg *packages.Package, file *ast.File, pos token.Pos) string {
	for _, d := range file.Decls {
		if pos < d.Pos() || pos > d.End() {
			continue
		}
		switch decl := d.(type) {
		case *ast.FuncDecl:
			if obj, ok := pkg.TypesInfo.Defs[decl.Name].(*types.Func); ok {
				return funcSymbol(obj)
			}
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				if pos < spec.Pos() || pos > spec.End() {
					continue
				}
				if name := specName(spec, pos); name != nil && name.Name != "_" {
					return pkg.PkgPath + "." + name.Name
				}
			}
		}
	}
	return pkg.PkgPath
}

func specName(spec ast.Spec, pos token.Pos) *ast.Ident {
	switch s := spec.(type) {
	case *ast.TypeSpec:
		return s.Name
	case *ast.ValueSpec:
		if len(s.Names) == 0 {
			return nil
		}
		if len(s.Names) == len(s.Values) {
			for i, v := range s.Values {
				if pos >= v.Pos() && pos <= v.End() {
					return s.Names[i]
				}
			}
		}
		return s.Names[0]
	}
	return nil
}

type surfaceAnchor struct {
	pkgPath string
	pos     token.Pos
	sym     string
	via     *types.TypeName
}

type surfaceType struct {
	pkg      *packages.Package
	named    *types.Named
	own      bool
	anchor   surfaceAnchor
	exposers []string
}

func (st surfaceType) label() string {
	return types.TypeString(st.named, func(p *types.Package) string { return p.Name() })
}

func (w *Workspace) locate(st surfaceType, pos token.Pos, member string) Violation {
	if !st.own {
		return Violation{Pkg: st.anchor.pkgPath, Pos: w.relPos(st.pkg.Fset, st.anchor.pos), Symbols: []string{st.anchor.sym}, Exposers: st.exposers}
	}
	sym := typeSymbol(st.named)
	if member != "" {
		sym += "." + member
	}
	return Violation{Pkg: objPkgPath(st.named.Obj()), Pos: w.relPos(st.pkg.Fset, pos), Symbols: []string{sym}, Exposers: st.exposers}
}

func hasTypeParam(t types.Type) bool {
	found := false
	seen := map[types.Type]bool{}
	var visit func(t types.Type)
	visit = func(t types.Type) {
		if found || seen[t] {
			return
		}
		seen[t] = true
		switch u := t.(type) {
		case *types.TypeParam:
			found = true
		case *types.Alias:
			visit(types.Unalias(u))
		case *types.Named:
			for i := 0; i < u.TypeArgs().Len(); i++ {
				visit(u.TypeArgs().At(i))
			}
		case *types.Pointer:
			visit(u.Elem())
		case *types.Slice:
			visit(u.Elem())
		case *types.Array:
			visit(u.Elem())
		case *types.Chan:
			visit(u.Elem())
		case *types.Map:
			visit(u.Key())
			visit(u.Elem())
		case *types.Signature:
			for _, tuple := range []*types.Tuple{u.Params(), u.Results()} {
				for i := 0; i < tuple.Len(); i++ {
					visit(tuple.At(i).Type())
				}
			}
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				visit(u.Field(i).Type())
			}
		case *types.Interface:
			for i := 0; i < u.NumMethods(); i++ {
				visit(u.Method(i).Type())
			}
			for i := 0; i < u.NumEmbeddeds(); i++ {
				visit(u.EmbeddedType(i))
			}
		case *types.Union:
			for i := 0; i < u.Len(); i++ {
				visit(u.Term(i).Type())
			}
		}
	}
	visit(t)
	return found
}

type externalKey struct {
	obj     *types.TypeName
	pkgPath string
	via     *types.TypeName
}

type surfaceWalker struct {
	own         map[string]bool
	external    bool
	emitted     map[*types.TypeName]bool
	instances   map[string]bool
	externals   map[externalKey]bool
	exposers    map[*types.TypeName]map[string]bool
	root        string
	visited     map[*types.TypeName]bool
	visitedInst map[string]bool
	out         []surfaceType
}

func (s *surfaceWalker) walk(pkg *packages.Package, t types.Type, at surfaceAnchor) {
	switch u := t.(type) {
	case *types.Alias:
		s.walk(pkg, types.Unalias(u), at)
	case *types.Named:
		s.walkNamed(pkg, u, at)
	case *types.Pointer:
		s.walk(pkg, u.Elem(), at)
	case *types.Slice:
		s.walk(pkg, u.Elem(), at)
	case *types.Array:
		s.walk(pkg, u.Elem(), at)
	case *types.Chan:
		s.walk(pkg, u.Elem(), at)
	case *types.Map:
		s.walk(pkg, u.Key(), at)
		s.walk(pkg, u.Elem(), at)
	case *types.Signature:
		for _, tuple := range []*types.Tuple{u.Params(), u.Results()} {
			for i := 0; i < tuple.Len(); i++ {
				s.walk(pkg, tuple.At(i).Type(), at)
			}
		}
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if f := u.Field(i); f.Exported() || f.Embedded() {
				s.walk(pkg, f.Type(), at)
			}
		}
	case *types.Interface:
		for i := 0; i < u.NumMethods(); i++ {
			if m := u.Method(i); m.Exported() {
				s.walk(pkg, m.Type(), at)
			}
		}
		for i := 0; i < u.NumEmbeddeds(); i++ {
			s.walk(pkg, u.EmbeddedType(i), at)
		}
	}
}

func (s *surfaceWalker) walkNamed(pkg *packages.Package, u *types.Named, at surfaceAnchor) {
	for i := 0; i < u.TypeArgs().Len(); i++ {
		s.walk(pkg, u.TypeArgs().At(i), at)
	}
	origin := u.Origin()
	obj := origin.Obj()
	if obj.Pkg() == nil || posInTestFile(pkg.Fset, obj.Pos()) {
		return
	}
	isOwn := s.own[obj.Pkg().Path()]
	typeAt := at
	if isOwn {
		typeAt = surfaceAnchor{pkgPath: obj.Pkg().Path(), pos: obj.Pos(), sym: typeSymbol(origin), via: obj}
		if s.exposers[obj] == nil {
			s.exposers[obj] = map[string]bool{}
		}
		s.exposers[obj][s.root] = true
		if !s.visited[obj] {
			s.visited[obj] = true
			if !s.emitted[obj] {
				s.emitted[obj] = true
				s.out = append(s.out, surfaceType{pkg: pkg, named: origin, own: true, anchor: typeAt})
			}
			s.walkMembers(pkg, origin, typeAt, true)
		}
	}
	switch {
	case u != origin && u.TypeArgs().Len() > 0 && !hasTypeParam(u):
		key := types.TypeString(u, nil)
		if !isOwn {
			key += "|" + typeAt.sym
		}
		if !s.instances[key] {
			s.instances[key] = true
			s.out = append(s.out, surfaceType{pkg: pkg, named: u, own: isOwn, anchor: typeAt})
		}
		if !s.visitedInst[key] {
			s.visitedInst[key] = true
			s.walkMembers(pkg, u, typeAt, isOwn)
		}
	case !isOwn && s.external && u.TypeArgs().Len() == 0 && !isHandlerType(u):
		key := externalKey{obj: obj, pkgPath: at.pkgPath, via: at.via}
		if s.externals[key] {
			return
		}
		s.externals[key] = true
		s.out = append(s.out, surfaceType{pkg: pkg, named: u, anchor: at})
		s.walkMembers(pkg, u, at, false)
	}
}

func (s *surfaceWalker) walkMembers(pkg *packages.Package, n *types.Named, at surfaceAnchor, isOwn bool) {
	member := func(pos token.Pos, name string) surfaceAnchor {
		if !isOwn {
			return at
		}
		return surfaceAnchor{pkgPath: objPkgPath(n.Obj()), pos: pos, sym: typeSymbol(n) + "." + name, via: n.Obj()}
	}
	if st, ok := n.Underlying().(*types.Struct); ok {
		for i := 0; i < st.NumFields(); i++ {
			if f := st.Field(i); f.Exported() || f.Embedded() {
				s.walk(pkg, f.Type(), member(f.Pos(), f.Name()))
			}
		}
	} else {
		s.walk(pkg, n.Underlying(), at)
	}
	for _, m := range exportedMethods(n) {
		s.walk(pkg, m.Type(), member(m.Pos(), m.Name()))
	}
}

func isMainPackage(p *packages.Package) bool { return p.Name == "main" }

func (w *Workspace) surfaceTypes(fromInternal, external bool) []surfaceType {
	s := &surfaceWalker{
		own:       map[string]bool{},
		external:  external,
		emitted:   map[*types.TypeName]bool{},
		instances: map[string]bool{},
		externals: map[externalKey]bool{},
		exposers:  map[*types.TypeName]map[string]bool{},
	}
	for _, p := range w.roots() {
		s.own[p.PkgPath] = true
	}
	for _, pkg := range w.roots() {
		if pkg.Types == nil || isMainPackage(pkg) || (!fromInternal && isInternalPath(pkg.PkgPath)) {
			continue
		}
		s.root, s.visited, s.visitedInst = pkg.PkgPath, map[*types.TypeName]bool{}, map[string]bool{}
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if !obj.Exported() || posInTestFile(pkg.Fset, obj.Pos()) {
				continue
			}
			switch obj.(type) {
			case *types.TypeName, *types.Func, *types.Var:
				s.walk(pkg, obj.Type(), surfaceAnchor{pkgPath: pkg.PkgPath, pos: obj.Pos(), sym: pkg.PkgPath + "." + obj.Name()})
			}
		}
	}
	for i := range s.out {
		st := &s.out[i]
		if st.anchor.via == nil {
			continue
		}
		for p := range s.exposers[st.anchor.via] {
			if p != st.anchor.pkgPath {
				st.exposers = append(st.exposers, p)
			}
		}
		slices.Sort(st.exposers)
	}
	return s.out
}

func objPkgPath(obj types.Object) string {
	if obj.Pkg() == nil {
		return ""
	}
	return obj.Pkg().Path()
}
