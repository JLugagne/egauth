package archtest

import (
	"go/ast"
	"go/types"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"
)

// ObjRef names a Go object for the single-owner table. Exactly one of Ext, Rel and PathContains
// selects the package: Ext is an absolute import path, Rel is relative to the root package ("*"
// stands for every package under the root) and PathContains matches any package whose import path
// contains the text. Name is "Func", "Var", "Type" or "Type.Member"; a trailing "*" makes it a
// prefix and a leading "*." matches the member of any type of the package.
type ObjRef struct {
	Ext          string
	Rel          string
	PathContains string
	Name         string
}

// OwnerRow is one row of the DESIGN.md section 9.2 single-owner table: the objects, literals and
// composite literals that only Owners may use in non-test code.
//
// An owner is a package path relative to the root package. "<path>/..." covers the package and its
// subtree, a "*" segment matches any one directory, and "<path>.<Func>" (empty path for the root
// package) names one top-level function.
type OwnerRow struct {
	ID           string
	Objects      []ObjRef
	Composites   []ObjRef
	Literals     []string
	ExactLiteral []string
	Owners       []string
	custom       func(c *ownerCtx, n ast.Node) string
}

type ownerCtx struct {
	info        *types.Info
	cfg         Config
	ws          *Workspace
	pkg         *packages.Package
	file        *ast.File
	tainted     map[types.Object]bool
	kek         *types.Named
	kekResolved bool
	shared      *ownerShared
}

const (
	pathHTTP = "net/http"
	pathTime = "time"
)

// OwnerRows returns the single-owner table of DESIGN.md section 9.2. The set is fixed by the spec
// and pinned by a test; it is not an exemption list.
func OwnerRows() []OwnerRow {
	return slices.Clone(ownerRows)
}

var ownerRows = []OwnerRow{
	{
		ID: "cookie",
		Objects: []ObjRef{
			{Ext: pathHTTP, Name: "SetCookie"},
			{Ext: pathHTTP, Name: "Request.Cookie"},
			{Ext: pathHTTP, Name: "Request.Cookies"},
		},
		Owners: []string{"internal/cookie"},
	},
	{
		ID:       "clientaddr",
		Objects:  []ObjRef{{Ext: pathHTTP, Name: "Request.RemoteAddr"}},
		Literals: []string{"X-Forwarded-For", "Forwarded", "X-Real-Ip"},
		Owners:   []string{"internal/clientaddr"},
	},
	{
		ID: "httpx",
		Objects: []ObjRef{
			{Ext: pathHTTP, Name: "MaxBytesReader"},
			{Ext: pathHTTP, Name: "Request.ParseForm"},
			{Ext: pathHTTP, Name: "Request.ParseMultipartForm"},
			{Ext: pathHTTP, Name: "Request.FormValue"},
			{Ext: pathHTTP, Name: "Request.PostFormValue"},
		},
		custom: jsonDecoderOnBody,
		Owners: []string{"internal/httpx"},
	},
	{
		ID:       "csrf",
		Literals: []string{"Origin", "Referer", "Sec-Fetch-*"},
		Owners:   []string{"internal/csrf"},
	},
	{
		ID: "outbound",
		Composites: []ObjRef{
			{Ext: pathHTTP, Name: "Client"},
			{Ext: pathHTTP, Name: "Transport"},
		},
		Objects: []ObjRef{
			{Ext: pathHTTP, Name: "DefaultClient"},
			{Ext: pathHTTP, Name: "DefaultTransport"},
			{Ext: pathHTTP, Name: "Get"},
			{Ext: pathHTTP, Name: "Post"},
			{Ext: pathHTTP, Name: "PostForm"},
			{Ext: pathHTTP, Name: "Head"},
		},
		custom: zeroOutboundValue,
		Owners: []string{"internal/outbound"},
	},
	{
		ID: "ctxvalue",
		Objects: []ObjRef{
			{Ext: "context", Name: "WithValue"},
			{Ext: "context", Name: "Context.Value"},
		},
		Owners: []string{"internal/principalctx"},
	},
	{
		ID:     "kek",
		custom: kekSealOrOpen,
		Owners: []string{"internal/sealing", ".UpgradeSecretsV016"},
	},
	{
		ID:      "audit",
		Objects: []ObjRef{{Rel: "event", Name: "Sink.Emit*"}},
		Owners:  []string{"internal/audit"},
	},
	{
		ID: "producers",
		Objects: []ObjRef{
			{Rel: "internal/core", Name: "NewPending"},
			{Rel: "internal/core", Name: "PendingForReauth"},
			{Rel: "internal/core", Name: "Pending.Add"},
			{Rel: "internal/core", Name: "Admit"},
			{Rel: "internal/core", Name: "Reauthenticate"},
			{Rel: "internal/core", Name: "FactorEnrolled"},
			{Rel: "internal/core", Name: "PasswordChanged"},
			{Rel: "internal/core", Name: "NewMFADecision"},
		},
		Owners: []string{"internal/issuance"},
	},
	{
		ID:      "renew",
		Objects: []ObjRef{{Rel: "internal/core", Name: "Renew"}},
		Owners:  []string{"internal/session/..."},
	},
	{
		ID:      "unseal",
		Objects: []ObjRef{{Rel: "internal/core", Name: "Unseal"}},
		Owners:  []string{"internal/session/...", "internal/issuance", "internal/flow"},
	},
	{
		ID:      "accountstate",
		Objects: []ObjRef{{Rel: "internal/core", Name: "NewAccountState"}},
		Owners:  []string{"internal/identitysvc"},
	},
	{
		ID:      "verified",
		Objects: []ObjRef{{Rel: "internal/core", Name: "NewVerified"}},
		Owners:  []string{"internal/factors"},
	},
	{
		ID:      "backendstart",
		Objects: []ObjRef{{Rel: "internal/session", Name: "Backend.Start"}},
		Owners:  []string{"internal/issuance", "internal/flow"},
	},
	{
		ID:      "backendreissue",
		Objects: []ObjRef{{Rel: "internal/session", Name: "Backend.Reissue"}},
		Owners:  []string{"internal/issuance"},
	},
	{
		ID: "clock",
		Objects: []ObjRef{
			{Ext: pathTime, Name: "Now"},
			{Ext: pathTime, Name: "Since"},
			{Ext: pathTime, Name: "Until"},
		},
		Owners: []string{"internal/clock"},
	},
	{
		ID: "jwt",
		Objects: []ObjRef{
			{PathContains: "github.com/golang-jwt/jwt/", Name: "Parse*"},
			{PathContains: "github.com/golang-jwt/jwt/", Name: "New*"},
			{PathContains: "github.com/golang-jwt/jwt/", Name: "Parser.*"},
			{PathContains: "github.com/golang-jwt/jwt/", Name: "Token.Sign*"},
			{PathContains: "github.com/golang-jwt/jwt/", Name: "SigningMethod*"},
			{PathContains: "github.com/golang-jwt/jwt/", Name: "GetSigningMethod"},
			{PathContains: "github.com/golang-jwt/jwt/", Name: "RegisterSigningMethod"},
			{PathContains: "github.com/golang-jwt/jwt/", Name: "*.Sign*"},
			{PathContains: "github.com/golang-jwt/jwt/", Name: "*.Verify*"},
		},
		ExactLiteral: []string{"amr"},
		Owners:       []string{"internal/session/jwt"},
	},
	{
		ID:         "redirect",
		Composites: []ObjRef{{Rel: "internal/redirect", Name: "Target"}},
		Owners:     []string{"internal/redirect"},
	},
	{
		ID: "newrecords",
		Objects: []ObjRef{
			{Rel: "store/tokens", Name: "NewRefreshRecord"},
			{Rel: "store/sessions", Name: "NewRecord"},
			{Rel: "store/ceremony", Name: "NewRecord"},
		},
		Owners: []string{"internal/session/...", "internal/issuance", "internal/flow", "internal/*svc"},
	},
	{
		ID:      "restore",
		Objects: []ObjRef{{Rel: "*", Name: "Restore*"}},
		Owners:  []string{"store/*/memory/...", "adapters/pgx/store/..."},
	},
	{
		ID:      "fortest",
		Objects: []ObjRef{{Rel: "internal/core", Name: "ForTest*"}},
		Owners:  []string{"internal/principaltest/..."},
	},
	{
		ID:     "normalise",
		custom: identifierNormalisation,
		Owners: []string{"internal/identitysvc"},
	},
	{
		ID:      "totp",
		Objects: []ObjRef{{PathContains: "github.com/pquerna/otp/totp", Name: "Validate*"}},
		Owners:  []string{"internal/mfasvc"},
	},
}

func (r ObjRef) matchesPkg(cfg Config, pkgPath string) bool {
	switch {
	case r.Ext != "":
		return pkgPath == r.Ext
	case r.PathContains != "":
		return strings.Contains(pkgPath+"/", r.PathContains)
	case r.Rel == "*":
		_, ok := cfg.Rel(pkgPath)
		return ok
	}
	return pkgPath == cfg.path(r.Rel)
}

func (r ObjRef) matchesName(key string) bool {
	pattern := r.Name
	if member, ok := strings.CutPrefix(pattern, "*."); ok {
		_, keyMember, isMember := strings.Cut(key, ".")
		if !isMember {
			return false
		}
		pattern, key = member, keyMember
	}
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(key, prefix)
	}
	return key == pattern
}

func (r ObjRef) matches(cfg Config, pkgPath, key string) bool {
	return r.matchesPkg(cfg, pkgPath) && r.matchesName(key)
}

func matchOwnerPath(pattern, rel string) bool {
	if base, ok := strings.CutSuffix(pattern, "/..."); ok {
		for anc := rel; ; {
			if matchGlob(base, anc) {
				return true
			}
			i := strings.LastIndex(anc, "/")
			if i < 0 {
				return false
			}
			anc = anc[:i]
		}
	}
	return matchGlob(pattern, rel)
}

func matchGlob(pattern, name string) bool {
	ps, ns := strings.Split(pattern, "/"), strings.Split(name, "/")
	if len(ps) != len(ns) {
		return false
	}
	for i, p := range ps {
		if !globSegment(p, ns[i]) {
			return false
		}
	}
	return true
}

func globSegment(p, s string) bool {
	if p == "*" {
		return true
	}
	if strings.HasPrefix(p, "*") {
		return strings.HasSuffix(s, p[1:])
	}
	return p == s
}

func isSymbolOwner(owner string) bool {
	slash := strings.LastIndex(owner, "/")
	return strings.Contains(owner[slash+1:], ".") && !strings.HasSuffix(owner, "/...")
}

func splitSymbolOwner(owner string) (rel, name string) {
	slash := strings.LastIndex(owner, "/")
	dot := strings.Index(owner[slash+1:], ".") + slash + 1
	return owner[:dot], owner[dot+1:]
}

func objectKey(info *types.Info, sel *ast.SelectorExpr, obj types.Object) (pkgPath, key string, ok bool) {
	if obj == nil || obj.Pkg() == nil {
		return "", "", false
	}
	if s := info.Selections[sel]; s != nil {
		switch o := s.Obj().(type) {
		case *types.Func:
			if n := recvNamed(o); n != nil {
				return objPkgPath(n.Obj()), n.Obj().Name() + "." + o.Name(), true
			}
		case *types.Var:
			if n := fieldOwner(s); n != nil {
				return objPkgPath(n.Obj()), n.Obj().Name() + "." + o.Name(), true
			}
		}
		return "", "", false
	}
	switch o := obj.(type) {
	case *types.Var:
		if o.IsField() {
			return "", "", false
		}
	case *types.Func:
		if recvNamed(o) != nil {
			return "", "", false
		}
	}
	if obj.Parent() != obj.Pkg().Scope() {
		return "", "", false
	}
	return obj.Pkg().Path(), obj.Name(), true
}

func fieldOwner(s *types.Selection) *types.Named {
	t := s.Recv()
	idx := s.Index()
	for i := 0; i < len(idx)-1; i++ {
		n := derefNamed(t)
		if n == nil {
			return nil
		}
		st, ok := n.Underlying().(*types.Struct)
		if !ok {
			return nil
		}
		t = st.Field(idx[i]).Type()
	}
	n := derefNamed(t)
	if n == nil {
		return nil
	}
	return n.Origin()
}

func jsonDecoderOnBody(c *ownerCtx, n ast.Node) string {
	call, ok := n.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	fn, ok := c.info.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "encoding/json" || fn.Name() != "NewDecoder" {
		return ""
	}
	if c.carriesBody(call.Args[0]) {
		return "json.NewDecoder on a request body"
	}
	return ""
}

func isRequestBody(info *types.Info, e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Body" {
		return false
	}
	s := info.Selections[sel]
	if s == nil {
		return false
	}
	n := fieldOwner(s)
	return n != nil && namedIs(n, pathHTTP, "Request")
}

func (c *ownerCtx) carriesBody(e ast.Expr) bool {
	if c.tainted == nil {
		c.tainted = bodyTaint(c.info, c.file)
	}
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if found {
			return false
		}
		switch x := n.(type) {
		case *ast.SelectorExpr:
			found = isRequestBody(c.info, x)
		case *ast.Ident:
			found = c.tainted[c.info.Uses[x]]
		}
		return !found
	})
	return found
}

func bodyTaint(info *types.Info, file *ast.File) map[types.Object]bool {
	tainted := map[types.Object]bool{}
	carries := func(e ast.Expr) bool {
		found := false
		ast.Inspect(e, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				found = found || isRequestBody(info, x)
			case *ast.Ident:
				found = found || tainted[info.Uses[x]]
			}
			return !found
		})
		return found
	}
	mark := func(lhs []ast.Expr, rhs []ast.Expr) bool {
		changed := false
		for _, r := range rhs {
			if !carries(r) {
				continue
			}
			for _, l := range lhs {
				id, ok := ast.Unparen(l).(*ast.Ident)
				if !ok {
					continue
				}
				obj := info.ObjectOf(id)
				if obj != nil && !tainted[obj] {
					tainted[obj] = true
					changed = true
				}
			}
		}
		return changed
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				changed = mark(x.Lhs, x.Rhs) || changed
			case *ast.ValueSpec:
				lhs := make([]ast.Expr, len(x.Names))
				for i, id := range x.Names {
					lhs[i] = id
				}
				changed = mark(lhs, x.Values) || changed
			}
			return true
		})
	}
	return tainted
}

func isOutboundValue(t types.Type) bool {
	return namedIs(t, pathHTTP, "Client") || namedIs(t, pathHTTP, "Transport")
}

func zeroOutboundValue(c *ownerCtx, n ast.Node) string {
	switch x := n.(type) {
	case *ast.CallExpr:
		id, ok := ast.Unparen(x.Fun).(*ast.Ident)
		if !ok || len(x.Args) != 1 {
			return ""
		}
		if b, ok := c.info.Uses[id].(*types.Builtin); ok && b.Name() == "new" && isOutboundValue(c.info.TypeOf(x.Args[0])) {
			return "new of an http.Client or http.Transport"
		}
	case *ast.ValueSpec:
		if x.Type != nil && isOutboundValue(c.info.TypeOf(x.Type)) {
			return "variable of type http.Client or http.Transport"
		}
	case *ast.Field:
		if isOutboundValue(c.info.TypeOf(x.Type)) {
			return "field of type http.Client or http.Transport"
		}
	}
	return ""
}

func findImported(p *types.Package, path string) *types.Package {
	seen := map[*types.Package]bool{}
	queue := []*types.Package{p}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.Path() == path {
			return cur
		}
		for _, imp := range cur.Imports() {
			if !seen[imp] {
				seen[imp] = true
				queue = append(queue, imp)
			}
		}
	}
	return nil
}

func kekSealOrOpen(c *ownerCtx, n ast.Node) string {
	sel, ok := n.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Seal" && sel.Sel.Name != "Open") {
		return ""
	}
	s := c.info.Selections[sel]
	if s == nil || (s.Kind() != types.MethodVal && s.Kind() != types.MethodExpr) {
		return ""
	}
	kekPath := c.cfg.path("kek")
	if c.pkg.PkgPath == kekPath {
		return ""
	}
	kp := findImported(c.pkg.Types, kekPath)
	if kp == nil {
		return ""
	}
	tn, ok := kp.Scope().Lookup("KEK").(*types.TypeName)
	if !ok {
		return ""
	}
	kekIface, ok := tn.Type().Underlying().(*types.Interface)
	if !ok {
		return ""
	}
	recv := s.Recv()
	if it, ok := recv.Underlying().(*types.Interface); ok {
		if types.Implements(tn.Type(), it) {
			return "kek.KEK " + sel.Sel.Name + " through " + types.TypeString(recv, nil)
		}
		return ""
	}
	if s.Obj().Pkg() == c.pkg.Types {
		return ""
	}
	if types.Implements(recv, kekIface) || types.Implements(types.NewPointer(recv), kekIface) {
		return "kek.KEK " + sel.Sel.Name + " on the implementation " + types.TypeString(recv, nil)
	}
	return ""
}

var normalisers = map[string]bool{"ToLower": true, "ToUpper": true, "ToTitle": true, "ToValidUTF8": true}

func identifierNormalisation(c *ownerCtx, n ast.Node) string {
	info := c.info
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return ""
	}
	switch p := fn.Pkg().Path(); {
	case p == "strings" && normalisers[fn.Name()]:
	case p == "golang.org/x/text/unicode/norm" && recvNamed(fn) != nil:
	default:
		return ""
	}
	for _, arg := range call.Args {
		if carriesIdentifier(info, arg) {
			return "normalisation of an identity.Identifier"
		}
	}
	return ""
}

func carriesIdentifier(info *types.Info, e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		x, ok := n.(ast.Expr)
		if !ok || found {
			return !found
		}
		if nm, ok := types.Unalias(info.TypeOf(x)).(*types.Named); ok {
			o := nm.Obj()
			if o.Name() == "Identifier" && o.Pkg() != nil && o.Pkg().Name() == "identity" {
				found = true
			}
		}
		return !found
	})
	return found
}
