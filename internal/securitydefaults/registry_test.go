package securitydefaults

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// scannedPackages are the handler families whose exported constructors the guard enumerates.
// A new handler added to any of these packages must be registered in handlerRegistry below.
var scannedPackages = []string{
	"authflow",
	"identity",
	"mfa",
	"oauth",
	"otp",
	"passkey",
	"sessions",
	"tokens",
	"tokens/basic",
	// webapp is the composition preset the quick-start hands a consumer, so it builds the
	// endpoints most deployments actually expose. Its constructor returns (http.Handler, error),
	// which returnsHTTPHandler matches once the multi-value result is unwrapped.
	"webapp",
	// origin and ratelimit export middleware constructors: they wrap an application's own routes,
	// so the control they apply (or decline to apply) is a default every route behind them inherits.
	"origin",
	"ratelimit",
}

// handlerRecord documents one exported handler constructor: whether it builds a state-changing
// handler and the default security control it applies (with the opt-out named in .llms).
type handlerRecord struct {
	mutation bool
	control  string
}

// handlerRegistry is the maintained inventory of every exported handler constructor in
// scannedPackages. TestExportedHandlerConstructorsAreRegistered fails when the source gains an
// exported constructor that is missing here (or when a registered constructor is removed), so a
// new endpoint cannot silently ship without the family's default control being reviewed.
var handlerRegistry = map[string]handlerRecord{
	// authflow
	"authflow.StepUpHandler": {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; signed flow-token verification"},

	// identity: POST-only form handlers, all gated by the same preamble.
	"identity.LoginHandler":                           {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.RegisterHandler":                        {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.RequestPasswordResetHandler":            {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.ResetPasswordHandler":                   {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.RequestEmailVerificationHandler":        {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.VerifyEmailHandler":                     {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.RequestMagicLinkHandler":                {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.MagicLinkLoginHandler":                  {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.ChangePasswordHandler":                  {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.ChangePasswordWithReissueHandler":       {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.RequestEmailChangeHandler":              {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.ConfirmEmailChangeHandler":              {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.DeleteAccountHandler":                   {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.RequestPhoneVerificationHandler":        {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.ConfirmPhoneVerificationHandler":        {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.RequestRecoveryEmailHandler":            {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.ConfirmRecoveryEmailHandler":            {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.RequestPasswordResetViaRecoveryHandler": {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},

	// mfa: all handlers share the guarded() preamble.
	"mfa.EnrollHandler":                  {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"mfa.ConfirmHandler":                 {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"mfa.VerifyHandler":                  {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"mfa.VerifyRecoveryHandler":          {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"mfa.RegenerateRecoveryCodesHandler": {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"mfa.DisableHandler":                 {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; step-up AMR gate; tenant resolver fails closed"},
	"mfa.StepUpHandler":                  {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},

	// oauth: GET flows protected by the signed state cookie instead of the origin gate.
	"oauth.BeginHandler":           {mutation: false, control: "HMAC-signed __Host- state cookie; PKCE by default; tenant resolver fails closed"},
	"oauth.CallbackHandler":        {mutation: true, control: "HMAC-signed __Host- state cookie; PKCE; provider/tenant binding; tenant resolver fails closed"},
	"oauth.DynamicBeginHandler":    {mutation: false, control: "HMAC-signed __Host- state cookie; PKCE by default; tenant resolver fails closed"},
	"oauth.DynamicCallbackHandler": {mutation: true, control: "HMAC-signed __Host- state cookie; PKCE; provider/tenant binding; tenant resolver fails closed"},

	// otp: both handlers share the guarded preamble.
	"otp.IssueHandler":  {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"otp.VerifyHandler": {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},

	// passkey: ceremony handlers rely on the sealed __Host- ceremony cookie and the single-use
	// challenge store; RenameCredentialHandler adds the origin gate.
	"passkey.BeginRegistrationHandler":       {mutation: true, control: "HMAC-sealed __Host- ceremony cookie; single-use challenge store"},
	"passkey.FinishRegistrationHandler":      {mutation: true, control: "HMAC-sealed __Host- ceremony cookie; single-use challenge store; body cap"},
	"passkey.BeginLoginHandler":              {mutation: true, control: "HMAC-sealed __Host- ceremony cookie; single-use challenge store"},
	"passkey.FinishLoginHandler":             {mutation: true, control: "HMAC-sealed __Host- ceremony cookie; single-use challenge store; body cap"},
	"passkey.BeginDiscoverableLoginHandler":  {mutation: true, control: "HMAC-sealed __Host- ceremony cookie; single-use challenge store"},
	"passkey.FinishDiscoverableLoginHandler": {mutation: true, control: "HMAC-sealed __Host- ceremony cookie; single-use challenge store; body cap"},
	"passkey.RenameCredentialHandler":        {mutation: true, control: "same-origin CSRF gate; application/json required; body cap"},

	// sessions: the session-authenticating middleware.
	"sessions.RequireSession": {mutation: true, control: "cookie-auth unsafe-method same-origin gate (Bearer exempt); __Host- session cookie; tenant resolver fails closed"},

	// tokens: cookie-driven handlers and the verification middleware.
	// webapp is a composition preset: it mounts the identity register/login handlers and the tokens
	// refresh/logout handlers, so it inherits their controls and adds its own construction-time
	// requirements. Refresh rotates the family and writes cookies, so the preset as a whole mutates.
	"webapp.NewWebApp": {mutation: true, control: "refuses to build without TrustedOrigins (CSRF-by-default) and rejects TrustedOrigins+InsecureNoOriginCheck; per-client-IP rate limit ON (burst 20, refill 6s, InsecureNoRateLimit opt-out); cookie configuration validated at construction; non-nil slog event sink"},

	// Middleware constructors: they wrap an application's OWN routes, so the control they apply — or
	// decline to apply — is a default every route behind them inherits.
	"origin.Middleware":    {mutation: true, control: "strict same-origin check ON for every unsafe method by default (empty allowlist = same-host only; a request with neither Origin nor Referer is rejected); InsecureNoOriginCheck is the explicit opt-out"},
	"ratelimit.Middleware": {mutation: false, control: "denies by default once the limiter refuses; KeyFunc defaults to ratelimit.ClientIP, which does NOT trust X-Forwarded-For; widen by passing a permissive limiter"},
	"ratelimit.Wrap":       {mutation: false, control: "same policy as ratelimit.Middleware, for a single http.HandlerFunc"},

	"tokens.RefreshHandler": {mutation: true, control: "same-origin CSRF gate (cookie-driven POST)"},
	"tokens.LogoutHandler":  {mutation: true, control: "same-origin CSRF gate (cookie-driven POST)"},
	// mutation is true for both: with WithAutoRefresh they rotate the refresh family and rewrite
	// the auth cookies on a request that arrived without a usable access token, so a route behind
	// them can change server-side state. The gate matrix itself is non-mutating.
	"tokens.RequireAuth":       {mutation: true, control: "access-token verification; tenant resolver fails closed (401); opt-in auto-refresh rotates the family and rewrites cookies"},
	"tokens.ContextMiddleware": {mutation: true, control: "access-token verification; tenant resolver fails closed (401); opt-in auto-refresh rotates the family and rewrites cookies"},

	// tokens/basic: the C=struct{} facade over the tokens constructors.
	"basic.RefreshHandler":    {mutation: true, control: "same-origin CSRF gate (cookie-driven POST)"},
	"basic.LogoutHandler":     {mutation: true, control: "same-origin CSRF gate (cookie-driven POST)"},
	"basic.RequireAuth":       {mutation: false, control: "access-token verification; tenant resolver fails closed (401)"},
	"basic.ContextMiddleware": {mutation: false, control: "access-token verification; tenant resolver fails closed (401)"},
}

// TestExportedHandlerConstructorsAreRegistered is the guard: every exported constructor in the
// scanned handler packages that returns an http.Handler/http.HandlerFunc must appear in
// handlerRegistry, and every registry entry must still exist in the source.
func TestExportedHandlerConstructorsAreRegistered(t *testing.T) {
	root := repoRoot(t)
	var found []string
	for _, pkg := range scannedPackages {
		found = append(found, scanHandlerConstructors(t, root, pkg)...)
	}
	if len(found) == 0 {
		t.Fatal("guard scanned no handler constructors; the scan paths are wrong")
	}
	for _, problem := range registryProblems(found) {
		t.Error(problem)
	}
}

// TestRegistryGuardRejectsUnregisteredHandler demonstrates the registry is enforced: a synthetic
// constructor that is not registered (as a newly added handler would be) is reported by the same
// check the guard runs above.
func TestRegistryGuardRejectsUnregisteredHandler(t *testing.T) {
	problems := registryProblems([]string{"otp.FakeUnregisteredHandler"})
	if len(problems) == 0 {
		t.Fatal("an exported handler constructor outside handlerRegistry must fail the guard")
	}
	if !containsProblemAbout(problems, "otp.FakeUnregisteredHandler") {
		t.Fatalf("guard must name the unregistered constructor, got %v", problems)
	}
}

// TestRegistryRecordsMutationControls keeps the registry honest: every mutation handler must
// record a non-empty default control.
func TestRegistryRecordsMutationControls(t *testing.T) {
	mutations := 0
	for name, rec := range handlerRegistry {
		if !rec.mutation {
			continue
		}
		mutations++
		if strings.TrimSpace(rec.control) == "" {
			t.Errorf("mutation handler %s records no default control", name)
		}
	}
	if mutations == 0 {
		t.Fatal("handlerRegistry must account for the mutation handlers")
	}
}

// registryProblems compares the constructors found in source with handlerRegistry and returns a
// human-readable problem per mismatch. Findings in the registry that no longer exist and mutation
// entries without a recorded control are also problems.
func registryProblems(found []string) []string {
	var problems []string
	foundSet := make(map[string]bool, len(found))
	for _, name := range found {
		foundSet[name] = true
		if _, ok := handlerRegistry[name]; !ok {
			problems = append(problems, fmt.Sprintf(
				"exported handler constructor %s is not registered in handlerRegistry: add it with the default security control it applies (and its opt-out) before merging", name))
		}
	}
	registered := make([]string, 0, len(handlerRegistry))
	for name := range handlerRegistry {
		registered = append(registered, name)
	}
	sort.Strings(registered)
	for _, name := range registered {
		if !foundSet[name] {
			problems = append(problems, fmt.Sprintf(
				"handlerRegistry lists %s but no exported handler constructor with that name exists anymore: update the registry", name))
		}
		if rec := handlerRegistry[name]; rec.mutation && strings.TrimSpace(rec.control) == "" {
			problems = append(problems, fmt.Sprintf("handlerRegistry entry %s is a mutation handler but records no control", name))
		}
	}
	return problems
}

// scanHandlerConstructors returns the sorted "pkg.Func" names of every exported package-level
// function in root/pkg whose results include http.Handler or http.HandlerFunc. Test files are
// skipped and methods are ignored, so helpers on config types are never flagged.
func scanHandlerConstructors(t *testing.T, root, pkg string) []string {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(pkg))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading handler package %s: %v", pkg, err)
	}
	fset := token.NewFileSet()
	var found []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s/%s: %v", pkg, name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() {
				continue
			}
			if returnsHTTPHandler(fn.Type.Results) {
				found = append(found, filepath.Base(pkg)+"."+fn.Name.Name)
			}
		}
	}
	sort.Strings(found)
	return found
}

// returnsHTTPHandler reports whether a function result list contains a selector of the form
// http.Handler or http.HandlerFunc.
// returnsHTTPHandler reports whether a function returns an http.Handler/http.HandlerFunc, either
// directly or as the result of a curried middleware: origin.Middleware returns
// func(http.Handler) http.Handler, and a consumer calls the inner function to wrap a route. Both
// shapes decide a control for every route they touch, so both belong in the registry.
func returnsHTTPHandler(results *ast.FieldList) bool {
	if results == nil {
		return false
	}
	for _, field := range results.List {
		if isHTTPHandlerType(field.Type) || isHandlerMiddlewareType(field.Type) {
			return true
		}
	}
	return false
}

// isHandlerMiddlewareType reports whether a type expression is func(http.Handler) http.Handler.
func isHandlerMiddlewareType(e ast.Expr) bool {
	fn, ok := e.(*ast.FuncType)
	if !ok {
		return false
	}
	if fn.Params == nil || len(fn.Params.List) != 1 || !isHTTPHandlerType(fn.Params.List[0].Type) {
		return false
	}
	return fn.Results != nil && len(fn.Results.List) == 1 && isHTTPHandlerType(fn.Results.List[0].Type)
}

// isHTTPHandlerType reports whether a type expression is http.Handler or http.HandlerFunc, unwrapping
// the parenthesised and generic forms that appear in real signatures.
func isHTTPHandlerType(e ast.Expr) bool {
	switch node := e.(type) {
	case *ast.ParenExpr:
		return isHTTPHandlerType(node.X)
	case *ast.SelectorExpr:
		ident, ok := node.X.(*ast.Ident)
		if !ok || ident.Name != "http" {
			return false
		}
		return node.Sel.Name == "Handler" || node.Sel.Name == "HandlerFunc"
	}
	return false
}

// repoRoot returns the module root (the parent of internal/) from this test file's location.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(file)))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s: %v", root, err)
	}
	return root
}

func containsProblemAbout(problems []string, name string) bool {
	for _, p := range problems {
		if strings.Contains(p, name) {
			return true
		}
	}
	return false
}
