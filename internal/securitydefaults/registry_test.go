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
// handler, the default security control it applies (with the opt-out), and — for the
// credential-enrollment surfaces — the fail-closed control applied when the caller supplies no
// assurance wiring.
type handlerRecord struct {
	mutation bool
	control  string
	// credentialEnrollment marks constructors that hand out or upgrade credential material
	// (passkey/mfa enrollment, identity recovery channels, MFA step-up). Such a surface must
	// record the fail-closed control it applies when the caller supplies no assurance wiring,
	// and the explicit opt-out, so a removed default is visible in review.
	credentialEnrollment bool
	// defaultControl is the control applied with no assurance wiring. It is required (and
	// guarded) for every credentialEnrollment record so a removed fail-closed default is
	// visible in review instead of silently disappearing.
	defaultControl string
	// optOut names the documented escape hatch that disables defaultControl.
	optOut string
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
	"identity.RequestEmailChangeHandler":              {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed", credentialEnrollment: true, defaultControl: "tokens.DenyInterim (403 assurance_required when an interim pre-MFA session is present; token-less sessions pass)", optOut: "WithInsecureNoAssuranceCheck; WithCredentialAssurance supplies an explicit gate"},
	"identity.ConfirmEmailChangeHandler":              {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed", credentialEnrollment: true, defaultControl: "tokens.DenyInterim (403 assurance_required when an interim pre-MFA session is present; token-less sessions pass)", optOut: "WithInsecureNoAssuranceCheck; WithCredentialAssurance supplies an explicit gate"},
	"identity.DeleteAccountHandler":                   {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"identity.RequestPhoneVerificationHandler":        {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed", credentialEnrollment: true, defaultControl: "tokens.DenyInterim (403 assurance_required when an interim pre-MFA session is present; token-less sessions pass)", optOut: "WithInsecureNoAssuranceCheck; WithCredentialAssurance supplies an explicit gate"},
	"identity.ConfirmPhoneVerificationHandler":        {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed", credentialEnrollment: true, defaultControl: "tokens.DenyInterim (403 assurance_required when an interim pre-MFA session is present; token-less sessions pass)", optOut: "WithInsecureNoAssuranceCheck; WithCredentialAssurance supplies an explicit gate"},
	"identity.RequestRecoveryEmailHandler":            {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed", credentialEnrollment: true, defaultControl: "tokens.DenyInterim (403 assurance_required when an interim pre-MFA session is present; token-less sessions pass)", optOut: "WithInsecureNoAssuranceCheck; WithCredentialAssurance supplies an explicit gate"},
	"identity.ConfirmRecoveryEmailHandler":            {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed", credentialEnrollment: true, defaultControl: "tokens.DenyInterim (403 assurance_required when an interim pre-MFA session is present; token-less sessions pass)", optOut: "WithInsecureNoAssuranceCheck; WithCredentialAssurance supplies an explicit gate"},
	"identity.RequestPasswordResetViaRecoveryHandler": {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},

	// mfa: all handlers share the guarded() preamble.
	"mfa.EnrollHandler":                  {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed", credentialEnrollment: true, defaultControl: "403 assurance_required (fail closed: with no WithCredentialAssurance and no opt-out, the enrollment action refuses)", optOut: "WithInsecureNoAssuranceCheck; WithCredentialAssurance supplies an explicit gate"},
	"mfa.ConfirmHandler":                 {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed", credentialEnrollment: true, defaultControl: "403 assurance_required (fail closed: with no WithCredentialAssurance and no opt-out, confirming the factor refuses)", optOut: "WithInsecureNoAssuranceCheck; WithCredentialAssurance supplies an explicit gate"},
	"mfa.VerifyHandler":                  {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"mfa.VerifyRecoveryHandler":          {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"mfa.RegenerateRecoveryCodesHandler": {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed"},
	"mfa.DisableHandler":                 {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; step-up AMR gate; tenant resolver fails closed"},
	"mfa.StepUpHandler":                  {mutation: true, control: "same-origin CSRF gate; 4 KiB body cap; tenant resolver fails closed", credentialEnrollment: true, defaultControl: "500 misconfigured (fail closed: without WithSessionStateResolver the handler refuses to mint the renewable pair from the interim token's own subject)", optOut: "WithInsecureEchoSessionState (legacy echo)"},

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
	"passkey.BeginRegistrationHandler":       {mutation: true, control: "HMAC-sealed __Host- ceremony cookie; single-use challenge store", credentialEnrollment: true, defaultControl: "403 assurance_required (fail closed: with no WithCredentialAssurance and no opt-out, registration Begin refuses before touching the ceremony)", optOut: "WithInsecureNoAssuranceCheck; WithCredentialAssurance supplies an explicit gate"},
	"passkey.FinishRegistrationHandler":      {mutation: true, control: "HMAC-sealed __Host- ceremony cookie; single-use challenge store; body cap", credentialEnrollment: true, defaultControl: "403 assurance_required (fail closed: with no WithCredentialAssurance and no opt-out, registration Finish refuses before consuming the challenge)", optOut: "WithInsecureNoAssuranceCheck; WithCredentialAssurance supplies an explicit gate"},
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
// human-readable problem per mismatch, then validates each registry entry through recordProblems
// (control recorded, and fail-closed default plus opt-out named for enrollment surfaces).
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
		problems = append(problems, recordProblems(name, handlerRegistry[name])...)
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

// recordProblems validates one registry entry on its own: a mutation handler must record its
// control, and a credential-enrollment surface must record both the fail-closed default it
// applies with no assurance wiring and the explicit opt-out that disables it.
func recordProblems(name string, rec handlerRecord) []string {
	var problems []string
	if rec.mutation && strings.TrimSpace(rec.control) == "" {
		problems = append(problems, fmt.Sprintf("handlerRegistry entry %s is a mutation handler but records no control", name))
	}
	if rec.credentialEnrollment {
		if strings.TrimSpace(rec.defaultControl) == "" {
			problems = append(problems, fmt.Sprintf("handlerRegistry entry %s is a credential-enrollment surface but records no fail-closed default control", name))
		}
		if strings.TrimSpace(rec.optOut) == "" {
			problems = append(problems, fmt.Sprintf("handlerRegistry entry %s is a credential-enrollment surface but names no opt-out", name))
		}
	}
	return problems
}

// TestRegistryRecordsCredentialEnrollmentControls makes the inventory enforce the documented
// fail-closed guarantee: every credential-enrollment surface names the control it applies with
// no assurance wiring and the explicit opt-out, and the families the docs promise (passkey
// registration, mfa enrollment and step-up, identity recovery/email/phone enrollment) are all
// covered.
func TestRegistryRecordsCredentialEnrollmentControls(t *testing.T) {
	required := map[string]string{
		"passkey.BeginRegistrationHandler":         "assurance_required",
		"passkey.FinishRegistrationHandler":        "assurance_required",
		"mfa.EnrollHandler":                        "assurance_required",
		"mfa.ConfirmHandler":                       "assurance_required",
		"mfa.StepUpHandler":                        "misconfigured",
		"identity.RequestRecoveryEmailHandler":     "DenyInterim",
		"identity.ConfirmRecoveryEmailHandler":     "DenyInterim",
		"identity.RequestEmailChangeHandler":       "DenyInterim",
		"identity.ConfirmEmailChangeHandler":       "DenyInterim",
		"identity.RequestPhoneVerificationHandler": "DenyInterim",
		"identity.ConfirmPhoneVerificationHandler": "DenyInterim",
	}
	enrollment := 0
	for name, rec := range handlerRegistry {
		if !rec.credentialEnrollment {
			continue
		}
		enrollment++
		if strings.TrimSpace(rec.defaultControl) == "" {
			t.Errorf("%s is a credential-enrollment surface but records no fail-closed default control", name)
		}
		if strings.TrimSpace(rec.optOut) == "" {
			t.Errorf("%s is a credential-enrollment surface but names no opt-out", name)
		}
	}
	for name, want := range required {
		rec, ok := handlerRegistry[name]
		if !ok {
			t.Errorf("%s must be registered: the documented enrollment controls depend on it", name)
			continue
		}
		if !rec.credentialEnrollment {
			t.Errorf("%s must be marked credentialEnrollment: it hands out or upgrades credential material", name)
		}
		if !strings.Contains(rec.defaultControl, want) {
			t.Errorf("%s defaultControl %q must name %q", name, rec.defaultControl, want)
		}
		if strings.TrimSpace(rec.optOut) == "" {
			t.Errorf("%s must name the opt-out that disables its default control", name)
		}
	}
	if enrollment < len(required) {
		t.Errorf("registry marks only %d credential-enrollment surfaces; the documented families need at least %d", enrollment, len(required))
	}
}

// TestRegistryGuardRejectsUncontrolledEnrollment proves the enrollment check has teeth: a
// record marked as a credential-enrollment surface without a fail-closed default control (or
// without an opt-out) is a problem, which is what silently deleting a default from the registry
// would look like, while a fully annotated record passes.
func TestRegistryGuardRejectsUncontrolledEnrollment(t *testing.T) {
	problems := recordProblems("mfa.FakeEnrollmentHandler", handlerRecord{mutation: true, control: "x", credentialEnrollment: true})
	if !containsProblemAbout(problems, "mfa.FakeEnrollmentHandler") {
		t.Fatalf("an enrollment record without a fail-closed default control must fail the guard, got %v", problems)
	}
	if len(problems) != 2 {
		t.Fatalf("expected one problem for the missing default control and one for the missing opt-out, got %v", problems)
	}
	annotated := handlerRecord{mutation: true, control: "x", credentialEnrollment: true, defaultControl: "403 assurance_required", optOut: "WithInsecureNoAssuranceCheck"}
	if got := recordProblems("mfa.FakeEnrollmentHandler", annotated); len(got) != 0 {
		t.Fatalf("a fully annotated enrollment record must pass, got %v", got)
	}
}
