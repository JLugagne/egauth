package tokens

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/httputil"
)

// AuthenticatedHandlerFunc is an HTTP handler that explicitly requires an authenticated
// actor and custom claims as parameters, ensuring business data is never hidden in the context.
type AuthenticatedHandlerFunc[C any] func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, customClaims C)

// authConfig holds the optional behavior of RequireAuth, configured via AuthOption.
type authConfig[C any] struct {
	cookies        *Cookies
	rotator        Rotator[C]
	tenantResolver func(*http.Request) string
	readHeader     bool
	persistRefresh bool
	requiredAMR    []string
	requiredScopes []string
	// requiredKinds is the set of egauth.PrincipalKind values permitted by WithRequiredKind.
	// When non-empty, a verified credential whose Actor.Kind is not in the set is rejected.
	requiredKinds          []egauth.PrincipalKind
	maxAuthAge             time.Duration
	passwordChangeGate     bool
	passwordChangeResetURL string
	// interimAllowed opts the route in to PRE-STEP-UP interim credentials (Claims.Interim). It is
	// false by default: an interim credential is rejected with 403 "step_up_required" on every
	// route that does not explicitly allow it (see WithInterimAllowed).
	interimAllowed bool
	// gate is the application-supplied predicate invoked after all built-in gates. A nil gate is a no-op.
	gate func(egauth.Actor, C) error
}

// AuthOption configures the RequireAuth middleware.
type AuthOption[C any] func(*authConfig[C])

// WithCookieAuth reads the access token from the given cookie configuration instead of
// (or in addition to) the Authorization header.
//
// The configuration is validated when the middleware is built: a value a browser would reject
// (e.g. a __Host- name kept alongside a Domain) panics there, never while serving a request.
// Derive such variants with Cookies.WithDomain / WithPath / WithRefreshPath / WithInsecure, which
// demote the prefix instead.
func WithCookieAuth[C any](c Cookies) AuthOption[C] {
	return func(a *authConfig[C]) {
		cc := c
		a.cookies = &cc
	}
}

// WithAutoRefresh enables opt-in transparent rotation: when the access token is missing or
// expired but a valid refresh cookie is present, the middleware rotates the pair, rewrites
// both cookies and proceeds with the freshly issued claims. It implies cookie-based reads.
//
// The cookie configuration is validated when the middleware is built (see WithCookieAuth).
func WithAutoRefresh[C any](rotator Rotator[C], cookies Cookies) AuthOption[C] {
	return func(a *authConfig[C]) {
		cc := cookies
		a.cookies = &cc
		a.rotator = rotator
	}
}

// WithAuthTenantResolver makes RequireAuth tenant-aware. The resolver maps an incoming request to
// its tenant ID (e.g. from the Host header, a path segment, or an upstream-set context value),
// and the middleware then verifies the access token through the tenant-bound path
// (Verifier.VerifyAccessTokenForTenant), failing closed with ErrTenantMismatch when the token's
// signed tenant does not match. The same resolver also scopes store-backed auto-refresh rotation.
//
// A configured resolver MUST return a non-empty tenant ID for any request it can map; returning
// "" is interpreted as "tenant could not be resolved" and the middleware rejects the request with
// 401 instead of falling back to the single-tenant ("") partition. This is the fail-closed
// guarantee: when a resolver is configured, the middleware only ever calls
// VerifyAccessTokenForTenant with the resolved tenant ID, never the single-tenant ("") partition.
// When no resolver is set at all, the middleware calls VerifyAccessTokenForTenant with "" and
// stays in single-tenant mode, so single-tenant consumers need no changes.
//
// This mirrors sessions.WithTenantResolver; it carries the Auth- prefix because the package-level
// tokens.WithTenantResolver name is already taken by the RefreshHandler/LogoutHandler option.
func WithAuthTenantResolver[C any](f func(*http.Request) string) AuthOption[C] {
	return func(a *authConfig[C]) { a.tenantResolver = f }
}

// WithoutHeaderAuth disables reading the access token from the Authorization header,
// restricting authentication to cookies only.
func WithoutHeaderAuth[C any]() AuthOption[C] {
	return func(a *authConfig[C]) { a.readHeader = false }
}

// WithPersistentAutoRefresh makes auto-refresh re-issue a PERSISTENT refresh cookie.
//
// By default auto-refresh writes a SESSION refresh cookie: the middleware cannot recover
// the per-user remember_me choice from a bare request (browsers never echo a cookie's
// Max-Age), so the conservative default never silently upgrades a session-only cookie into
// a persistent one. Enable this only when the deployment uses persistent "remember me"
// refresh cookies globally.
func WithPersistentAutoRefresh[C any]() AuthOption[C] {
	return func(a *authConfig[C]) { a.persistRefresh = true }
}

// WithRequiredAMR gates the route on step-up authentication: the verified token's AMR claim
// (RFC 8176) must contain ALL of the given values, otherwise the request is rejected with 403
// "step_up_required" (the subject is authenticated but at too low an assurance level). Issue
// tokens whose Claims.AMR records the factors used (e.g. AMRPassword, AMROTP, AMRWebAuthn,
// AMRMFA) so this gate can enforce, for example, WithRequiredAMR(AMRMFA) on sensitive routes.
func WithRequiredAMR[C any](values ...string) AuthOption[C] {
	return func(a *authConfig[C]) { a.requiredAMR = values }
}

// WithInterimAllowed admits a PRE-STEP-UP interim credential (Claims.Interim) to this route.
//
// By default EVERY route rejects an interim credential with 403 "step_up_required": the credential
// minted by an MFA-gated login (identity.WithMFAGate, oauth.WithMFAGate) proves only the first
// factor, so it is not a session. Mount this option ONLY on the endpoints that exist to complete the
// second factor — mfa.StepUpHandler (and, if you expose them separately, the verify/recovery-code
// endpoints and logout) — never on an ordinary application route.
//
// It does not weaken the other gates: WithRequiredAMR(AMRMFA) still rejects the interim credential,
// because an interim credential never carries a step-up factor in its AMR.
func WithInterimAllowed[C any]() AuthOption[C] {
	return func(a *authConfig[C]) { a.interimAllowed = true }
}

// WithRequiredScopes gates the route on token scopes: the verified token's Scopes claim must
// contain ALL of the given values, otherwise the request is rejected with 403
// "insufficient_scope". No effect when no scopes are required (opt-in only).
// Use this to restrict API-key-backed or PAT-backed routes to tokens carrying specific
// capabilities (e.g. WithRequiredScopes("repo:write", "ci:trigger")).
func WithRequiredScopes[C any](scopes ...string) AuthOption[C] {
	return func(a *authConfig[C]) { a.requiredScopes = scopes }
}

// WithRequiredKind gates the route on principal kind: the verified credential's
// egauth.Actor.Kind must be one of the supplied kinds, otherwise the request is rejected
// with 403 "wrong_principal_kind". An empty kind list has no effect (opt-in gate).
//
// The principal kind is taken from Claims.Kind, which is stamped by the issuer when minting
// API-key-backed tokens (PAT or Service). Interactive access tokens (IssueTokenPair) leave
// Kind at its zero value, which the gate treats as egauth.User (human). Use RequireMachine
// and RequireHuman for the two common cases. Use this directly when a more specific subset
// is needed (e.g. only egauth.PAT, not all human principals).
func WithRequiredKind[C any](kinds ...egauth.PrincipalKind) AuthOption[C] {
	return func(a *authConfig[C]) { a.requiredKinds = kinds }
}

// RequireMachine is a convenience AuthOption that restricts the route to Service (machine)
// actors. PAT and User (interactive) tokens are rejected with 403 "wrong_principal_kind".
// It is equivalent to WithRequiredKind(egauth.Service).
func RequireMachine[C any]() AuthOption[C] {
	return WithRequiredKind[C](egauth.Service)
}

// RequireHuman is a convenience AuthOption that restricts the route to human actors: User
// (interactive session) and PAT (personal access token acting on behalf of a user). Service
// (machine) tokens are rejected with 403 "wrong_principal_kind".
// It is equivalent to WithRequiredKind(egauth.User, egauth.PAT).
func RequireHuman[C any]() AuthOption[C] {
	return WithRequiredKind[C](egauth.User, egauth.PAT)
}

// WithMaxAuthAge gates the route on step-up ("sudo mode") freshness: the subject must have
// authenticated within d, measured from the token's auth_time (OIDC) claim — NOT its issue time,
// so a silent auto-refresh does not reset the clock. A subject whose authentication is older than
// d (or whose token carries no auth_time) is rejected with 403 "step_up_required" and should
// re-authenticate to mint a fresh token.
//
// It is a FRESHNESS gate, not an assurance gate, and is NOT sufficient on its own for a sensitive
// action such as disabling MFA or deleting the account: the pre-step-up interim credential of an
// MFA-gated login is freshly issued, so it passes trivially. Combine it with
// WithRequiredAMR(AMRMFA) — which fails closed for any credential that has not proven a second
// factor — and use this option for the "sudo mode" window on top (it works for any factor, so it
// also covers OAuth-only accounts that cannot re-verify a password). A non-positive d disables the
// check. See also Claims.FreshAuth for gating outside an HTTP handler.
func WithMaxAuthAge[C any](d time.Duration) AuthOption[C] {
	return func(a *authConfig[C]) { a.maxAuthAge = d }
}

// RequireAuth wraps an AuthenticatedHandlerFunc to enforce access-token verification.
//
// By default it reads a Bearer token from the Authorization header (backward-compatible) and
// verifies it without tenant binding — correct for single-tenant deployments, where every token
// is issued under the empty tenant. Options enable reading from a cookie (WithCookieAuth), opt-in
// transparent rotation (WithAutoRefresh) and, for multi-tenant deployments, per-request tenant
// resolution (WithTenantResolver).
//
// When a tenant resolver is configured the middleware becomes tenant-aware: it resolves the
// request's tenant up front and verifies the access token through Verifier.VerifyAccessTokenForTenant,
// so a token minted for one tenant cannot be replayed in another under a shared signing key. A
// resolver that returns "" (tenant could not be resolved) fails the request closed with 401 — it
// never falls back to the tenant-unaware path. On success it explicitly passes the extracted
// egauth.Actor and custom claims to the next handler.
func RequireAuth[C any](verifier Verifier[C], next AuthenticatedHandlerFunc[C], opts ...AuthOption[C]) http.HandlerFunc {
	cfg := authConfig[C]{readHeader: true}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.cookies != nil {
		cfg.cookies.MustValidate()
	}

	return func(w http.ResponseWriter, r *http.Request) {
		serveAuthenticated(w, r, verifier, &cfg, func(w http.ResponseWriter, r *http.Request, claims *Claims[C]) {
			actor := actorFromClaims(claims)
			if !cfg.kindSatisfied(actor) {
				wrongPrincipalKind(w)
				return
			}
			next(w, r, actor, claims.Custom)
		})
	}
}

// serveAuthenticated runs the shared access-token verification + opt-in auto-refresh path
// and, on success, invokes onAuth with the verified claims. It is the single fail-closed
// authentication implementation behind both RequireAuth (which forwards claims as explicit
// arguments) and ContextMiddleware (which injects them into the request context). Every
// failure mode writes its own response and returns WITHOUT calling onAuth.
func serveAuthenticated[C any](w http.ResponseWriter, r *http.Request, verifier Verifier[C], cfg *authConfig[C], onAuth func(http.ResponseWriter, *http.Request, *Claims[C])) {
	// Resolve the tenant up front so BOTH the access-token verification and any
	// auto-refresh rotation are scoped to the same tenant. When a resolver is configured
	// it MUST map the request to a non-empty tenant ID; an empty return means the tenant
	// could not be determined, and failing open into the "" partition would let such a
	// request reach the tenant-unaware verification path (which a multi-tenant Verifier
	// refuses anyway). So we reject it. The "" partition is used only when no resolver is
	// configured at all (single-tenant mode).
	tenantID := ""
	tenantAware := cfg.tenantResolver != nil
	if tenantAware {
		tenantID = cfg.tenantResolver(r)
		if tenantID == "" {
			unauthorized(w)
			return
		}
	}

	token, _ := extractAccessToken(r, cfg)

	if token != "" {
		var claims *Claims[C]
		var err error
		if tenantAware {
			claims, err = verifier.VerifyAccessTokenForTenant(r.Context(), tenantID, token)
		} else {
			claims, err = verifier.VerifyAccessTokenForTenant(r.Context(), "", token)
		}
		if err == nil {
			if !cfg.stepUpSatisfied(claims) {
				stepUpRequired(w)
				return
			}
			if !cfg.scopesSatisfied(claims) {
				insufficientScope(w)
				return
			}
			if cfg.passwordChangeBlocked(claims) {
				passwordChangeRequired(w, r, cfg.passwordChangeResetURL)
				return
			}
			if cfg.gate != nil {
				if gateErr := cfg.gate(actorFromClaims(claims), claims.Custom); gateErr != nil {
					forbidden(w)
					return
				}
			}
			onAuth(w, r, claims)
			return
		}
		// Only an expired token is eligible for auto-refresh; any other failure
		// (malformed, bad signature, invalid claims, tenant mismatch) is rejected outright.
		if !errors.Is(err, ErrTokenExpired) || cfg.rotator == nil {
			unauthorized(w)
			return
		}
	}

	// No usable access token. Attempt opt-in auto-refresh from the refresh cookie.
	if cfg.rotator != nil && cfg.cookies != nil {
		if refreshToken, ok := cfg.cookies.Refresh(r); ok {
			pair, err := cfg.rotator.Rotate(r.Context(), tenantID, refreshToken)
			if err != nil {
				// ErrRefreshConcurrent is benign concurrency: a parallel request won the
				// rotation race and already minted a fresh, valid refresh cookie for this
				// client. The family is explicitly NOT poisoned. Clearing the refresh
				// cookie here would wipe the winner's freshly issued cookie and log the
				// user out — the exact lockout the reuse grace exists to prevent. So we
				// drop only the stale access cookie and reject this request; the client
				// retries with the winner's still-valid refresh cookie.
				if errors.Is(err, ErrRefreshConcurrent) {
					cfg.cookies.ClearAccess(w)
					unauthorized(w)
					return
				}
				// Any other rotation failure (after-grace reuse/expired/not found): clear
				// all cookies so a poisoned family cannot keep retrying, then reject.
				cfg.cookies.Clear(w)
				unauthorized(w)
				return
			}
			cfg.cookies.SetAccess(w, pair.AccessToken)
			cfg.cookies.SetRefresh(w, pair.RefreshToken, pair.RefreshTokenExpiresAt, cfg.persistRefresh)
			if !cfg.stepUpSatisfied(&pair.Claims) {
				stepUpRequired(w)
				return
			}
			if !cfg.scopesSatisfied(&pair.Claims) {
				insufficientScope(w)
				return
			}
			if cfg.passwordChangeBlocked(&pair.Claims) {
				passwordChangeRequired(w, r, cfg.passwordChangeResetURL)
				return
			}
			if cfg.gate != nil {
				if gateErr := cfg.gate(actorFromClaims(&pair.Claims), pair.Claims.Custom); gateErr != nil {
					forbidden(w)
					return
				}
			}
			onAuth(w, r, &pair.Claims)
			return
		}
	}

	unauthorized(w)
}

// extractAccessToken pulls the access token from the configured cookie and/or the
// Authorization header. The bool reports whether it came from a cookie.
func extractAccessToken[C any](r *http.Request, cfg *authConfig[C]) (string, bool) {
	if cfg.cookies != nil {
		if t, ok := cfg.cookies.Access(r); ok {
			return t, true
		}
	}
	if cfg.readHeader {
		authHeader := r.Header.Get("Authorization")
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return parts[1], false
		}
	}
	return "", false
}

// actorFromClaims builds the egauth.Actor from verified claims. Kind is propagated verbatim
// from Claims.Kind so that API-key-backed tokens (PAT, Service) carry the right principal
// classification through to the WithRequiredKind gate. Interactive tokens leave Kind at the
// zero value, which egauth.IsHuman treats as User (the safe human default).
// Scopes are copied verbatim from the claims so that application predicates (e.g. those
// passed to WithGate) can call actor.HasAllScopes without having to inspect the raw claims.
//
// The subject mapping mirrors ActorFromAPIKey's per-Kind model: for a Service token the subject
// is the key's own identity, so it lands on KeyID and UserID is left zero (IsMachine true); for
// PAT and User (including the zero Kind) the subject is the owning/authenticated user, so it
// lands on UserID. Unlike ActorFromAPIKey, the JWT wire format (Claims) carries no separate
// api-key-id claim, so a PAT's KeyID is unavailable on this path and stays zero.
func actorFromClaims[C any](claims *Claims[C]) egauth.Actor {
	actor := egauth.Actor{
		TenantID: claims.TenantID,
		Kind:     claims.Kind,
		Scopes:   claims.Scopes,
	}
	if claims.Kind == egauth.Service {
		actor.KeyID = claims.Subject
	} else {
		actor.UserID = claims.Subject
	}
	return actor
}

// stepUpSatisfied reports whether the claims clear the step-up gates: the credential must not be a
// PRE-STEP-UP interim one (unless the route opted in with WithInterimAllowed), and it must carry the
// required AMR factors (WithRequiredAMR) within the authentication-freshness window
// (WithMaxAuthAge). The AMR and freshness gates are no-ops when not configured; the interim
// rejection is ALWAYS on, so an interim credential is not a session anywhere it was not explicitly
// admitted.
func (cfg *authConfig[C]) stepUpSatisfied(claims *Claims[C]) bool {
	if claims.Interim && !cfg.interimAllowed {
		return false
	}
	return cfg.amrSatisfied(claims) && claims.FreshAuth(cfg.maxAuthAge)
}

// amrSatisfied reports whether the claims carry every required authentication-method
// reference (step-up gate). With no requirement configured it always passes.
func (cfg *authConfig[C]) amrSatisfied(claims *Claims[C]) bool {
	if len(cfg.requiredAMR) == 0 {
		return true
	}
	have := make(map[string]bool, len(claims.AMR))
	for _, a := range claims.AMR {
		have[a] = true
	}
	for _, req := range cfg.requiredAMR {
		if !have[req] {
			return false
		}
	}
	return true
}

// scopesSatisfied reports whether the claims carry every required scope. With no requirement
// configured it always passes (opt-in gate).
func (cfg *authConfig[C]) scopesSatisfied(claims *Claims[C]) bool {
	if len(cfg.requiredScopes) == 0 {
		return true
	}
	have := make(map[string]bool, len(claims.Scopes))
	for _, s := range claims.Scopes {
		have[s] = true
	}
	for _, req := range cfg.requiredScopes {
		if !have[req] {
			return false
		}
	}
	return true
}

// kindSatisfied reports whether the actor's principal kind is in the required set. With no
// requirement configured it always passes (opt-in gate). A zero Kind (interactive session token)
// is matched against egauth.User so it passes RequireHuman but fails RequireMachine.
func (cfg *authConfig[C]) kindSatisfied(actor egauth.Actor) bool {
	if len(cfg.requiredKinds) == 0 {
		return true
	}
	// Normalise the zero Kind to egauth.User: an interactive JWT access token carries no
	// explicit Kind, which actorFromClaims leaves zero. The zero value behaves as User per
	// egauth.IsHuman documentation, so we apply the same normalisation here so that
	// RequireHuman passes and RequireMachine fails for plain interactive tokens.
	kind := actor.Kind
	if kind == "" {
		kind = egauth.User
	}
	for _, allowed := range cfg.requiredKinds {
		if kind == allowed {
			return true
		}
	}
	return false
}

func unauthorized(w http.ResponseWriter) {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// stepUpRequired signals an authenticated subject whose assurance level is too low for the
// route (RFC 8176 AMR gate); the client should re-authenticate with the missing factor.
func stepUpRequired(w http.ResponseWriter) {
	http.Error(w, "step_up_required", http.StatusForbidden)
}

// insufficientScope signals that the verified token does not carry all scopes required by the
// route (WithRequiredScopes gate). The subject is authenticated; the token simply lacks authority.
func insufficientScope(w http.ResponseWriter) {
	http.Error(w, "insufficient_scope", http.StatusForbidden)
}

// wrongPrincipalKind signals that the verified credential's principal kind is not in the set
// allowed by the route (WithRequiredKind gate). The credential is authentic but the wrong type
// for this endpoint.

// WithPasswordChangeGate enforces the soft password-change gate: after a request's access
// token has been successfully verified (and any step-up / AMR checks have passed), if the
// token carries Claims.MustChangePassword the request is intercepted and the wrapped handler
// is NOT invoked. The credential itself stays valid — this is a soft redirect to the reset
// flow, never a lockout.
//
// When resetURL is non-empty the gate replies 303 See Other with a Location pointing at
// resetURL (carrying an ?error=password_change_required parameter); when resetURL is empty it
// replies 403 Forbidden with the plain-text body "password_change_required".
//
// IMPORTANT: wrap the change-password and logout routes WITHOUT this option. A user who must
// change their password has to be able to reach the reset endpoint (and to log out); gating
// those routes would trap the user in a redirect loop. Apply the gate to every other route.
func WithPasswordChangeGate[C any](resetURL string) AuthOption[C] {
	return func(a *authConfig[C]) {
		a.passwordChangeGate = true
		a.passwordChangeResetURL = resetURL
	}
}

// passwordChangeBlocked reports whether the gate is configured and the verified claims carry
// the must-change-password flag, meaning the request must be diverted to the reset flow
// instead of reaching the wrapped handler.
func (cfg *authConfig[C]) passwordChangeBlocked(claims *Claims[C]) bool {
	return cfg.passwordChangeGate && claims.MustChangePassword
}

// passwordChangeRequired emits the soft password-change-gate response: a 303 redirect to the
// configured reset URL when one is set, otherwise a 403 with the "password_change_required"
// code. It mirrors the WithFailureRedirect style by delegating to httputil.Fail.
func passwordChangeRequired(w http.ResponseWriter, r *http.Request, resetURL string) {
	httputil.Fail(w, r, resetURL, http.StatusForbidden, "password_change_required")
}

// wrongPrincipalKind signals that the verified credential's principal kind is not in the set
// allowed by the route (WithRequiredKind gate). The credential is authentic but the wrong type
// for this endpoint.
func wrongPrincipalKind(w http.ResponseWriter) {
	http.Error(w, "wrong_principal_kind", http.StatusForbidden)
}

// forbidden signals that the application-supplied gate predicate (WithGate) rejected the
// request. The credential is authentic, but the gate's policy denies access. The predicate's
// error text is intentionally not echoed to avoid leaking internal policy detail.
func forbidden(w http.ResponseWriter) {
	http.Error(w, "forbidden", http.StatusForbidden)
}

// WithGate attaches an application-supplied predicate that runs after all built-in gates
// (kind, scopes, AMR, auth-age, password-change) and before the protected handler.
// The predicate receives the verified Actor (basic identity + scopes) and the decoded
// custom claims C. If it returns a non-nil error the request is rejected with 403 Forbidden;
// the error text is NOT echoed to the client. A nil fn is a no-op (equivalent to no gate).
func WithGate[C any](fn func(egauth.Actor, C) error) AuthOption[C] {
	return func(a *authConfig[C]) {
		a.gate = fn
	}
}
