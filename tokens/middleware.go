package tokens

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/JLugagne/egauth"
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
	maxAuthAge     time.Duration
}

// AuthOption configures the RequireAuth middleware.
type AuthOption[C any] func(*authConfig[C])

// WithCookieAuth reads the access token from the given cookie configuration instead of
// (or in addition to) the Authorization header.
func WithCookieAuth[C any](c Cookies) AuthOption[C] {
	return func(a *authConfig[C]) {
		cc := c
		a.cookies = &cc
	}
}

// WithAutoRefresh enables opt-in transparent rotation: when the access token is missing or
// expired but a valid refresh cookie is present, the middleware rotates the pair, rewrites
// both cookies and proceeds with the freshly issued claims. It implies cookie-based reads.
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

// WithMaxAuthAge gates the route on step-up ("sudo mode") freshness: the subject must have
// authenticated within d, measured from the token's auth_time (OIDC) claim — NOT its issue time,
// so a silent auto-refresh does not reset the clock. A subject whose authentication is older than
// d (or whose token carries no auth_time) is rejected with 403 "step_up_required" and should
// re-authenticate to mint a fresh token.
//
// This is the enforceable primitive for sensitive actions such as disabling MFA, deleting the
// account, or changing security settings: wrap their routes with it (it works for any factor, so
// it covers OAuth-only accounts that cannot re-verify a password). A non-positive d disables the
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

	return func(w http.ResponseWriter, r *http.Request) {
		serveAuthenticated(w, r, verifier, &cfg, func(w http.ResponseWriter, r *http.Request, claims *Claims[C]) {
			next(w, r, actorFromClaims(claims), claims.Custom)
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

func actorFromClaims[C any](claims *Claims[C]) egauth.Actor {
	return egauth.Actor{
		UserID:   claims.Subject,
		TenantID: claims.TenantID,
	}
}

// stepUpSatisfied reports whether the claims clear BOTH step-up gates: the required AMR factors
// (WithRequiredAMR) and the authentication-freshness window (WithMaxAuthAge). Either gate is a
// no-op when not configured.
func (cfg *authConfig[C]) stepUpSatisfied(claims *Claims[C]) bool {
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

func unauthorized(w http.ResponseWriter) {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// stepUpRequired signals an authenticated subject whose assurance level is too low for the
// route (RFC 8176 AMR gate); the client should re-authenticate with the missing factor.
func stepUpRequired(w http.ResponseWriter) {
	http.Error(w, "step_up_required", http.StatusForbidden)
}
