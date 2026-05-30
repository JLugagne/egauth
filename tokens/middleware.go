package tokens

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/JLugagne/libauth"
)

// AuthenticatedHandlerFunc is an HTTP handler that explicitly requires an authenticated
// actor and custom claims as parameters, ensuring business data is never hidden in the context.
type AuthenticatedHandlerFunc[C any] func(w http.ResponseWriter, r *http.Request, actor libauth.Actor, customClaims C)

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

// WithRefreshTenantResolver supplies the tenant for store-scoped auto-refresh rotation in
// multi-tenant setups.
func WithRefreshTenantResolver[C any](f func(*http.Request) string) AuthOption[C] {
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
// By default it reads a Bearer token from the Authorization header (backward-compatible).
// Options enable reading from a cookie (WithCookieAuth) and opt-in transparent rotation
// (WithAutoRefresh). On success it explicitly passes the extracted libauth.Actor and custom
// claims to the next handler.
func RequireAuth[C any](verifier Verifier[C], next AuthenticatedHandlerFunc[C], opts ...AuthOption[C]) http.HandlerFunc {
	cfg := authConfig[C]{readHeader: true}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		token, _ := extractAccessToken(r, &cfg)

		if token != "" {
			claims, err := verifier.VerifyAccessToken(r.Context(), token)
			if err == nil {
				if !cfg.stepUpSatisfied(claims) {
					stepUpRequired(w)
					return
				}
				next(w, r, actorFromClaims(claims), claims.Custom)
				return
			}
			// Only an expired token is eligible for auto-refresh; any other failure
			// (malformed, bad signature, invalid claims) is rejected outright.
			if !errors.Is(err, ErrTokenExpired) || cfg.rotator == nil {
				unauthorized(w)
				return
			}
		}

		// No usable access token. Attempt opt-in auto-refresh from the refresh cookie.
		if cfg.rotator != nil && cfg.cookies != nil {
			if refreshToken, ok := cfg.cookies.Refresh(r); ok {
				var ropts []Option
				if cfg.tenantResolver != nil {
					ropts = append(ropts, WithTenant(cfg.tenantResolver(r)))
				}
				pair, err := cfg.rotator.Rotate(r.Context(), refreshToken, ropts...)
				if err != nil {
					// Rotation failed (reuse/expired/not found): clear cookies so a
					// poisoned family cannot keep retrying, then reject.
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
				next(w, r, actorFromClaims(&pair.Claims), pair.Claims.Custom)
				return
			}
		}

		unauthorized(w)
	}
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

func actorFromClaims[C any](claims *Claims[C]) libauth.Actor {
	return libauth.Actor{
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
