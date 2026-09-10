// Package webapp provides NewWebApp, a batteries-included preset that wires the identity and
// tokens packages into a single mounted http.Handler for the common password web-app case
// (no custom token claims), with secure-by-default cookies, CSRF and a non-nil event sink.
//
// It is a thin, documented convenience layer over the public API — nothing private — and is
// frozen under the v1 SemVer promise. Reach for the à-la-carte handlers
// (identity.LoginHandler, tokens.RefreshHandler, ...) directly when you need custom claims or
// finer control.
//
// NOTE ON PACKAGE PLACEMENT: road-to-v1.md §9 names this preset NewWebApp on the ROOT
// egauth package. It cannot live there: the root package exports egauth.Actor, which the
// tokens package imports (tokens/middleware.go), so a root-package preset that composes
// identity+tokens forms the import cycle root -> identity -> tokens -> root. This subpackage
// is the cycle-free home for the same composition; promoting it onto the root package
// requires first relocating egauth.Actor out of the root (a separate, breaking decision —
// see the TASK-023 notes).
package webapp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/internal/httputil"
	"github.com/JLugagne/egauth/ratelimit"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/basic"
)

// DefaultAccessTTL is the access-token lifetime NewWebApp uses when Config.AccessTTL is left
// zero. Short-lived access tokens bound the window a leaked access token is usable; rotation
// refreshes them transparently.
const DefaultAccessTTL = 15 * time.Minute

// DefaultRateLimitBurst is the number of authentication requests a single client IP may make as
// a burst before the default limiter starts answering 429 Too Many Requests. It is deliberately
// generous enough for ordinary use (a login, a refresh, a logout) while keeping a flood of
// credential guesses from reaching the handlers at full speed.
const DefaultRateLimitBurst = 20

// DefaultRateLimitRefill is how often the default limiter restores one request to a client IP's
// budget once the burst is exhausted: one request per interval per IP. Combined with
// DefaultRateLimitBurst this allows a sustained 10 requests/minute per IP.
const DefaultRateLimitRefill = 6 * time.Second

// DefaultRefreshTTL is the refresh-token lifetime NewWebApp uses when Config.RefreshTTL is
// left zero. It bounds how long a session can be kept alive by rotation before the user must
// re-authenticate.
const DefaultRefreshTTL = 30 * 24 * time.Hour

// Config configures NewWebApp. It is deliberately tiny and frozen under the v1 SemVer
// promise: it composes the existing public identity + tokens API and adds nothing private.
type Config struct {
	// Identity is the account service that verifies credentials and manages the account
	// lifecycle (typically identity.NewService(...)). Required.
	Identity identity.Service
	// TokenStore persists refresh tokens and API keys (it doubles as the logout
	// family-revoker). Use basic.NewMemoryStore() for a single instance or
	// adapters/pgx/tokens.NewStore(pool) for Postgres. Required.
	TokenStore tokens.Store[struct{}]
	// SigningKey is the HS256 secret used to sign and verify access tokens. Required; it
	// must be a high-entropy secret kept out of source control.
	SigningKey string
	// Issuer is the JWT "iss" claim stamped on issued tokens (e.g. your app's name or
	// URL). Required.
	Issuer string
	// Tenant scopes every store/service operation. Leave it "" for a single-tenant app
	// (the default partition).
	Tenant string
	// AccessTTL overrides the access-token lifetime. Zero selects DefaultAccessTTL.
	AccessTTL time.Duration
	// RefreshTTL overrides the refresh-token lifetime. Zero selects DefaultRefreshTTL.
	RefreshTTL time.Duration
	// CookieDomain optionally scopes the auth cookies to a domain (empty = host-only).
	CookieDomain string
	// TrustedOrigins, when non-empty, enables the CSRF origin check on every cookie-bearing
	// POST endpoint (login, register, refresh, logout). Entries may be full origins
	// ("https://app.example.com") or bare hosts ("app.example.com"); both are accepted and
	// normalized to bare hosts before the handlers see them, so the two forms are equivalent.
	// List every origin your forms are served from. Entries that cannot be normalized to a
	// host make NewWebApp fail with an error.
	TrustedOrigins []string
	// InsecureNoOriginCheck opts out of the preset's CSRF-by-default guarantee. NewWebApp refuses
	// to build when TrustedOrigins is empty unless this is set; when set, it wires
	// WithInsecureNoOriginCheck into BOTH the identity and tokens handlers so the whole preset is
	// consistently insecure (every origin accepted), restoring the pre-v1 behavior. Only set this
	// when CSRF is handled by a separate layer.
	InsecureNoOriginCheck bool
	// RateLimiter overrides the throttle applied to every mounted authentication endpoint. Nil
	// selects a process-local ratelimit.TokenBucket keyed by client IP (see RateLimitBurst and
	// RateLimitRefill). Supply a shared-store implementation (e.g. Redis) for multi-instance
	// deployments. Cannot be combined with InsecureNoRateLimit.
	RateLimiter ratelimit.Limiter
	// RateLimitBurst overrides the default limiter's burst size (DefaultRateLimitBurst). Ignored
	// when RateLimiter is set; non-positive selects the default.
	RateLimitBurst int
	// RateLimitRefill overrides the default limiter's refill interval (DefaultRateLimitRefill):
	// how often one request is restored to a client IP's budget. Ignored when RateLimiter is set;
	// non-positive selects the default.
	RateLimitRefill time.Duration
	// InsecureNoRateLimit disables the preset's rate-limiting-by-default guarantee on every
	// mounted authentication endpoint, leaving login/register/refresh/logout unthrottled. Only set
	// this when an outer proxy or middleware already throttles those routes; it restores the
	// pre-v1 behavior. Cannot be combined with RateLimiter.
	InsecureNoRateLimit bool
	// EventSink receives security events (login, registration, refresh reuse, logout, ...).
	// Nil selects event.NewSlogSink(nil), so events go to slog.Default() instead of being
	// silently dropped — silent auth is un-auditable auth.
	EventSink event.Sink
	Routes    Routes
}

// NewWebApp wires the identity and tokens packages into a single mounted http.Handler for
// the 80% password web-app case, with secure-by-default cookies, CSRF, per-client-IP rate
// limiting and a non-nil event sink. Every route it mounts is the same exported handler you
// would wire by hand:
//
//	POST /auth/register   identity.RegisterHandler
//	POST /auth/login      identity.LoginHandler
//	POST /auth/refresh    tokens.RefreshHandler  (rotates the refresh cookie)
//	POST /auth/logout     tokens.LogoutHandler   (revokes the rotation family)
//
// Those /auth/* paths are defaults, not opinions: override any of them via Config.Routes to
// mount the endpoints under your own URL layout (an empty Routes field keeps the default).
//
// On success the login/register routes issue an access+refresh token pair and write them as
// secure cookies. Protect your own application routes with tokens.RequireAuth — that
// per-route concern stays à-la-carte by design.
//
// NewWebApp returns an error when a required field (Identity, TokenStore, SigningKey,
// Issuer) is missing. It does not bundle a router, mailer or config framework; mount the
// returned handler under whatever prefix and middleware your application already uses.
func NewWebApp(cfg Config) (http.Handler, error) {
	if cfg.Identity == nil {
		return nil, errors.New("webapp: Config.Identity is required")
	}
	if cfg.TokenStore == nil {
		return nil, errors.New("webapp: Config.TokenStore is required")
	}
	if cfg.SigningKey == "" {
		return nil, errors.New("webapp: Config.SigningKey is required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("webapp: Config.Issuer is required")
	}
	// CSRF-by-default guarantee: the preset enforces a strict same-origin check on every mounted
	// endpoint (identity login/register and tokens refresh/logout alike). Same-origin works out of
	// the box, but a cross-origin front-end needs its host on the allowlist — so refuse to build
	// with an empty TrustedOrigins unless the consumer explicitly opts out. This makes
	// "CSRF-by-default" mean the same thing across both handler families.
	if len(cfg.TrustedOrigins) == 0 && !cfg.InsecureNoOriginCheck {
		return nil, errors.New("webapp: Config.TrustedOrigins must be set for CSRF-by-default (or set Config.InsecureNoOriginCheck to opt out)")
	}
	if len(cfg.TrustedOrigins) > 0 && cfg.InsecureNoOriginCheck {
		return nil, errors.New("webapp: cannot specify both TrustedOrigins and InsecureNoOriginCheck")
	}
	if cfg.RateLimiter != nil && cfg.InsecureNoRateLimit {
		return nil, errors.New("webapp: cannot specify both RateLimiter and InsecureNoRateLimit")
	}

	accessTTL := cfg.AccessTTL
	if accessTTL <= 0 {
		accessTTL = DefaultAccessTTL
	}
	refreshTTL := cfg.RefreshTTL
	if refreshTTL <= 0 {
		refreshTTL = DefaultRefreshTTL
	}
	sink := cfg.EventSink
	if sink == nil {
		sink = event.NewSlogSink(nil)
	}

	// claimsForUser is the fresh-claims seam used both at issuance (claimsOf) and during
	// refresh rotation (ClaimsProvider). The no-claims preset carries no custom data, so
	// fresh claims are simply the subject + tenant; AuthTime/IssuedAt/ExpiresAt are stamped
	// by the issuer.
	claimsForUser := func(userID uuid.UUID, tenantID string) basic.Claims {
		return basic.Claims{Subject: userID, TenantID: tenantID}
	}

	issuer := basic.NewIssuer(basic.Config{
		Store:      cfg.TokenStore,
		Issuer:     cfg.Issuer,
		SecretKey:  cfg.SigningKey,
		AccessTTL:  accessTTL,
		RefreshTTL: refreshTTL,
		EventSink:  sink,
		ClaimsProvider: basic.ClaimsProviderFunc(func(_ context.Context, userID uuid.UUID, tenantID string) (basic.Claims, error) {
			return claimsForUser(userID, tenantID), nil
		}),
	})

	claimsOf := func(u *identity.User) basic.Claims {
		return claimsForUser(u.ID, cfg.Tenant)
	}

	idOpts := []identity.HandlerOption{identity.WithHandlerEventSink(sink), identity.WithUniformAuthErrors()}
	tkOpts := []tokens.HandlerOption{}
	if cfg.CookieDomain != "" {
		if strings.Contains(cfg.CookieDomain, "://") || strings.Contains(cfg.CookieDomain, "/") || strings.Contains(cfg.CookieDomain, ":") {
			return nil, errors.New("webapp: Config.CookieDomain must not include scheme, port, or path")
		}
		cookies := tokens.DefaultCookies()
		cookies.Domain = cfg.CookieDomain
		cookies.AccessName = "access_token"
		cookies.RefreshName = "refresh_token"
		idOpts = append(idOpts, identity.WithCookies(cookies))
		tkOpts = append(tkOpts, tokens.WithCookies(cookies))
	}
	if len(cfg.TrustedOrigins) > 0 {
		// Accept both the documented full-origin format ("https://app.example.com") and the
		// bare-host format the handlers expect; normalize loudly so a mistyped entry fails
		// at construction time instead of silently never matching at request time.
		hosts, err := httputil.NormalizeHosts(cfg.TrustedOrigins)
		if err != nil {
			return nil, fmt.Errorf("webapp: Config.TrustedOrigins: %w", err)
		}
		idOpts = append(idOpts, identity.WithTrustedOrigins(hosts...))
		tkOpts = append(tkOpts, tokens.WithTrustedOrigins(hosts...))
	}
	if cfg.InsecureNoOriginCheck {
		// Opt-out: disable the same-origin check on BOTH families so the preset is consistently
		// insecure rather than protecting only one half.
		idOpts = append(idOpts, identity.WithInsecureNoOriginCheck())
		tkOpts = append(tkOpts, tokens.WithInsecureNoOriginCheck())
	}
	if cfg.Tenant != "" {
		tenant := cfg.Tenant
		resolve := func(*http.Request) string { return tenant }
		idOpts = append(idOpts, identity.WithTenantResolver(resolve))
		tkOpts = append(tkOpts, tokens.WithTenantResolver(resolve))
	}

	register := http.Handler(identity.RegisterHandler(cfg.Identity, issuer, claimsOf, idOpts...))
	login := http.Handler(identity.LoginHandler(cfg.Identity, issuer, claimsOf, idOpts...))
	refresh := http.Handler(basic.RefreshHandler(issuer, tkOpts...))
	logout := http.Handler(basic.LogoutHandler(cfg.TokenStore, tkOpts...))

	// Throttle-by-default: every mounted authentication endpoint shares one limiter keyed by
	// client IP, so an attacker cannot spread credential guessing across routes, and a flood is
	// rejected with 429 before it reaches the argon2/stdlib handlers. One limiter per preset means
	// the burst budget is per client, not per route. Config.RateLimiter (e.g. a Redis-backed
	// implementation) replaces the process-local TokenBucket.
	if !cfg.InsecureNoRateLimit {
		limiter := cfg.RateLimiter
		if limiter == nil {
			burst := cfg.RateLimitBurst
			if burst <= 0 {
				burst = DefaultRateLimitBurst
			}
			refill := cfg.RateLimitRefill
			if refill <= 0 {
				refill = DefaultRateLimitRefill
			}
			limiter = ratelimit.NewTokenBucket(burst, refill)
		}
		throttle := ratelimit.Middleware(limiter, ratelimit.ClientIP)
		register = throttle(register)
		login = throttle(login)
		refresh = throttle(refresh)
		logout = throttle(logout)
	}

	routes := cfg.Routes.withDefaults()
	mux := http.NewServeMux()
	mux.Handle(routes.Register, register)
	mux.Handle(routes.Login, login)
	mux.Handle(routes.Refresh, refresh)
	mux.Handle(routes.Logout, logout)

	return mux, nil
}

// Default route patterns NewWebApp mounts when the corresponding Routes field is left empty.
// They follow Go 1.22 ServeMux "METHOD /path" syntax. Each is overridable via Config.Routes so
// the preset stays unopinionated about your URL layout.
const (
	DefaultRegisterRoute = "POST /auth/register"
	DefaultLoginRoute    = "POST /auth/login"
	DefaultRefreshRoute  = "POST /auth/refresh"
	DefaultLogoutRoute   = "POST /auth/logout"
)

// Routes overrides the route patterns NewWebApp mounts. Every field is optional: an empty field
// falls back to its Default*Route. A pattern uses Go 1.22 ServeMux syntax ("METHOD /path", e.g.
// "POST /api/v1/sign-in"); the method should stay POST since all four endpoints are
// state-changing, but the path is entirely yours. This keeps NewWebApp's defaults convenient
// without forcing its /auth/* URL layout on you.
type Routes struct {
	// Register overrides the registration route. Empty selects DefaultRegisterRoute.
	Register string
	// Login overrides the login route. Empty selects DefaultLoginRoute.
	Login string
	// Refresh overrides the token-refresh route. Empty selects DefaultRefreshRoute.
	Refresh string
	// Logout overrides the logout route. Empty selects DefaultLogoutRoute.
	Logout string
}

// withDefaults returns a copy of r with every empty field filled from its Default*Route, so
// callers always end up with a complete, mountable set of patterns.
func (r Routes) withDefaults() Routes {
	if r.Register == "" {
		r.Register = DefaultRegisterRoute
	}
	if r.Login == "" {
		r.Login = DefaultLoginRoute
	}
	if r.Refresh == "" {
		r.Refresh = DefaultRefreshRoute
	}
	if r.Logout == "" {
		r.Logout = DefaultLogoutRoute
	}
	return r
}
