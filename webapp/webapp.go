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
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/basic"
)

// DefaultAccessTTL is the access-token lifetime NewWebApp uses when Config.AccessTTL is left
// zero. Short-lived access tokens bound the window a leaked access token is usable; rotation
// refreshes them transparently.
const DefaultAccessTTL = 15 * time.Minute

// DefaultRefreshTTL is the refresh-token lifetime NewWebApp uses when Config.RefreshTTL is
// left zero. It bounds how long an IDLE session survives before the user must re-authenticate;
// the ABSOLUTE bound on a continuously rotated session is the issuer's refresh-family lifetime
// cap (jwt.DefaultMaxRefreshFamilyLifetime, also 30 days, measured from login).
const DefaultRefreshTTL = 30 * 24 * time.Hour

// ErrIdentityNotRegisterable is returned by NewWebApp when Config.Identity does not implement
// identity.RevocationRegistry. The preset needs that seam to register the tokens account revoker
// on the service it is handed; without it identity.DisableUser could not revoke the refresh
// families the preset issues, so a deactivated account would keep rotating its refresh cookie
// indefinitely. The Service returned by identity.NewService implements it — a custom Service
// implementation must too (embedding the real Service satisfies it).
var ErrIdentityNotRegisterable = errors.New("webapp: Config.Identity must implement identity.RevocationRegistry so account deactivation revokes tokens")

// Config configures NewWebApp. It is deliberately tiny and frozen under the v1 SemVer
// promise: it composes the existing public identity + tokens API and adds nothing private.
type Config struct {
	// Identity is the account service that verifies credentials and manages the account
	// lifecycle (typically identity.NewService(...)). Required.
	//
	// NewWebApp registers the tokens account revoker on it (see identity.RevocationRegistry), so
	// DisableUser and DeleteAccount cascade into TokenStore, and wraps its EnsureActive check
	// around the refresh-rotation ClaimsProvider. It must therefore implement
	// identity.RevocationRegistry or NewWebApp returns ErrIdentityNotRegisterable.
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
	// Setting it opts out of the __Host- cookie prefix (which forbids a Domain), so the cookie
	// names are demoted to their __Secure- form and the subdomain cookie-tossing protection
	// __Host- provides is forfeited. Leave it empty unless the deployment needs cross-subdomain
	// cookies.
	CookieDomain string
	// TrustedOrigins, when non-empty, enables the CSRF origin check on every cookie-bearing
	// POST endpoint (login, register, refresh, logout). List the exact origins your forms are
	// served from, scheme-qualified, e.g. "https://app.example.com" — a scheme-qualified entry
	// is matched against the request's Origin scheme AND host, the stricter form (a bare host
	// without scheme, e.g. "app.example.com", is also accepted and matched against host only).
	TrustedOrigins []string
	// InsecureNoOriginCheck opts out of the preset's CSRF-by-default guarantee. NewWebApp refuses
	// to build when TrustedOrigins is empty unless this is set; when set, it wires
	// WithInsecureNoOriginCheck into BOTH the identity and tokens handlers so the whole preset is
	// consistently insecure (every origin accepted), restoring the pre-v1 behavior. Only set this
	// when CSRF is handled by a separate layer.
	InsecureNoOriginCheck bool
	// EventSink receives security events (login, registration, refresh reuse, logout, ...).
	// Nil selects event.NewSlogSink(nil), so events go to slog.Default() instead of being
	// silently dropped — silent auth is un-auditable auth.
	EventSink event.Sink
	Routes    Routes
}

// NewWebApp wires the identity and tokens packages into a single mounted http.Handler for
// the 80% password web-app case, with secure-by-default cookies, CSRF and a non-nil event
// sink. Every route it mounts is the same exported handler you would wire by hand:
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
// ACCOUNT DEACTIVATION ENDS ACCESS. NewWebApp wires both halves of that guarantee on the Identity
// service it is handed: it registers tokens.NewAccountRevoker(TokenStore) as a disable revoker and
// account eraser (so identity.DisableUser / DeleteAccount revoke the user's refresh families and
// API keys), and it wraps the refresh-rotation ClaimsProvider in identity.ActiveClaimsProvider (so
// a refresh token minted before the disable is refused with 401 instead of rotating into a fresh
// pair). Registering hooks on the caller's service is deliberate: Config.Identity arrives already
// built, so identity.RevocationRegistry is the seam that keeps the preset's guarantee intact.
// Wire the preset once, during startup, before serving traffic.
//
// NewWebApp returns an error when a required field (Identity, TokenStore, SigningKey,
// Issuer) is missing, and ErrIdentityNotRegisterable when Identity cannot accept that revocation
// wiring. It does not bundle a router, mailer or config framework; mount the returned handler
// under whatever prefix and middleware your application already uses.
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

	// Account deactivation must actually end access, and that takes BOTH halves of the wiring
	// below. Refuse to build without the registration seam rather than mount a preset whose
	// DisableUser leaves every refresh family live and rotatable.
	registry, ok := cfg.Identity.(identity.RevocationRegistry)
	if !ok {
		return nil, ErrIdentityNotRegisterable
	}
	// Half one: DisableUser (and DeleteAccount / ResetPassword / SetTemporaryPassword) must
	// cascade into the token store, revoking the user's refresh families and API keys.
	revoker := tokens.NewAccountRevoker(cfg.TokenStore)
	registry.RegisterDisableRevokers(revoker)
	registry.RegisterAccountErasers(revoker)

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
		// Half two: a refresh token minted before the disable must not rotate. The
		// ClaimsProvider is the only place rotation can be refused, so it re-checks account
		// status on every refresh — without it a suspended user renews forever, each rotation
		// pushing the refresh expiry out again.
		ClaimsProvider: identity.ActiveClaimsProvider(cfg.Identity, basic.ClaimsProviderFunc(func(_ context.Context, userID uuid.UUID, tenantID string) (basic.Claims, error) {
			return claimsForUser(userID, tenantID), nil
		})),
	})

	claimsOf := func(u *identity.User) basic.Claims {
		return claimsForUser(u.ID, cfg.Tenant)
	}

	// Build the cookie configuration once and validate it here, at construction: a configuration a
	// browser would reject must surface as a NewWebApp error, never as a per-request failure.
	// WithDomain demotes the __Host- prefix the defaults carry (a Domain cannot coexist with it).
	cookies := tokens.DefaultCookies()
	if cfg.CookieDomain != "" {
		cookies = cookies.WithDomain(cfg.CookieDomain)
	}
	if err := cookies.Validate(); err != nil {
		return nil, errors.Join(errors.New("webapp: invalid cookie configuration"), err)
	}

	idOpts := []identity.HandlerOption{
		identity.WithHandlerEventSink(sink),
		identity.WithCookies(cookies),
	}
	tkOpts := []tokens.HandlerOption{tokens.WithCookies(cookies), tokens.WithEventSink(sink)}
	if len(cfg.TrustedOrigins) > 0 {
		idOpts = append(idOpts, identity.WithTrustedOrigins(cfg.TrustedOrigins...))
		tkOpts = append(tkOpts, tokens.WithTrustedOrigins(cfg.TrustedOrigins...))
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

	routes := cfg.Routes.withDefaults()
	mux := http.NewServeMux()
	mux.Handle(routes.Register, identity.RegisterHandler(cfg.Identity, issuer, claimsOf, idOpts...))
	mux.Handle(routes.Login, identity.LoginHandler(cfg.Identity, issuer, claimsOf, idOpts...))
	mux.Handle(routes.Refresh, basic.RefreshHandler(issuer, tkOpts...))
	mux.Handle(routes.Logout, basic.LogoutHandler(cfg.TokenStore, tkOpts...))

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
