package tokens

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/httputil"

	"github.com/google/uuid"
)

// FamilyRevoker is the minimal store capability LogoutHandler needs to revoke a rotation
// family. tokens.Store[C] satisfies it for any C (neither method depends on C).
type FamilyRevoker interface {
	FindRefreshToken(ctx context.Context, tenantID string, tokenHash string) (*RefreshToken, error)
	RevokeFamily(ctx context.Context, tenantID string, familyID uuid.UUID) error
}

// handlerConfig holds the configurable behavior of the tokens HTTP handlers.
type handlerConfig struct {
	cookies               Cookies
	tenantResolver        func(*http.Request) string
	successURL            string
	failureURL            string
	persistRefresh        bool
	trustedOrigins        map[string]bool
	insecureNoOriginCheck bool
	events                event.Sink
	insecureWarnedOnce    *sync.Once
}

// HandlerOption configures the tokens HTTP handlers (RefreshHandler, LogoutHandler).
type HandlerOption func(*handlerConfig)

func newHandlerConfig(opts []HandlerOption) handlerConfig {
	c := handlerConfig{cookies: DefaultCookies(), insecureWarnedOnce: &sync.Once{}}
	for _, opt := range opts {
		opt(&c)
	}
	c.cookies.MustValidate()
	return c
}

// WithCookies replaces the cookie configuration wholesale.
func WithCookies(c Cookies) HandlerOption { return func(h *handlerConfig) { h.cookies = c } }

// WithCookieDomain scopes the auth cookies to a domain.
//
// A Domain is incompatible with the __Host- prefix the default names carry, so a cookie name still
// carrying it is DEMOTED (to __Secure- while the cookie stays Secure with Path="/", otherwise to
// the bare name): setting a Domain is an explicit opt-out of host-lock semantics. Note that this
// forfeits the subdomain cookie-tossing protection __Host- provides.
func WithCookieDomain(domain string) HandlerOption {
	return func(h *handlerConfig) { h.cookies = h.cookies.WithDomain(domain) }
}

// WithSameSite overrides the SameSite attribute of the auth cookies.
func WithSameSite(mode http.SameSite) HandlerOption {
	return func(h *handlerConfig) { h.cookies.SameSite = mode }
}

// WithCookiePath sets the path for both the access and refresh cookies.
//
// A path other than "/" is incompatible with the __Host- prefix the default names carry, so a
// cookie name still carrying it is DEMOTED (see WithCookieDomain).
func WithCookiePath(path string) HandlerOption {
	return func(h *handlerConfig) { h.cookies = h.cookies.WithPath(path) }
}

// WithRefreshCookiePath scopes only the refresh cookie (e.g. to a dedicated refresh route).
//
// A path other than "/" is incompatible with the __Host- prefix the default refresh name carries,
// so that name is DEMOTED (see WithCookieDomain).
func WithRefreshCookiePath(path string) HandlerOption {
	return func(h *handlerConfig) { h.cookies = h.cookies.WithRefreshPath(path) }
}

// WithInsecureCookies disables the Secure attribute. Use only for local HTTP development.
//
// Browsers reject a __Host- or __Secure- named cookie that is not Secure, so the cookie names are
// DEMOTED to their bare form ("access_token" / "refresh_token"): the option is an explicit opt-out
// of the prefixed, browser-enforced naming.
//
// Guard against production misuse: because there is no host at construction time, the handlers
// inspect each request and, when insecure cookies are served to a host that is not
// localhost/loopback over a plaintext (non-TLS) connection, emit a single WARN-level
// event.InsecureCookieMisuse to the sink registered with WithHandlerEventSink. This is a
// warning, not a refusal — a reverse proxy that terminates TLS and forwards plaintext to the
// app legitimately presents a non-loopback Host with no r.TLS, and refusing would brick it. The
// warning fires at most once per handler instance (it is not per-request spam). To silence it
// for legitimate non-loopback HTTP dev, omit WithHandlerEventSink (a nil sink is a no-op),
// serve over a loopback host, or terminate TLS so r.TLS is set.
func WithInsecureCookies() HandlerOption {
	return func(h *handlerConfig) { h.cookies = h.cookies.WithInsecure() }
}

// WithSuccessRedirect makes the handler reply with a 303 redirect to url on success
// (instead of 204 No Content).
func WithSuccessRedirect(url string) HandlerOption {
	return func(h *handlerConfig) { h.successURL = url }
}

// WithFailureRedirect makes the handler reply with a 303 redirect to url (with an
// ?error=<code> query parameter) on failure, instead of an HTTP error status.
func WithFailureRedirect(url string) HandlerOption {
	return func(h *handlerConfig) { h.failureURL = url }
}

// WithPersistentRefresh re-issues the rotated refresh cookie as a PERSISTENT cookie
// (Max-Age aligned to the refresh expiry). By default the rotated refresh cookie is a
// session cookie, since this endpoint cannot recover the original remember_me choice from
// the request and must not silently upgrade a session-only cookie to a persistent one.
func WithPersistentRefresh() HandlerOption {
	return func(h *handlerConfig) { h.persistRefresh = true }
}

// WithTenantResolver derives the tenant from the request to scope store operations in
// multi-tenant deployments.
func WithTenantResolver(f func(*http.Request) string) HandlerOption {
	return func(h *handlerConfig) { h.tenantResolver = f }
}

// WithTrustedOrigins widens the same-origin CSRF check on the cookie-driven token endpoints
// (RefreshHandler, LogoutHandler) to additional hosts.
//
// These are state-changing POSTs authenticated purely by the refresh cookie, so SameSite=Lax
// alone does not fully prevent a forged cross-site refresh/logout. The check is ON BY DEFAULT
// (secure-by-default): even with no trusted origins configured, a request whose Origin — or,
// failing that, Referer — host is not the request's own Host is rejected with 403, and a POST
// carrying neither header is treated as untrusted. This option adds further allowed hosts (e.g. a
// front-end served from another subdomain). Supply hosts WITHOUT scheme, e.g. "app.example.com".
// To disable the check entirely use the explicit WithInsecureNoOriginCheck opt-out.
func WithTrustedOrigins(origins ...string) HandlerOption {
	return func(h *handlerConfig) {
		h.trustedOrigins = make(map[string]bool, len(origins))
		for _, o := range origins {
			h.trustedOrigins[o] = true
		}
	}
}

// RefreshHandler builds an HTTP handler that rotates the refresh token carried in the
// refresh cookie: it consumes the old token, issues a fresh access+refresh pair within the
// same family, and rewrites both cookies. A replayed token causes family revocation and a
// rejection. On failure the cookies are cleared, except for the benign concurrency case
// (ErrRefreshConcurrent: a parallel request won the rotation race within the reuse grace),
// where only the stale access cookie is cleared so the winner's fresh refresh cookie survives.
func RefreshHandler[C any](rotator Rotator[C], opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return func(w http.ResponseWriter, r *http.Request) {
		cfg.warnIfInsecureMisuse(r)
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !cfg.originAllowed(r) {
			cfg.fail(w, r, http.StatusForbidden, "cross_site_blocked")
			return
		}

		refreshToken, ok := cfg.cookies.Refresh(r)
		if !ok {
			cfg.cookies.Clear(w)
			cfg.fail(w, r, http.StatusUnauthorized, "missing_refresh_token")
			return
		}

		pair, err := rotator.Rotate(r.Context(), cfg.tenant(r), refreshToken)
		if err != nil {
			// ErrRefreshConcurrent is benign concurrency: a parallel request won the rotation
			// race and already minted a fresh, valid refresh cookie for this client (the family
			// is NOT poisoned). Clearing the refresh cookie would wipe the winner's freshly
			// issued cookie and log the user out — the lockout the reuse grace prevents. Drop
			// only the stale access cookie and reject; the client retries with the live cookie.
			if errors.Is(err, ErrRefreshConcurrent) {
				cfg.cookies.ClearAccess(w)
				cfg.fail(w, r, http.StatusUnauthorized, refreshErrorCode(err))
				return
			}
			// Any other failure (after-grace reuse already revoked the family, expired, not
			// found): clear the client's now-useless cookies.
			cfg.cookies.Clear(w)
			cfg.fail(w, r, http.StatusUnauthorized, refreshErrorCode(err))
			return
		}

		cfg.cookies.SetAccess(w, pair.AccessToken)
		cfg.cookies.SetRefresh(w, pair.RefreshToken, pair.RefreshTokenExpiresAt, cfg.persistRefresh)
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// LogoutHandler builds an HTTP handler that revokes the entire rotation family of the
// presented refresh token (global logout) and clears the auth cookies.
//
// Idempotency: if the token is absent or already gone (ErrRefreshTokenNotFound) the
// handler clears the cookies and returns success (204 / success redirect), so a
// client-side double-logout does not fail.
//
// Store errors are surfaced: if FindRefreshToken returns any error other than
// ErrRefreshTokenNotFound, or if RevokeFamily returns an error, the cookies are still
// cleared (the local session ends) but the handler responds with 500 (or with a
// failure redirect carrying error=logout_incomplete when WithFailureRedirect is set).
// This lets clients retry and lets monitoring catch un-revoked families.
func LogoutHandler(revoker FamilyRevoker, opts ...HandlerOption) http.HandlerFunc {
	cfg := newHandlerConfig(opts)
	return func(w http.ResponseWriter, r *http.Request) {
		cfg.warnIfInsecureMisuse(r)
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !cfg.originAllowed(r) {
			cfg.fail(w, r, http.StatusForbidden, "cross_site_blocked")
			return
		}

		if refreshToken, ok := cfg.cookies.Refresh(r); ok {
			tenantID := cfg.tenant(r)
			hash := HashToken(refreshToken)
			rt, err := revoker.FindRefreshToken(r.Context(), tenantID, hash)
			switch {
			case err == nil:
				// Token found: revoke the whole rotation family.
				if err := revoker.RevokeFamily(r.Context(), tenantID, rt.FamilyID); err != nil {
					cfg.cookies.Clear(w)
					cfg.fail(w, r, http.StatusInternalServerError, "logout_incomplete")
					return
				}
				// Audit the user sign-out. Reuse the existing logout event type with
				// Reason="token_logout" (symmetric with sessions/service.go), carrying the client
				// IP/User-Agent. A nil sink is a no-op and emission never alters the response.
				cfg.emitLogout(r, tenantID, rt.UserID.String())
			case errors.Is(err, ErrRefreshTokenNotFound):
				// Token already gone: idempotent success — fall through. The double-logout path
				// emits nothing: there is no family to revoke and no fresh sign-out to record, and
				// a benign event here would let a client manufacture spurious logout records by
				// replaying the call.
			default:
				// Unexpected store error: clear cookies but report failure so the
				// client knows the server-side revocation did not happen.
				cfg.cookies.Clear(w)
				cfg.fail(w, r, http.StatusInternalServerError, "logout_incomplete")
				return
			}
		}

		cfg.cookies.Clear(w)
		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}

// originAllowed reports whether the request passes the CSRF origin check. The check is ON BY
// DEFAULT: a request is allowed only when its Origin (or Referer fallback) host is the request's
// own Host or an allowlisted host, and a POST carrying neither header is treated as untrusted.
// The explicit WithInsecureNoOriginCheck opt-out restores the pre-v1 accept-all behavior.
func (cfg handlerConfig) originAllowed(r *http.Request) bool {
	// Secure-by-default CSRF check (TASK-025): allowed only when the Origin/Referer host matches
	// the request Host or an explicitly trusted origin; a missing origin host is rejected.
	// WithInsecureNoOriginCheck restores the pre-v1 accept-all behavior. Origin-host parsing is
	// shared via httputil (TASK-024), but the strict allow/deny policy is enforced here — NOT
	// httputil.OriginAllowed, whose empty-allowlist default is permissive.
	if cfg.insecureNoOriginCheck {
		return true
	}
	host := httputil.RequestOriginHost(r)
	if host == "" {
		return false
	}
	return host == r.Host || cfg.trustedOrigins[host]
}

// tenant returns the tenant derived from the request's resolver, or "" when no resolver is
// configured (the single-tenant default partition).
func (cfg handlerConfig) tenant(r *http.Request) string {
	if cfg.tenantResolver == nil {
		return ""
	}
	return cfg.tenantResolver(r)
}

// fail emits a failure response: a 303 redirect to the configured failure URL (carrying an
// ?error=<code> param) when set, otherwise an HTTP error with the given status.
func (cfg handlerConfig) fail(w http.ResponseWriter, r *http.Request, status int, code string) {
	httputil.Fail(w, r, cfg.failureURL, status, code)
}

// emitLogout records a successful token-model sign-out on the configured sink (a nil sink is a
// no-op via event.Emit). It reuses the existing event.Logout type with Reason="token_logout" so
// the token/refresh logout joins the same logout stream as sessions/service.go, and threads the
// client IP/User-Agent derived from the request. The event carries no token, hash or raw input —
// only the tenant, the user UUID and the transport metadata.
func (cfg handlerConfig) emitLogout(r *http.Request, tenantID, userID string) {
	rc := requestContext(r)
	event.Emit(r.Context(), cfg.events, event.Event{
		Type:     event.Logout,
		TenantID: tenantID,
		UserID:   userID,
		Reason:   "token_logout",
		Attrs:    rc.ApplyTo(nil),
	})
}

// requestContext builds the optional event.RequestContext that the logout handler stamps onto the
// emitted event.Logout, so the client IP and User-Agent land in the event Attrs.
//
// The IP is taken from r.RemoteAddr (host part only) — the address of the immediate peer. egauth
// deliberately does NOT trust X-Forwarded-For / Forwarded here: those headers are spoofable unless
// a trusted reverse proxy terminates them, and egauth cannot know the deployment's proxy topology.
// This mirrors identity.requestContext and the untrusted-RemoteAddr stance of ratelimit.ClientIP.
func requestContext(r *http.Request) event.RequestContext {
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}
	return event.RequestContext{IP: ip, UserAgent: r.UserAgent()}
}

func refreshErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrRefreshConcurrent):
		// Benign concurrency, not theft: a parallel request already rotated the token. Distinct
		// from token_reuse_detected so clients can retry with the winner's fresh cookie. Checked
		// before ErrRefreshTokenReused since ErrRefreshConcurrent wraps it.
		return "concurrent_refresh"
	case errors.Is(err, ErrRefreshTokenReused):
		return "token_reuse_detected"
	case errors.Is(err, ErrTokenExpired):
		return "refresh_expired"
	case errors.Is(err, ErrRefreshTokenNotFound):
		return "invalid_refresh_token"
	default:
		return "refresh_failed"
	}
}

// WithInsecureNoOriginCheck disables the CSRF same-origin check on the cookie-driven token
// endpoints (RefreshHandler, LogoutHandler).
//
// By default these handlers reject any state-changing POST whose Origin (or Referer fallback)
// host is neither the request's own Host nor an explicitly trusted origin (see WithTrustedOrigins),
// because they are authenticated purely by the refresh cookie and SameSite=Lax alone does not
// fully prevent a forged cross-site refresh/logout.
//
// This option turns that protection OFF, restoring the pre-v1 behavior where every origin is
// accepted. It is named "Insecure" deliberately: only reach for it when CSRF is handled by a
// separate layer (e.g. a synchronizer-token middleware) or in trusted test setups. Prefer
// WithTrustedOrigins to extend, rather than remove, the allowlist.
func WithInsecureNoOriginCheck() HandlerOption {
	return func(h *handlerConfig) { h.insecureNoOriginCheck = true }
}

// WithEventSink registers a security-event sink (see the event package) for the tokens handlers.
// It serves two purposes:
//
//   - LogoutHandler emits event.Logout (Reason="token_logout") after it successfully revokes the
//     rotation family, carrying the client IP/User-Agent so the token-model sign-out is audited
//     symmetrically with the session-model logout in sessions/service.go.
//   - The WithInsecureCookies guard emits a WARN-level event.InsecureCookieMisuse (once per
//     handler) when insecure cookies are served to a non-loopback host over a non-TLS request.
//
// A nil sink (the default) makes every emission a no-op, and emission never changes the handler's
// client-visible behaviour. This is the handler-level counterpart to the service-level
// WithEventSink found on the other egauth packages.
func WithEventSink(sink event.Sink) HandlerOption {
	return func(h *handlerConfig) { h.events = sink }
}

// WithHandlerEventSink is a deprecated alias for WithEventSink, kept so existing call sites keep
// compiling. Prefer WithEventSink.
//
// Deprecated: use WithEventSink.
func WithHandlerEventSink(sink event.Sink) HandlerOption {
	return WithEventSink(sink)
}

// warnIfInsecureMisuse emits a one-shot WARN event when the handler is configured with insecure
// (non-Secure) cookies yet is serving a request that looks like production: a non-loopback Host
// over a plaintext (non-TLS) connection. It is the honest "is this prod?" signal — there is no
// host at construction time, only at request time (r.Host / r.TLS). It deliberately WARNs rather
// than refusing: a legitimate reverse proxy that terminates TLS and forwards plaintext to the app
// presents a non-loopback Host with r.TLS == nil, and refusing would brick that setup. The
// warning fires at most once per handler instance (sync.Once), so it never spams per request.
func (cfg handlerConfig) warnIfInsecureMisuse(r *http.Request) {
	if !cfg.cookies.Insecure {
		return
	}
	// A TLS request is genuinely encrypted; insecure cookies there are not the misuse we guard.
	if r.TLS != nil {
		return
	}
	if isLoopbackHost(r.Host) {
		return
	}
	once := cfg.insecureWarnedOnce
	if once == nil {
		// Defensive: a handler built without newHandlerConfig still must not panic; emit every
		// time rather than crash (the supported path always has a non-nil Once).
		once = &sync.Once{}
	}
	once.Do(func() {
		event.Emit(r.Context(), cfg.events, event.Event{
			Type:     event.InsecureCookieMisuse,
			TenantID: cfg.tenant(r),
			Reason:   "non_loopback_plaintext_host",
			Attrs:    map[string]any{"host": r.Host},
		})
	})
}

// isLoopbackHost reports whether host (an HTTP Host header value, optionally with a port) refers
// to the local machine — localhost or a loopback IP literal. These are the legitimate local-HTTP
// development targets for WithInsecureCookies, so they must never trigger the misuse warning.
func isLoopbackHost(host string) bool {
	if host == "" {
		// No Host at all is not a host we can call "production"; stay quiet.
		return true
	}
	h := host
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		h = hostOnly
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
