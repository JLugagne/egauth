package sessions

import (
	"net/http"
	"strings"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/httputil"
	"github.com/JLugagne/egauth/origin"
)

// DefaultSessionCookieName is the secure-by-default cookie name RequireSession reads the
// session token from. It carries the browser-enforced __Host- prefix, which guarantees the
// cookie is Secure, has no Domain attribute, and is scoped to Path=/ — host-locking it so a
// sibling/subdomain cannot plant a same-named cookie (cookie-tossing session fixation). Use
// WithCookieName to override it only when the deployment genuinely cannot meet the __Host-
// requirements.
const DefaultSessionCookieName = "__Host-session_token"

// AuthenticatedSessionHandlerFunc is a handler that receives the authenticated actor and session explicitly.
type AuthenticatedSessionHandlerFunc func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, session Session)

// RequireSession is a middleware that validates a session token from cookies or the Authorization header.
// It injects the Actor and Session explicitly into the handler.
// The tenant is resolved via the optional tenantResolver. When no resolver is configured the empty
// string (single-tenant default partition) is used. When a resolver IS configured it must return a
// non-empty tenant ID; an empty return is treated as a resolution failure and the request is rejected
// with 401 rather than falling open into the "" partition.
//
// The cookie name used to look up the session token defaults to the hardened "__Host-session_token"
// (DefaultSessionCookieName). The __Host- prefix is browser-enforced: the cookie must be Secure, must
// carry no Domain attribute, and must have Path=/, which host-locks it and defeats subdomain/sibling-host
// cookie-tossing session fixation. This is the secure default — consumers no longer have to opt in.
// Use WithCookieName only as an escape hatch when the deployment genuinely cannot use a __Host- cookie
// (e.g. a path-scoped cookie, or a non-HTTPS internal environment). Overriding to a name that violates
// the __Host- rules is the consumer's explicit choice; the default remains safe.
//
// A cookie-authenticated state-changing request (POST/PUT/PATCH/DELETE) is additionally subject to a
// strict same-origin CSRF check, ON BY DEFAULT: its Origin — or, failing that, Referer — host must
// equal the request's own Host or an allow-listed origin (see WithTrustedOrigins), otherwise it is
// rejected with 403 cross_site_blocked. A request carrying neither header is treated as untrusted.
// Without this gate the session cookie is an ambient credential that the browser attaches to forged
// cross-site requests. Requests authenticated with an Authorization: Bearer token are EXEMPT: a
// Bearer token is a non-ambient credential that a cross-site attacker cannot read or make the browser
// attach, so CSRF does not apply to header authentication. Use WithInsecureNoOriginCheck only for an
// explicitly documented opt-out.
func RequireSession(svc Service, handler AuthenticatedSessionHandlerFunc, opts ...HandlerOption) http.HandlerFunc {
	cfg := handlerConfig{
		cookieName: DefaultSessionCookieName,
	}
	for _, o := range opts {
		o(&cfg)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		token := ""
		fromCookie := false

		// 1. Try Cookie — the default name carries the __Host- prefix, which browsers
		// enforce as host-locked/Secure/no-Domain, defeating cookie-tossing fixation.
		// A consumer that opted out via WithCookieName gets whatever name they chose.
		cookie, err := r.Cookie(cfg.cookieName)
		if err == nil && cookie.Value != "" {
			token = cookie.Value
			fromCookie = true
		}

		// 2. Try Authorization Header
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if after, ok := strings.CutPrefix(authHeader, "Bearer "); ok {
				token = after
			}
		}

		if token == "" {
			http.Error(w, "Unauthorized: missing session token", http.StatusUnauthorized)
			return
		}

		// 3. CSRF origin gate. The session cookie is ambient: the browser attaches it to
		// requests initiated by any origin, so a cookie-authenticated unsafe request is only
		// trusted when its Origin (or Referer fallback) host is the request's own Host or an
		// allow-listed origin. A Bearer token is non-ambient — a cross-site attacker cannot
		// read it to attach it — so header authentication is not CSRF-exposed and skips the
		// gate. This runs before ValidateSession so a forged request never reaches the store
		// or the handler.
		if fromCookie && isUnsafeMethod(r.Method) && !cfg.originAllowed(r) {
			http.Error(w, "cross_site_blocked", http.StatusForbidden)
			return
		}

		// Resolve the tenant. When a resolver is configured it MUST map the
		// request to a non-empty tenant ID; an empty return means the resolver
		// could not determine the tenant (e.g. an unmapped Host, a missing path
		// segment, or an absent claim). Failing open into the "" partition would
		// let such requests reach sessions created under the single-tenant
		// default (bootstrap/admin sessions), so we reject them instead. The ""
		// partition is used only when no resolver is configured at all.
		tenantID := ""
		if cfg.tenantResolver != nil {
			tenantID = cfg.tenantResolver(r)
			if tenantID == "" {
				http.Error(w, "Unauthorized: unresolved tenant", http.StatusUnauthorized)
				return
			}
		}

		session, err := svc.ValidateSession(r.Context(), tenantID, token)
		if err != nil {
			http.Error(w, "Unauthorized: invalid or expired session", http.StatusUnauthorized)
			return
		}

		actor := egauth.Actor{
			UserID:   session.UserID,
			TenantID: session.TenantID,
		}

		// Call the handler with explicit arguments
		handler(w, r, actor, *session)
	}
}

// HandlerOption configures RequireSession behaviour.
type HandlerOption func(*handlerConfig)

type handlerConfig struct {
	tenantResolver func(*http.Request) string
	// cookieName is the HTTP cookie name to look up for the session token.
	// It defaults to DefaultSessionCookieName ("__Host-session_token"), the
	// hardened host-locked name. WithCookieName overrides it as an escape hatch.
	cookieName string
	// trustedOrigins widens the strict same-origin CSRF allowlist (see
	// WithTrustedOrigins); the check remains on by default with an empty allowlist.
	trustedOrigins map[string]bool
	// insecureNoOriginCheck disables the strict same-origin CSRF check (see
	// WithInsecureNoOriginCheck). By default the check is ON even with an empty
	// trustedOrigins allowlist.
	insecureNoOriginCheck bool
}

// WithTenantResolver sets a function that extracts the tenant ID from an incoming request
// (e.g. from a host header, path segment, or JWT claim). The session lookup is scoped to
// the returned tenant. A configured resolver MUST return a non-empty tenant ID for any
// request it can map; returning "" is interpreted as "tenant could not be resolved" and the
// middleware rejects the request with 401 instead of falling back to the single-tenant ("")
// partition. When no resolver is set at all, the empty string (single-tenant partition) is used.
func WithTenantResolver(f func(*http.Request) string) HandlerOption {
	return func(c *handlerConfig) { c.tenantResolver = f }
}

// WithCookieName overrides the HTTP cookie name that RequireSession looks up for the session
// token. The secure default is DefaultSessionCookieName ("__Host-session_token"), whose __Host-
// prefix browsers enforce as host-locked, Secure, and Domain-less — preventing subdomain/sibling-host
// cookie-tossing session fixation. This option is an escape hatch: use it only when the deployment
// genuinely cannot satisfy the __Host- requirements (e.g. a path-scoped cookie, or local plain-HTTP
// development). Overriding to a name that drops the __Host- prefix forfeits the host-lock hardening;
// that is the consumer's explicit choice.
func WithCookieName(name string) HandlerOption {
	return func(c *handlerConfig) { c.cookieName = name }
}

// WithTrustedOrigins widens the CSRF same-origin check applied to cookie-authenticated
// state-changing requests (POST/PUT/PATCH/DELETE) to additional hosts.
//
// The check is ON BY DEFAULT (secure-by-default): even with no trusted origins configured, a
// cookie-authenticated unsafe request whose Origin — or, failing that, Referer — host is not
// the request's own Host is rejected with 403 cross_site_blocked, and a request carrying
// neither header is treated as untrusted. This option adds further allowed hosts (e.g. a
// front-end served from another subdomain). Entries may be full origins
// ("https://app.example.com") or bare hosts ("app.example.com"); both are normalized to the bare
// host before matching, so the documented full-origin form works when the middleware is wired
// directly. Requests authenticated with an Authorization: Bearer header are
// non-ambient and are never subject to the check. To disable the check entirely use the
// explicit WithInsecureNoOriginCheck opt-out.
func WithTrustedOrigins(origins ...string) HandlerOption {
	return func(c *handlerConfig) {
		c.trustedOrigins = origin.TrustedSet(origins...)
	}
}

// WithInsecureNoOriginCheck disables the CSRF same-origin check on RequireSession.
//
// By default RequireSession rejects any cookie-authenticated state-changing request
// (POST/PUT/PATCH/DELETE) whose Origin (or Referer fallback) host is neither the request's
// own Host nor an explicitly trusted origin (see WithTrustedOrigins), because the session
// cookie is ambient and SameSite=Lax alone does not prevent a forged same-site request.
//
// This option turns that protection OFF, restoring the pre-v1 behavior where every origin is
// accepted. It is named "Insecure" deliberately: only reach for it when CSRF is handled by a
// separate layer (e.g. a synchronizer-token middleware) or in trusted test setups. Prefer
// WithTrustedOrigins to extend, rather than remove, the allowlist. Bearer-header
// authentication is unaffected either way.
func WithInsecureNoOriginCheck() HandlerOption {
	return func(c *handlerConfig) { c.insecureNoOriginCheck = true }
}

// originAllowed reports whether the request passes the CSRF origin check. The check is ON BY
// DEFAULT: a request is allowed only when its Origin (or Referer fallback) host is the
// request's own Host or an allowlisted host, and a request carrying neither header is treated
// as untrusted. Cross-scheme protection is enforced via httputil.OriginAllowed. The explicit
// WithInsecureNoOriginCheck opt-out restores the accept-all behavior.
func (cfg handlerConfig) originAllowed(r *http.Request) bool {
	if cfg.insecureNoOriginCheck {
		return true
	}
	return httputil.OriginAllowed(r, cfg.trustedOrigins)
}

// isUnsafeMethod reports whether method is a state-changing HTTP method subject to the CSRF
// origin check. GET/HEAD/OPTIONS and any other method are not gated: the check exists to stop
// cross-site state changes, not reads.
func isUnsafeMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}
