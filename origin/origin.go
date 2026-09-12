// Package origin exposes egauth's same-origin / CSRF primitive so applications can protect
// their OWN cookie-authenticated routes with exactly the check the built-in handlers apply
// internally.
//
// egauth's handlers (tokens, identity, otp, mfa, passkey, authflow, sessions) enforce a
// strict same-origin check by default. Application routes protected with tokens.RequireAuth
// or tokens.ContextMiddleware did not have an exported way to apply the same check, so
// consumers hand-rolled it and drifted from egauth's semantics. This package closes that gap:
//
//	origin.Middleware(widgetHandler,
//		origin.WithTrustedOrigins("https://app.example.com"),
//	)
//
// The semantics are intentionally exact and fail-closed:
//
//   - the Origin host (or Referer fallback) must equal the request's own Host or an
//     allowlisted host — no substring, suffix or parent-domain matching;
//   - an unsafe method with neither Origin nor Referer is rejected;
//   - an http Origin on an HTTPS request is rejected;
//   - allowlist entries are normalized first, so full origins ("https://app.example.com")
//     and bare hosts ("app.example.com") are equivalent.
package origin

import (
	"net/http"

	"github.com/JLugagne/egauth/internal/httputil"
)

// Allowed reports whether r passes egauth's strict same-origin check against the trusted
// allowlist. It is the exact predicate the built-in handlers use, exported for custom
// routes and middleware. trusted entries are bare hosts; use NormalizeHosts or TrustedSet
// to build the map from full origins or bare hosts.
func Allowed(r *http.Request, trusted map[string]bool) bool {
	return httputil.OriginAllowed(r, trusted)
}

// NormalizeHosts turns trusted-origin entries into the bare hosts Allowed compares against.
// Each entry may be a full origin ("https://app.example.com:8443") or a bare host
// ("app.example.com"): full origins are reduced to their URL host (host or host:port,
// lowercased, with scheme, path, query and userinfo dropped) and bare hosts are validated
// and returned as-is. It returns an error naming the first entry that fails to parse or
// yields no host.
func NormalizeHosts(entries []string) ([]string, error) {
	return httputil.NormalizeHosts(entries)
}

// TrustedSet builds the allowlist map consumed by Allowed, normalizing each entry
// best-effort: entries that are neither a full origin nor a bare host are ignored so an
// option that cannot return an error never fails construction. Use NormalizeHosts when you
// want a loud, validating failure instead (e.g. at config load).
func TrustedSet(entries ...string) map[string]bool {
	trusted := make(map[string]bool, len(entries))
	for _, entry := range entries {
		hosts, err := NormalizeHosts([]string{entry})
		if err != nil {
			continue
		}
		for _, host := range hosts {
			trusted[host] = true
		}
	}
	return trusted
}

// Config configures Middleware.
type Config struct {
	// TrustedOrigins widens the same-origin allowlist beyond the request's own host. Entries
	// may be full origins or bare hosts (see NormalizeHosts).
	TrustedOrigins []string
	// InsecureNoOriginCheck disables the check entirely. It is an explicit, loud opt-out and
	// should be used only for non-browser clients that cannot send Origin/Referer.
	InsecureNoOriginCheck bool
}

// Option customizes Middleware.
type Option func(*Config)

// WithTrustedOrigins widens the same-origin allowlist beyond the request's own host.
// Entries may be full origins ("https://app.example.com") or bare hosts ("app.example.com").
func WithTrustedOrigins(origins ...string) Option {
	return func(c *Config) { c.TrustedOrigins = append(c.TrustedOrigins, origins...) }
}

// WithInsecureNoOriginCheck disables the same-origin check. It exists for parity with the
// handler families' WithInsecureNoOriginCheck; prefer configuring trusted origins.
func WithInsecureNoOriginCheck() Option {
	return func(c *Config) { c.InsecureNoOriginCheck = true }
}

// Middleware wraps next with the same-origin CSRF gate applied to unsafe HTTP methods
// (anything other than GET, HEAD and OPTIONS). A rejected request gets 403 and next is not
// called. Safe methods are never blocked, so reads keep working cross-origin.
func Middleware(next http.Handler, opts ...Option) http.Handler {
	cfg := Config{}
	for _, opt := range opts {
		opt(&cfg)
	}
	trusted := TrustedSet(cfg.TrustedOrigins...)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.InsecureNoOriginCheck || safeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if !Allowed(r, trusted) {
			http.Error(w, "cross_site_blocked", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func safeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
