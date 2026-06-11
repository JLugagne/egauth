package sessions

import (
	"net/http"
	"strings"

	"github.com/JLugagne/egauth"
)

// AuthenticatedSessionHandlerFunc is a handler that receives the authenticated actor and session explicitly.
type AuthenticatedSessionHandlerFunc func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, session Session)

// RequireSession is a middleware that validates a session token from cookies or the Authorization header.
// It injects the Actor and Session explicitly into the handler.
// The tenant is resolved via the optional tenantResolver. When no resolver is configured the empty
// string (single-tenant default partition) is used. When a resolver IS configured it must return a
// non-empty tenant ID; an empty return is treated as a resolution failure and the request is rejected
// with 401 rather than falling open into the "" partition.
func RequireSession(svc Service, handler AuthenticatedSessionHandlerFunc, opts ...HandlerOption) http.HandlerFunc {
	cfg := handlerConfig{}
	for _, o := range opts {
		o(&cfg)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		token := ""

		// 1. Try Cookie
		cookie, err := r.Cookie("session_token")
		if err == nil {
			token = cookie.Value
		}

		// 2. Try Authorization Header
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if token == "" {
			http.Error(w, "Unauthorized: missing session token", http.StatusUnauthorized)
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
