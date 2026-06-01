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
// The tenant is resolved via the optional tenantResolver; when nil, the empty string is used
// (the single-tenant default partition).
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

		tenantID := ""
		if cfg.tenantResolver != nil {
			tenantID = cfg.tenantResolver(r)
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
// the returned tenant. When not set, the empty string (single-tenant partition) is used.
func WithTenantResolver(f func(*http.Request) string) HandlerOption {
	return func(c *handlerConfig) { c.tenantResolver = f }
}
