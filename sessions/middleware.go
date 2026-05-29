package sessions

import (
	"net/http"
	"strings"

	"github.com/JLugagne/libauth"
)

// AuthenticatedSessionHandlerFunc is a handler that receives the authenticated actor and session explicitly.
type AuthenticatedSessionHandlerFunc func(w http.ResponseWriter, r *http.Request, actor libauth.Actor, session Session)

// RequireSession is a middleware that validates a session token from cookies or the Authorization header.
// It injects the Actor and Session explicitly into the handler.
func RequireSession(svc Service, handler AuthenticatedSessionHandlerFunc) http.HandlerFunc {
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

		// Validate session (Note: here we don't have tenant yet, so we hope the service can find it)
		session, err := svc.ValidateSession(r.Context(), token)
		if err != nil {
			http.Error(w, "Unauthorized: invalid or expired session", http.StatusUnauthorized)
			return
		}

		actor := libauth.Actor{
			UserID:   session.UserID,
			TenantID: session.TenantID,
		}

		// Call the handler with explicit arguments
		handler(w, r, actor, *session)
	}
}
