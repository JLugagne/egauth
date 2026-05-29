package tokens

import (
	"net/http"
	"strings"

	"github.com/JLugagne/libauth"
)

// AuthenticatedHandlerFunc is an HTTP handler that explicitly requires an authenticated
// actor and custom claims as parameters, ensuring business data is never hidden in the context.
type AuthenticatedHandlerFunc[C any] func(w http.ResponseWriter, r *http.Request, actor libauth.Actor, customClaims C)

// RequireAuth wraps an AuthenticatedHandlerFunc to enforce Bearer token verification.
// If valid, it explicitly passes the extracted libauth.Actor and custom claims to the next handler.
func RequireAuth[C any](verifier Verifier[C], next AuthenticatedHandlerFunc[C]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "invalid authorization header format", http.StatusUnauthorized)
			return
		}

		tokenStr := parts[1]

		claims, err := verifier.VerifyAccessToken(r.Context(), tokenStr)
		if err != nil {
			// In a real application, we might want to log this or handle expired differently
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		actor := libauth.Actor{
			UserID:   claims.Subject,
			TenantID: claims.TenantID,
		}

		next(w, r, actor, claims.Custom)
	}
}
