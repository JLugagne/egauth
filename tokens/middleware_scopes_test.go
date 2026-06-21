package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func scopesService() *jwt.Service[struct{}] {
	return jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      memory.NewStore[struct{}](),
		SecretKey:  "scopes-secret-aaaaaaaaaaaaaaaaaaa", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  time.Hour,
		RefreshTTL: time.Hour,
	})
}

// TestWithRequiredScopes is the primary unit test for the scope gate.
// It verifies: missing scope → denied, present → allowed, unset → no effect.
func TestWithRequiredScopes(t *testing.T) {
	svc := scopesService()
	uid := uuid.Must(uuid.NewV7())

	issue := func(scopes ...string) string {
		pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
			Subject: uid,
			Scopes:  scopes,
		})
		require.NoError(t, err)
		return pair.AccessToken
	}

	protected := func(opts ...tokens.AuthOption[struct{}]) http.HandlerFunc {
		return tokens.RequireAuth[struct{}](svc, func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			w.WriteHeader(http.StatusOK)
		}, opts...)
	}

	call := func(h http.HandlerFunc, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}

	t.Run("missing required scope is denied with 403 insufficient_scope", func(t *testing.T) {
		rec := call(protected(tokens.WithRequiredScopes[struct{}]("repo:write")), issue("repo:read"))
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "insufficient_scope")
	})

	t.Run("token with all required scopes is allowed", func(t *testing.T) {
		rec := call(protected(tokens.WithRequiredScopes[struct{}]("repo:read", "repo:write")), issue("repo:read", "repo:write"))
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("token with superset of required scopes is allowed", func(t *testing.T) {
		rec := call(protected(tokens.WithRequiredScopes[struct{}]("repo:read")), issue("repo:read", "repo:write", "ci:trigger"))
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("no scope requirement lets any authenticated token through", func(t *testing.T) {
		// WithRequiredScopes not set — gate is inactive, empty-scoped token must pass.
		rec := call(protected(), issue())
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("multiple required scopes must all be present", func(t *testing.T) {
		gate := tokens.WithRequiredScopes[struct{}]("repo:read", "repo:write", "ci:trigger")

		// Only one of the required scopes present — denied.
		assert.Equal(t, http.StatusForbidden, call(protected(gate), issue("repo:read")).Code)

		// All required scopes present — allowed.
		assert.Equal(t, http.StatusOK, call(protected(gate), issue("repo:read", "repo:write", "ci:trigger")).Code)
	})

	t.Run("token with no scopes is denied when a scope is required", func(t *testing.T) {
		rec := call(protected(tokens.WithRequiredScopes[struct{}]("admin")), issue())
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "insufficient_scope")
	})
}

// TestWithRequiredScopes_ContextMiddleware verifies the scope gate works via ContextMiddleware,
// which uses the same serveAuthenticated path.
func TestWithRequiredScopes_ContextMiddleware(t *testing.T) {
	svc := scopesService()
	uid := uuid.Must(uuid.NewV7())

	issue := func(scopes ...string) string {
		pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
			Subject: uid,
			Scopes:  scopes,
		})
		require.NoError(t, err)
		return pair.AccessToken
	}

	wrapped := func(opts ...tokens.AuthOption[struct{}]) http.Handler {
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		return tokens.ContextMiddleware[struct{}](svc, next, opts...)
	}

	call := func(h http.Handler, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	t.Run("missing scope denied via ContextMiddleware", func(t *testing.T) {
		rec := call(wrapped(tokens.WithRequiredScopes[struct{}]("admin")), issue("user"))
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "insufficient_scope")
	})

	t.Run("matching scope allowed via ContextMiddleware", func(t *testing.T) {
		rec := call(wrapped(tokens.WithRequiredScopes[struct{}]("admin")), issue("admin"))
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
