package sessions_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/sessions"
	"github.com/JLugagne/egauth/sessions/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestMiddleware(t *testing.T) {
	userID := uuid.New()
	tenantID := "tenant-1"
	token := "valid_token"

	mockStore := &storetest.MockStore{
		FindSessionByHashFunc: func(ctx context.Context, tID string, hash string) (*sessions.Session, error) {
			// In service, hash is hex(sha256(token))
			return &sessions.Session{
				UserID:    userID,
				TenantID:  tenantID,
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
	}
	svc := sessions.NewService(mockStore)

	handler := func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, session sessions.Session) {
		assert.Equal(t, userID, actor.UserID)
		assert.Equal(t, tenantID, actor.TenantID)
		w.WriteHeader(http.StatusOK)
	}

	t.Run("Valid session in cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: token})
		rr := httptest.NewRecorder()

		middleware := sessions.RequireSession(svc, handler)
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Valid session in header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		middleware := sessions.RequireSession(svc, handler)
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("No token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware := sessions.RequireSession(svc, func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, session sessions.Session) {})
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Invalid session", func(t *testing.T) {
		mockStoreError := &storetest.MockStore{
			FindSessionByHashFunc: func(ctx context.Context, tID string, hash string) (*sessions.Session, error) {
				return nil, sessions.ErrSessionNotFound
			},
		}
		svcError := sessions.NewService(mockStoreError)

		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: "invalid"})
		rr := httptest.NewRecorder()

		middleware := sessions.RequireSession(svcError, func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, session sessions.Session) {})
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Invalid Authorization header prefix", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Basic something")
		rr := httptest.NewRecorder()

		middleware := sessions.RequireSession(svc, func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, session sessions.Session) {})
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

// TestMiddleware_ResolverEmptyReturnIsRejected proves that when a tenantResolver
// IS configured, an empty-string return (meaning the resolver could not map the
// request to a tenant) must be treated as a resolution failure and rejected with
// a 4xx, NOT silently admitted into the single-tenant ("") partition.
func TestMiddleware_ResolverEmptyReturnIsRejected(t *testing.T) {
	userID := uuid.New()
	token := "valid_token"

	// A session exists under the "" partition (e.g. a bootstrap/admin session).
	mockStore := &storetest.MockStore{
		FindSessionByHashFunc: func(ctx context.Context, tID string, hash string) (*sessions.Session, error) {
			return &sessions.Session{
				UserID:    userID,
				TenantID:  "",
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
	}
	svc := sessions.NewService(mockStore)

	handlerCalled := false
	handler := func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, session sessions.Session) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}

	// Resolver that cannot map the request (e.g. unmapped Host) and returns "".
	resolver := func(*http.Request) string { return "" }

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: token})
	rr := httptest.NewRecorder()

	middleware := sessions.RequireSession(svc, handler, sessions.WithTenantResolver(resolver))
	middleware.ServeHTTP(rr, req)

	assert.False(t, handlerCalled, "handler must not be invoked when the resolver fails to map a tenant")
	assert.GreaterOrEqual(t, rr.Code, 400, "an unresolved tenant must be rejected with a 4xx")
	assert.Less(t, rr.Code, 500, "rejection must be a client error (4xx), not a server error")
}

// TestMiddleware_WithCookieName is the regression test for TASK-082.
// It proves that RequireSession configured with WithCookieName reads the session
// token from the specified cookie name (e.g. "__Host-session") instead of
// the hardcoded "session_token". This test MUST fail before the fix is applied.
func TestMiddleware_WithCookieName(t *testing.T) {
	userID := uuid.New()
	tenantID := "tenant-1"
	token := "valid_token"

	mockStore := &storetest.MockStore{
		FindSessionByHashFunc: func(ctx context.Context, tID string, hash string) (*sessions.Session, error) {
			return &sessions.Session{
				UserID:    userID,
				TenantID:  tenantID,
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
	}
	svc := sessions.NewService(mockStore)

	handler := func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, session sessions.Session) {
		w.WriteHeader(http.StatusOK)
	}

	t.Run("WithCookieName reads from custom cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-session", Value: token})
		rr := httptest.NewRecorder()

		middleware := sessions.RequireSession(svc, handler, sessions.WithCookieName("__Host-session"))
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code, "should authenticate using the custom __Host-session cookie")
	})

	t.Run("WithCookieName ignores the default session_token cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		// Only the old hardcoded name is present; the custom name is absent.
		req.AddCookie(&http.Cookie{Name: "session_token", Value: token})
		rr := httptest.NewRecorder()

		middleware := sessions.RequireSession(svc, handler, sessions.WithCookieName("__Host-session"))
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code, "should not fall back to session_token when WithCookieName is set")
	})
}
