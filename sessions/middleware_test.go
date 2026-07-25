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
	userID := uuid.Must(uuid.NewV7())
	tenantID := "tenant-1"
	token := "valid_token"

	mockStore := &storetest.MockStore{
		FindSessionByHashFunc: func(ctx context.Context, tID string, hash string) (*sessions.Session, error) {
			// In service, hash is hex(sha256(token))
			return &sessions.Session{
				UserID:    userID,
				TenantID:  tenantID,
				ExpiresAt: time.Now().Add(time.Hour),
				CreatedAt: time.Now(),
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
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// The secure default cookie name is now "__Host-session_token".
		req.AddCookie(&http.Cookie{Name: sessions.DefaultSessionCookieName, Value: token})
		rr := httptest.NewRecorder()

		middleware := sessions.RequireSession(svc, handler)
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Valid session in header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		middleware := sessions.RequireSession(svc, handler)
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("No token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
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

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: sessions.DefaultSessionCookieName, Value: "invalid"})
		rr := httptest.NewRecorder()

		middleware := sessions.RequireSession(svcError, func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, session sessions.Session) {})
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Invalid Authorization header prefix", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
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
	userID := uuid.Must(uuid.NewV7())
	token := "valid_token"

	// A session exists under the "" partition (e.g. a bootstrap/admin session).
	mockStore := &storetest.MockStore{
		FindSessionByHashFunc: func(ctx context.Context, tID string, hash string) (*sessions.Session, error) {
			return &sessions.Session{
				UserID:    userID,
				TenantID:  "",
				ExpiresAt: time.Now().Add(time.Hour),
				CreatedAt: time.Now(),
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

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessions.DefaultSessionCookieName, Value: token})
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
	userID := uuid.Must(uuid.NewV7())
	tenantID := "tenant-1"
	token := "valid_token"

	mockStore := &storetest.MockStore{
		FindSessionByHashFunc: func(ctx context.Context, tID string, hash string) (*sessions.Session, error) {
			return &sessions.Session{
				UserID:    userID,
				TenantID:  tenantID,
				ExpiresAt: time.Now().Add(time.Hour),
				CreatedAt: time.Now(),
			}, nil
		},
	}
	svc := sessions.NewService(mockStore)

	handler := func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, session sessions.Session) {
		w.WriteHeader(http.StatusOK)
	}

	t.Run("WithCookieName reads from custom cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-session", Value: token})
		rr := httptest.NewRecorder()

		middleware := sessions.RequireSession(svc, handler, sessions.WithCookieName("__Host-session"))
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code, "should authenticate using the custom __Host-session cookie")
	})

	t.Run("WithCookieName ignores the default session_token cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// Only the old hardcoded name is present; the custom name is absent.
		req.AddCookie(&http.Cookie{Name: "session_token", Value: token})
		rr := httptest.NewRecorder()

		middleware := sessions.RequireSession(svc, handler, sessions.WithCookieName("__Host-session"))
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code, "should not fall back to session_token when WithCookieName is set")
	})
}

// TestMiddleware_SecureCookieNameIsDefault proves the secure-by-default behavior: without any
// option, RequireSession reads the session token from the hardened "__Host-session_token" cookie
// (DefaultSessionCookieName) and ignores the legacy plain "session_token" name. WithCookieName
// remains an escape hatch for deployments that genuinely cannot use a __Host- cookie.
func TestMiddleware_SecureCookieNameIsDefault(t *testing.T) {
	userID := uuid.Must(uuid.NewV7())
	tenantID := "tenant-1"
	token := "valid_token"

	mockStore := &storetest.MockStore{
		FindSessionByHashFunc: func(ctx context.Context, tID string, hash string) (*sessions.Session, error) {
			return &sessions.Session{
				UserID:    userID,
				TenantID:  tenantID,
				ExpiresAt: time.Now().Add(time.Hour),
				CreatedAt: time.Now(),
			}, nil
		},
	}
	svc := sessions.NewService(mockStore)

	handler := func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, session sessions.Session) {
		w.WriteHeader(http.StatusOK)
	}

	t.Run("the default name carries the __Host- prefix", func(t *testing.T) {
		assert.Equal(t, "__Host-session_token", sessions.DefaultSessionCookieName)
	})

	t.Run("default reads the __Host- cookie without any option", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: sessions.DefaultSessionCookieName, Value: token})
		rr := httptest.NewRecorder()

		middleware := sessions.RequireSession(svc, handler)
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code, "the secure __Host- cookie must be read by default")
	})

	t.Run("default ignores the legacy plain session_token cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// Only the old hardcoded name is present; the secure default name is absent.
		req.AddCookie(&http.Cookie{Name: "session_token", Value: token})
		rr := httptest.NewRecorder()

		middleware := sessions.RequireSession(svc, handler)
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code, "the insecure plain name must not be read by default")
	})

	t.Run("WithCookieName escape hatch overrides the secure default", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: token})
		rr := httptest.NewRecorder()

		// A consumer that genuinely cannot use __Host- opts back to the plain name.
		middleware := sessions.RequireSession(svc, handler, sessions.WithCookieName("session_token"))
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code, "WithCookieName must let a consumer opt out of the __Host- default")
	})
}
