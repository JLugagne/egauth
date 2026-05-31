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
		FindSessionByHashFunc: func(ctx context.Context, hash string, opts ...sessions.Option) (*sessions.Session, error) {
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
			FindSessionByHashFunc: func(ctx context.Context, hash string, opts ...sessions.Option) (*sessions.Session, error) {
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
