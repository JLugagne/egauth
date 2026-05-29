package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/libauth"
	"github.com/JLugagne/libauth/tokens"
	"github.com/JLugagne/libauth/tokens/issuertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestRequireAuth(t *testing.T) {
	subject := uuid.New()
	tenantID := "tenant-123"

	mockVerifier := &issuertest.MockVerifier[any]{
		VerifyAccessTokenFunc: func(ctx context.Context, token string) (*tokens.Claims[any], error) {
			if token == "valid-token" {
				return &tokens.Claims[any]{
					Subject:  subject,
					TenantID: tenantID,
				}, nil
			}
			return nil, tokens.ErrInvalidToken
		},
	}

	t.Run("Valid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		rec := httptest.NewRecorder()

		var extractedActor libauth.Actor
		var called bool

		handler := tokens.RequireAuth[any](mockVerifier, func(w http.ResponseWriter, r *http.Request, actor libauth.Actor, custom any) {
			extractedActor = actor
			called = true
			w.WriteHeader(http.StatusOK)
		})

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called)
		assert.Equal(t, subject, extractedActor.UserID)
		assert.Equal(t, tenantID, extractedActor.TenantID)
	})

	t.Run("Missing header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		handler := tokens.RequireAuth[any](mockVerifier, func(w http.ResponseWriter, r *http.Request, actor libauth.Actor, custom any) {
			w.WriteHeader(http.StatusOK)
		})

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("Invalid format", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Basic some-token")
		rec := httptest.NewRecorder()

		handler := tokens.RequireAuth[any](mockVerifier, func(w http.ResponseWriter, r *http.Request, actor libauth.Actor, custom any) {
			w.WriteHeader(http.StatusOK)
		})

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("Invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		rec := httptest.NewRecorder()

		handler := tokens.RequireAuth[any](mockVerifier, func(w http.ResponseWriter, r *http.Request, actor libauth.Actor, custom any) {
			w.WriteHeader(http.StatusOK)
		})

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}
