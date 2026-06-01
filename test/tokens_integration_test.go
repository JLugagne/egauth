package internal_test

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

type IntegrationCustomClaims struct {
	Subscription string `json:"subscription"`
}

func TestTokenLifecycleIntegration(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore[IntegrationCustomClaims]()

	// Instantiate the JWT service
	cfg := jwt.Config[IntegrationCustomClaims]{
		Store:      store,
		SecretKey:  "integration-secret-key",
		Issuer:     "egauth-integration",
		AccessTTL:  5 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	}
	svc := jwt.New[IntegrationCustomClaims](cfg)

	t.Run("Scenario: Valid token issuance and explicit extraction via handler", func(t *testing.T) {
		subject := uuid.New()
		tenantID := "tenant-xyz"
		custom := IntegrationCustomClaims{Subscription: "premium"}

		// 1. Issue Token
		claims := tokens.Claims[IntegrationCustomClaims]{
			Subject:  subject,
			TenantID: tenantID,
			Custom:   custom,
		}

		pair, err := svc.IssueTokenPair(ctx, claims)
		require.NoError(t, err)
		require.NotEmpty(t, pair.AccessToken)

		// 2. Make HTTP request with Token
		req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
		req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
		rec := httptest.NewRecorder()

		var extractedActor egauth.Actor
		var extractedCustom IntegrationCustomClaims
		var called bool

		handler := tokens.RequireAuth[IntegrationCustomClaims](svc, func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, custom IntegrationCustomClaims) {
			extractedActor = actor
			extractedCustom = custom
			called = true
			w.WriteHeader(http.StatusOK)
		})

		handler.ServeHTTP(rec, req)

		// 3. Verify extraction of Actor and Custom Claims
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called)
		assert.Equal(t, subject, extractedActor.UserID)
		assert.Equal(t, tenantID, extractedActor.TenantID)
		assert.Equal(t, custom, extractedCustom)
	})

	t.Run("Scenario: Expired token is rejected", func(t *testing.T) {
		// Create a service that issues immediately expired tokens
		expiredCfg := cfg
		expiredCfg.AccessTTL = -1 * time.Minute
		expiredSvc := jwt.New[IntegrationCustomClaims](expiredCfg)

		pair, err := expiredSvc.IssueTokenPair(ctx, tokens.Claims[IntegrationCustomClaims]{
			Subject: uuid.New(),
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
		req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
		rec := httptest.NewRecorder()

		handler := tokens.RequireAuth[IntegrationCustomClaims](svc, func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, custom IntegrationCustomClaims) {
			w.WriteHeader(http.StatusOK)
		})

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("Scenario: Token with different signature is rejected", func(t *testing.T) {
		otherSvc := jwt.New[IntegrationCustomClaims](jwt.Config[IntegrationCustomClaims]{
			Store:     store,
			SecretKey: "different-secret-key",
			AccessTTL: 5 * time.Minute,
		})

		pair, err := otherSvc.IssueTokenPair(ctx, tokens.Claims[IntegrationCustomClaims]{
			Subject: uuid.New(),
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
		req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
		rec := httptest.NewRecorder()

		handler := tokens.RequireAuth[IntegrationCustomClaims](svc, func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, custom IntegrationCustomClaims) {
			w.WriteHeader(http.StatusOK)
		})

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}
