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
		SecretKey:  "integration-secret-key----------", // 32 bytes
		Issuer:     "egauth-integration",
		AccessTTL:  5 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	}
	svc := jwt.New[IntegrationCustomClaims](cfg)

	t.Run("Scenario: Valid token issuance and explicit extraction via handler", func(t *testing.T) {
		subject := uuid.Must(uuid.NewV7())
		tenantID := "" // single-tenant middleware (no resolver) authenticates only empty-tenant tokens
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
			Subject: uuid.Must(uuid.NewV7()),
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
		// InsecureAllowWeakKey is set because key-length is not the subject of this test.
		otherSvc := jwt.New[IntegrationCustomClaims](jwt.Config[IntegrationCustomClaims]{
			Store:                store,
			SecretKey:            "different-secret-key",
			AccessTTL:            5 * time.Minute,
			InsecureAllowWeakKey: true,
		})

		pair, err := otherSvc.IssueTokenPair(ctx, tokens.Claims[IntegrationCustomClaims]{
			Subject: uuid.Must(uuid.NewV7()),
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

// TestRequireAuthRejectsTenantTokenWithoutResolver locks in the fail-closed
// behavior of single-tenant middleware: a token minted for a real (non-empty)
// tenant must NOT authenticate through the no-resolver RequireAuth path. The
// middleware calls VerifyAccessTokenForTenant(ctx, "", token), which returns
// ErrTenantMismatch when the token's signed TenantID is not "", yielding 401
// and never invoking the protected handler.
func TestRequireAuthRejectsTenantTokenWithoutResolver(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore[IntegrationCustomClaims]()

	cfg := jwt.Config[IntegrationCustomClaims]{
		Store:      store,
		SecretKey:  "integration-secret-key----------", // 32 bytes
		Issuer:     "egauth-integration",
		AccessTTL:  5 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	}
	svc := jwt.New[IntegrationCustomClaims](cfg)

	// Issue a token under a NON-EMPTY tenant.
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[IntegrationCustomClaims]{
		Subject:  uuid.Must(uuid.NewV7()),
		TenantID: "tenant-xyz",
		Custom:   IntegrationCustomClaims{Subscription: "premium"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, pair.AccessToken)

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rec := httptest.NewRecorder()

	var called bool
	// No tenant resolver configured -> single-tenant middleware path.
	handler := tokens.RequireAuth[IntegrationCustomClaims](svc, func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, custom IntegrationCustomClaims) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler.ServeHTTP(rec, req)

	// Fail closed: tenant-scoped token rejected, handler never reached.
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, called)
}
