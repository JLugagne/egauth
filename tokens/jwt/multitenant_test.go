package jwt_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMultiTenantService builds a Service backed by a tenant-aware in-memory store, used to
// prove the tenant scoping of VerifyRefreshToken / VerifyAPIKey.
func newMultiTenantService(t *testing.T) *jwt.Service[struct{}] {
	t.Helper()
	return jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      memory.NewStore[struct{}](),
		SecretKey:  "multi-tenant-secret-key-for-tests",
		Issuer:     "egauth-test",
		AccessTTL:  5 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	})
}

// TestVerifyRefreshTokenMultiTenant proves a refresh token saved under a non-empty tenant
// verifies only when the matching tenantID is passed, and fails closed (not-found) for a
// wrong tenant AND for the empty tenant.
func TestVerifyRefreshTokenMultiTenant(t *testing.T) {
	ctx := context.Background()
	svc := newMultiTenantService(t)

	const tenant = "tenant-a"
	userID := uuid.New()

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{
		Subject:  userID,
		TenantID: tenant,
	})
	require.NoError(t, err)

	t.Run("matching tenant resolves", func(t *testing.T) {
		claims, err := svc.VerifyRefreshToken(ctx, tenant, pair.RefreshToken)
		require.NoError(t, err)
		assert.Equal(t, userID, claims.Subject)
		assert.Equal(t, tenant, claims.TenantID)
	})

	t.Run("wrong tenant fails closed", func(t *testing.T) {
		_, err := svc.VerifyRefreshToken(ctx, "tenant-b", pair.RefreshToken)
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)
	})

	t.Run("empty tenant fails closed", func(t *testing.T) {
		_, err := svc.VerifyRefreshToken(ctx, "", pair.RefreshToken)
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)
	})
}

// TestVerifyAPIKeyMultiTenant proves an API key saved under a non-empty tenant verifies
// only when the matching tenantID is passed, and fails closed (not-found) for a wrong
// tenant AND for the empty tenant.
func TestVerifyAPIKeyMultiTenant(t *testing.T) {
	ctx := context.Background()
	svc := newMultiTenantService(t)

	const tenant = "tenant-a"
	userID := uuid.New()

	apiKey, err := svc.IssueAPIKey(ctx, "sk_test_", tokens.Claims[struct{}]{
		Subject:  userID,
		TenantID: tenant,
	})
	require.NoError(t, err)

	t.Run("matching tenant resolves", func(t *testing.T) {
		claims, err := svc.VerifyAPIKey(ctx, tenant, apiKey.Token)
		require.NoError(t, err)
		assert.Equal(t, userID, claims.Subject)
		assert.Equal(t, tenant, claims.TenantID)
	})

	t.Run("wrong tenant fails closed", func(t *testing.T) {
		_, err := svc.VerifyAPIKey(ctx, "tenant-b", apiKey.Token)
		assert.ErrorIs(t, err, tokens.ErrAPIKeyNotFound)
	})

	t.Run("empty tenant fails closed", func(t *testing.T) {
		_, err := svc.VerifyAPIKey(ctx, "", apiKey.Token)
		assert.ErrorIs(t, err, tokens.ErrAPIKeyNotFound)
	})
}

// TestSingleTenantVerifyUnchanged confirms the SingleTenant facade keeps its no-tenant
// signature and still resolves tokens issued under the empty (default) tenant.
func TestSingleTenantVerifyUnchanged(t *testing.T) {
	ctx := context.Background()
	svc := newMultiTenantService(t)
	st := jwt.NewSingleTenant[struct{}](svc)

	userID := uuid.New()

	pair, err := st.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID})
	require.NoError(t, err)
	refClaims, err := st.VerifyRefreshToken(ctx, pair.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, userID, refClaims.Subject)

	apiKey, err := st.IssueAPIKey(ctx, "sk_test_", tokens.Claims[struct{}]{Subject: userID})
	require.NoError(t, err)
	keyClaims, err := st.VerifyAPIKey(ctx, apiKey.Token)
	require.NoError(t, err)
	assert.Equal(t, userID, keyClaims.Subject)
}
