package tokens_test

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

// integrationClaims is a minimal custom-claims payload used to exercise the generic
// API-key lifecycle end-to-end against a real jwt.Service and the memory store.
type integrationClaims struct {
	Plan string
}

// TestAPIKeyLifecycle_Integration proves the PRD's IC-1 and IC-2 end-to-end through a real
// jwt.Service backed by the in-memory store: issue two keys for one creator, list them
// (IC-1: no clear-text token is ever returned by the list), verify a fresh key succeeds,
// revoke one by ID and confirm it is rejected with ErrAPIKeyRevoked while the other still
// verifies (IC-2), and finally that the revoked key remains visible in the list with
// RevokedAt populated for management tooling.
func TestAPIKeyLifecycle_Integration(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-int"

	store := memory.NewStore[integrationClaims]()
	svc := jwt.New[integrationClaims](jwt.Config[integrationClaims]{
		Store:      store,
		SecretKey:  "super-secret-key-for-testing----", // 32 bytes
		Issuer:     "egauth-int-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	})

	creator := uuid.Must(uuid.NewV7())

	// Issue two PATs for the same creator.
	keyA, err := svc.IssueAPIKey(ctx, "sk_int_", tokens.KeyTypePAT, creator, tokens.Claims[integrationClaims]{
		Subject:  creator,
		TenantID: tenant,
		Scopes:   []string{"repo:read"},
	})
	require.NoError(t, err)
	require.NotNil(t, keyA)
	require.NotEmpty(t, keyA.Token, "the clear-text token is only available at creation")

	keyB, err := svc.IssueAPIKey(ctx, "sk_int_", tokens.KeyTypePAT, creator, tokens.Claims[integrationClaims]{
		Subject:  creator,
		TenantID: tenant,
		Scopes:   []string{"repo:write"},
	})
	require.NoError(t, err)
	require.NotNil(t, keyB)
	require.NotEqual(t, keyA.ID, keyB.ID)

	// IC-1: listing exposes no clear-text token on any listed key.
	listed, err := svc.ListAPIKeysByCreator(ctx, tenant, creator)
	require.NoError(t, err)
	require.Len(t, listed, 2)
	for _, k := range listed {
		assert.Empty(t, k.Token, "ListAPIKeysByCreator must never surface the clear-text token (IC-1)")
		assert.Nil(t, k.RevokedAt, "freshly issued keys are active")
	}

	// A freshly issued key verifies successfully.
	claimsA, err := svc.VerifyAPIKey(ctx, tenant, keyA.Token)
	require.NoError(t, err)
	require.NotNil(t, claimsA)
	assert.Equal(t, creator, claimsA.Subject)

	claimsB, err := svc.VerifyAPIKey(ctx, tenant, keyB.Token)
	require.NoError(t, err)
	require.NotNil(t, claimsB)

	// IC-2: revoke one key by ID; it is then rejected with ErrAPIKeyRevoked while the other
	// still verifies.
	require.NoError(t, svc.RevokeAPIKey(ctx, tenant, keyA.ID))

	_, err = svc.VerifyAPIKey(ctx, tenant, keyA.Token)
	require.ErrorIs(t, err, tokens.ErrAPIKeyRevoked, "a revoked key must be rejected with ErrAPIKeyRevoked (IC-2)")

	stillValid, err := svc.VerifyAPIKey(ctx, tenant, keyB.Token)
	require.NoError(t, err, "revoking one key must not affect the other (IC-2)")
	require.NotNil(t, stillValid)

	// The revoked key still appears in the list with RevokedAt set, so management tooling can
	// see it; the active key remains active.
	afterRevoke, err := svc.ListAPIKeysByCreator(ctx, tenant, creator)
	require.NoError(t, err)
	require.Len(t, afterRevoke, 2)

	var revoked, active *tokens.APIKey[integrationClaims]
	for _, k := range afterRevoke {
		assert.Empty(t, k.Token, "listing must never surface the clear-text token, even after revocation (IC-1)")
		switch k.ID {
		case keyA.ID:
			revoked = k
		case keyB.ID:
			active = k
		}
	}
	require.NotNil(t, revoked, "the revoked key must still be returned by ListAPIKeysByCreator")
	require.NotNil(t, active)
	assert.NotNil(t, revoked.RevokedAt, "the revoked key must carry RevokedAt")
	assert.Nil(t, active.RevokedAt, "the untouched key must remain active")
}
