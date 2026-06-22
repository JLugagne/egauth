package tokens_test

import (
	"context"
	"errors"
	"testing"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewAccountRevoker_RevokesRefreshTokensAndAPIKeys proves the bundled hook kills every
// credential a user holds: all of their refresh tokens are gone and every API key they issued is
// soft-revoked, while another user's credentials are untouched.
func TestNewAccountRevoker_RevokesRefreshTokensAndAPIKeys(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore[struct{}]()

	const tenant = ""
	victim := uuid.Must(uuid.NewV7())
	bystander := uuid.Must(uuid.NewV7())

	// The victim holds a refresh token and an issued API key.
	require.NoError(t, store.SaveRefreshToken(ctx, tenant, &tokens.RefreshToken{
		Hash: "victim_rt", FamilyID: uuid.Must(uuid.NewV7()), UserID: victim, TenantID: tenant,
	}))
	victimKey := &tokens.APIKey[struct{}]{
		ID: uuid.Must(uuid.NewV7()), TenantID: tenant, Prefix: "pk_", Hash: "victim_key", CreatedBy: victim,
		Claims: tokens.Claims[struct{}]{Subject: victim},
	}
	require.NoError(t, store.SaveAPIKey(ctx, tenant, victimKey))

	// A bystander's refresh token and key must survive.
	require.NoError(t, store.SaveRefreshToken(ctx, tenant, &tokens.RefreshToken{
		Hash: "bystander_rt", FamilyID: uuid.Must(uuid.NewV7()), UserID: bystander, TenantID: tenant,
	}))
	bystanderKey := &tokens.APIKey[struct{}]{
		ID: uuid.Must(uuid.NewV7()), TenantID: tenant, Prefix: "pk_", Hash: "bystander_key", CreatedBy: bystander,
		Claims: tokens.Claims[struct{}]{Subject: bystander},
	}
	require.NoError(t, store.SaveAPIKey(ctx, tenant, bystanderKey))

	revoke := tokens.NewAccountRevoker(store)
	require.NoError(t, revoke(ctx, tenant, victim))

	// The victim's refresh token is gone and their key is revoked.
	_, err := store.FindRefreshToken(ctx, tenant, "victim_rt")
	assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)
	got, err := store.FindAPIKeyByHash(ctx, tenant, "victim_key")
	require.NoError(t, err)
	assert.NotNil(t, got.RevokedAt, "the victim's API key must be revoked")

	// The bystander is untouched.
	_, err = store.FindRefreshToken(ctx, tenant, "bystander_rt")
	assert.NoError(t, err)
	got, err = store.FindAPIKeyByHash(ctx, tenant, "bystander_key")
	require.NoError(t, err)
	assert.Nil(t, got.RevokedAt, "another user's API key must stay active")

	// Idempotent: re-running against a user with nothing left is a no-op.
	assert.NoError(t, revoke(ctx, tenant, victim))
}

// TestNewAccountRevoker_JoinsErrors verifies both revocations run even when the first fails, and
// the errors are joined so neither failure masks the other.
func TestNewAccountRevoker_JoinsErrors(t *testing.T) {
	ctx := context.Background()

	rtErr := errors.New("refresh store down")
	keyErr := errors.New("api-key store down")
	var refreshCalled, keyCalled bool
	store := &failingStore{
		revokeRefresh: func() error { refreshCalled = true; return rtErr },
		revokeKeys:    func() error { keyCalled = true; return keyErr },
	}

	err := tokens.NewAccountRevoker[struct{}](store)(ctx, "", uuid.Must(uuid.NewV7()))
	require.Error(t, err)
	assert.True(t, refreshCalled, "refresh-token revocation must run")
	assert.True(t, keyCalled, "API-key revocation must run even after the refresh revocation failed")
	assert.ErrorIs(t, err, rtErr)
	assert.ErrorIs(t, err, keyErr)
}

// failingStore is a tokens.Store whose two user-wide revocation methods are programmable; every
// other method panics because NewAccountRevoker must touch only those two.
type failingStore struct {
	tokens.Store[struct{}]
	revokeRefresh func() error
	revokeKeys    func() error
}

func (f *failingStore) RevokeAllRefreshTokensForUser(context.Context, string, uuid.UUID) error {
	return f.revokeRefresh()
}

func (f *failingStore) RevokeAllAPIKeysForUser(context.Context, string, uuid.UUID) error {
	return f.revokeKeys()
}
