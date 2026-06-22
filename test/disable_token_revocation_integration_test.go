package internal_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/identity"
	identitymem "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/JLugagne/egauth/tokens"
	tokensmem "github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDisableUser_RevokesRefreshTokensAndAPIKeys is the cross-module integration test for the
// identity.WithDisableRevokers ↔ tokens.NewAccountRevoker revocation fan-out: disabling a user
// must kill every refresh token they hold AND soft-revoke every API key they issued, via the real
// in-memory tokens store wired as a disable revoker — without coupling the identity and tokens
// packages directly. A second user's credentials must be left untouched.
func TestDisableUser_RevokesRefreshTokensAndAPIKeys(t *testing.T) {
	ctx := context.Background()

	const tenant = ""

	identityStore := identitymem.NewStore()
	tokenStore := tokensmem.NewStore[struct{}]()

	// Wire token revocation (refresh tokens + API keys) into DisableUser.
	identitySvc := identity.NewService(
		identityStore,
		argon2.NewHasher(),
		policy.NewDefaultPolicy(),
		identity.WithDisableRevokers(tokens.NewAccountRevoker(tokenStore)),
	)

	victim, err := identitySvc.Register(ctx, tenant, "disabled@example.com", "StrongP@ss1!")
	require.NoError(t, err)
	bystander, err := identitySvc.Register(ctx, tenant, "active@example.com", "StrongP@ss2!")
	require.NoError(t, err)

	// The victim holds a refresh token (a live session) and issued an API key.
	require.NoError(t, tokenStore.SaveRefreshToken(ctx, tenant, &tokens.RefreshToken{
		Hash: "victim_rt", FamilyID: uuid.Must(uuid.NewV7()), UserID: victim.ID, TenantID: tenant,
	}))
	require.NoError(t, tokenStore.SaveAPIKey(ctx, tenant, &tokens.APIKey[struct{}]{
		ID: uuid.Must(uuid.NewV7()), TenantID: tenant, Prefix: "pk_", Hash: "victim_key",
		CreatedBy: victim.ID, Claims: tokens.Claims[struct{}]{Subject: victim.ID},
	}))

	// The bystander has equivalent credentials that must survive.
	require.NoError(t, tokenStore.SaveRefreshToken(ctx, tenant, &tokens.RefreshToken{
		Hash: "bystander_rt", FamilyID: uuid.Must(uuid.NewV7()), UserID: bystander.ID, TenantID: tenant,
	}))
	require.NoError(t, tokenStore.SaveAPIKey(ctx, tenant, &tokens.APIKey[struct{}]{
		ID: uuid.Must(uuid.NewV7()), TenantID: tenant, Prefix: "pk_", Hash: "bystander_key",
		CreatedBy: bystander.ID, Claims: tokens.Claims[struct{}]{Subject: bystander.ID},
	}))

	// Disable the victim — this must cascade into the tokens store.
	require.NoError(t, identitySvc.DisableUser(ctx, tenant, victim.ID))

	// The victim's refresh token is revoked (gone) and their API key is soft-revoked.
	_, err = tokenStore.FindRefreshToken(ctx, tenant, "victim_rt")
	assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound,
		"a disabled user's refresh token must be revoked")
	victimKey, err := tokenStore.FindAPIKeyByHash(ctx, tenant, "victim_key")
	require.NoError(t, err)
	assert.NotNil(t, victimKey.RevokedAt, "a disabled user's API key must be revoked")

	// The bystander's credentials are untouched.
	_, err = tokenStore.FindRefreshToken(ctx, tenant, "bystander_rt")
	assert.NoError(t, err, "another user's refresh token must survive the disable")
	bystanderKey, err := tokenStore.FindAPIKeyByHash(ctx, tenant, "bystander_key")
	require.NoError(t, err)
	assert.Nil(t, bystanderKey.RevokedAt, "another user's API key must stay active")
}
