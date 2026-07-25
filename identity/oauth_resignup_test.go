package identity_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeleteAccount_ReleasesProviderIdentityForResignup is the bug-confirming test for
// identity/TEN-6: after a user-facing account deletion the account's OAuth provider identity was
// kept intact, so every later login or signup with the SAME provider account was refused forever.
// A user who deletes their account could never come back through the same social login. Deletion
// must release the provider identity (as it already does for the password identity's email key), so
// the same provider account cleanly provisions a NEW account.
func TestDeleteAccount_ReleasesProviderIdentityForResignup(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const (
		provider = "google"
		sub      = "sub-resignup"
		email    = "resignup@example.com"
	)

	user, err := svc.LinkOrCreateIdentity(ctx, "", provider, sub, email, true)
	require.NoError(t, err)
	require.NotNil(t, user)

	require.NoError(t, svc.DeleteAccount(ctx, "", user.ID))

	// Re-signup with the same provider account: a fresh account, never the deleted one.
	again, err := svc.LinkOrCreateIdentity(ctx, "", provider, sub, email, true)
	require.NoError(t, err, "a deleted account's provider identity must be re-registerable")
	require.NotNil(t, again)
	assert.NotEqual(t, user.ID, again.ID, "re-signup must provision a NEW account, never resurrect the deleted one")
	assert.Equal(t, email, again.Email)

	// And the new account works like any other: it resolves on the next login.
	third, err := svc.LinkOrCreateIdentity(ctx, "", provider, sub, email, true)
	require.NoError(t, err)
	assert.Equal(t, again.ID, third.ID)
}

// staleIdentityStore serves a provider identity that outlived its account, so the service-layer
// liveness gate can be exercised on its own.
type staleIdentityStore struct {
	*memory.Store
	stale *identity.Identity
}

func (s *staleIdentityStore) FindIdentityByProvider(ctx context.Context, tenantID string, provider, providerID string) (*identity.Identity, error) {
	if s.stale != nil {
		return s.stale, nil
	}
	return s.Store.FindIdentityByProvider(ctx, tenantID, provider, providerID)
}

// TestLinkOrCreateIdentity_RefusesIdentityOfDeletedUser keeps the service-layer DeletedAt gate
// covered now that deletion releases provider identities: should an identity row ever outlive its
// account (a legacy row, an external store), the already-linked branch must still refuse it rather
// than hand a soft-deleted user to an OAuth callback that would mint a session for it.
func TestLinkOrCreateIdentity_RefusesIdentityOfDeletedUser(t *testing.T) {
	ctx := context.Background()
	base := memory.NewStore()
	store := &staleIdentityStore{Store: base}
	svc := newHookedService(t, store)

	user, err := svc.LinkOrCreateIdentity(ctx, "", "google", "sub-stale", "stale@example.com", true)
	require.NoError(t, err)
	require.NoError(t, svc.DeleteAccount(ctx, "", user.ID))

	store.stale = &identity.Identity{UserID: user.ID, Provider: "google", ProviderID: "sub-stale"}

	_, err = svc.LinkOrCreateIdentity(ctx, "", "google", "sub-stale", "stale@example.com", true)
	assert.ErrorIs(t, err, identity.ErrUserNotFound,
		"an identity that outlived its soft-deleted account must not produce a session")
}
