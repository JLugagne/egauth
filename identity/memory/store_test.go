package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/identity/storetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreContract(t *testing.T) {
	store := memory.NewStore()
	storetest.StoreContractTesting(t, store, true)
	storetest.StoreDisableEnableContract(t, store, "tenant-A")
	storetest.StoreDeleteAuthGateContract(t, store, "tenant-A")
	storetest.StoreUpdateUserSoftDeleteContract(t, store, "tenant-A")
}

// TestUpdateIdentityPasswordStampsRotationFields asserts that UpdateIdentityPassword stamps
// PasswordChangedAt and both sets and clears MustChangePassword across successive writes.
func TestUpdateIdentityPasswordStampsRotationFields(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-A"
	store := memory.NewStore()

	const email = "rotation@example.com"
	user, err := store.CreateUser(ctx, tenant, email)
	require.NoError(t, err)

	oldHash := "old_hash"
	require.NoError(t, store.AddIdentity(ctx, tenant, &identity.Identity{
		UserID:       user.ID,
		Provider:     "password",
		ProviderID:   email,
		PasswordHash: &oldHash,
	}))

	// First update flags the credential and stamps the change time.
	changedAt := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, store.UpdateIdentityPassword(ctx, tenant, user.ID, "new_hash", changedAt, true))

	found, err := store.FindIdentityByProvider(ctx, tenant, "password", email)
	require.NoError(t, err)
	assert.WithinDuration(t, changedAt, found.PasswordChangedAt, time.Second, "PasswordChangedAt must be stamped")
	assert.True(t, found.MustChangePassword, "MustChangePassword must be set when requested")

	// A second update with mustChange=false clears the flag and re-stamps the time.
	later := changedAt.Add(time.Hour)
	require.NoError(t, store.UpdateIdentityPassword(ctx, tenant, user.ID, "newer_hash", later, false))

	found, err = store.FindIdentityByProvider(ctx, tenant, "password", email)
	require.NoError(t, err)
	assert.WithinDuration(t, later, found.PasswordChangedAt, time.Second, "PasswordChangedAt must be re-stamped")
	assert.False(t, found.MustChangePassword, "MustChangePassword must be cleared when not requested")
}
