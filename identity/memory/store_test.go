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

// TestIncrementFailedAttempts_DecaysStaleAttemptsAfterWindow verifies that failed attempts
// outside the sliding window (lockDuration) decay and reset to 1 on the next failed attempt.
func TestIncrementFailedAttempts_DecaysStaleAttemptsAfterWindow(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-A"
	const email = "decay@example.com"
	const lockThreshold = 5
	const lockDuration = 20 * time.Millisecond

	store := memory.NewStore()

	user, err := store.CreateUser(ctx, tenant, email)
	require.NoError(t, err)

	oldHash := "old_hash"
	ident := &identity.Identity{
		UserID:       user.ID,
		Provider:     "password",
		ProviderID:   email,
		PasswordHash: &oldHash,
	}
	require.NoError(t, store.AddIdentity(ctx, tenant, ident))

	// Accumulate 4 failed attempts (just below threshold 5)
	for i := 0; i < 4; i++ {
		justLocked, err := store.IncrementFailedAttempts(ctx, tenant, ident.ID, lockThreshold, lockDuration)
		require.NoError(t, err)
		assert.False(t, justLocked)
	}

	found, err := store.FindIdentityByProvider(ctx, tenant, "password", email)
	require.NoError(t, err)
	assert.Equal(t, 4, found.FailedAttempts)
	assert.Nil(t, found.LockedUntil)

	// Wait for the lockout duration / sliding window to elapse
	time.Sleep(30 * time.Millisecond)

	// Next failed attempt after window must decay stale attempts and reset count to 1
	justLocked, err := store.IncrementFailedAttempts(ctx, tenant, ident.ID, lockThreshold, lockDuration)
	require.NoError(t, err)
	assert.False(t, justLocked, "must not lock the account when stale attempts have decayed")

	found, err = store.FindIdentityByProvider(ctx, tenant, "password", email)
	require.NoError(t, err)
	assert.Equal(t, 1, found.FailedAttempts, "failed attempts must reset to 1 after sliding window has elapsed")
	assert.Nil(t, found.LockedUntil, "account must remain unlocked")
}

// TestIncrementFailedAttempts_DecaysStaleAttemptsWithClock verifies that failed attempts
// decay when advancing time via WithClock/SetClock.
func TestIncrementFailedAttempts_DecaysStaleAttemptsWithClock(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-A"
	const email = "clock_decay@example.com"
	const lockThreshold = 5
	const lockDuration = 15 * time.Minute

	now := time.Now()
	store := memory.NewStore(memory.WithClock(func() time.Time { return now }))

	user, err := store.CreateUser(ctx, tenant, email)
	require.NoError(t, err)

	oldHash := "old_hash"
	ident := &identity.Identity{
		UserID:       user.ID,
		Provider:     "password",
		ProviderID:   email,
		PasswordHash: &oldHash,
	}
	require.NoError(t, store.AddIdentity(ctx, tenant, ident))

	// Accumulate 4 failed attempts
	for i := 0; i < 4; i++ {
		justLocked, err := store.IncrementFailedAttempts(ctx, tenant, ident.ID, lockThreshold, lockDuration)
		require.NoError(t, err)
		assert.False(t, justLocked)
	}

	found, err := store.FindIdentityByProvider(ctx, tenant, "password", email)
	require.NoError(t, err)
	assert.Equal(t, 4, found.FailedAttempts)
	assert.Nil(t, found.LockedUntil)

	// Advance clock beyond lockDuration
	now = now.Add(lockDuration + time.Second)

	// Next attempt must decay and reset to 1
	justLocked, err := store.IncrementFailedAttempts(ctx, tenant, ident.ID, lockThreshold, lockDuration)
	require.NoError(t, err)
	assert.False(t, justLocked, "must not lock the account after window has elapsed")

	found, err = store.FindIdentityByProvider(ctx, tenant, "password", email)
	require.NoError(t, err)
	assert.Equal(t, 1, found.FailedAttempts)
	assert.Nil(t, found.LockedUntil)
}

// TestIncrementFailedAttempts_DecaysStaleAttemptsWithSetIdentityUpdatedAt verifies that
// updating UpdatedAt directly causes stale failed attempts to decay.
func TestIncrementFailedAttempts_DecaysStaleAttemptsWithSetIdentityUpdatedAt(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-A"
	const email = "updatedat_decay@example.com"
	const lockThreshold = 5
	const lockDuration = 15 * time.Minute

	store := memory.NewStore()

	user, err := store.CreateUser(ctx, tenant, email)
	require.NoError(t, err)

	oldHash := "old_hash"
	ident := &identity.Identity{
		UserID:       user.ID,
		Provider:     "password",
		ProviderID:   email,
		PasswordHash: &oldHash,
	}
	require.NoError(t, store.AddIdentity(ctx, tenant, ident))

	// Accumulate 3 failed attempts
	for i := 0; i < 3; i++ {
		justLocked, err := store.IncrementFailedAttempts(ctx, tenant, ident.ID, lockThreshold, lockDuration)
		require.NoError(t, err)
		assert.False(t, justLocked)
	}

	found, err := store.FindIdentityByProvider(ctx, tenant, "password", email)
	require.NoError(t, err)
	assert.Equal(t, 3, found.FailedAttempts)

	// Set UpdatedAt into the past beyond lockDuration
	past := time.Now().Add(-lockDuration - time.Minute)
	store.SetIdentityUpdatedAt(ident.ID, past)

	// Next attempt must decay and reset to 1
	justLocked, err := store.IncrementFailedAttempts(ctx, tenant, ident.ID, lockThreshold, lockDuration)
	require.NoError(t, err)
	assert.False(t, justLocked)

	found, err = store.FindIdentityByProvider(ctx, tenant, "password", email)
	require.NoError(t, err)
	assert.Equal(t, 1, found.FailedAttempts)
	assert.Nil(t, found.LockedUntil)
}
