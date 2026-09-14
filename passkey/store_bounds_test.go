package passkey_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAccountGate_DisabledAccountCannotRegister is the regression test for the lifecycle gap on the
// registration half of the ceremony. The gate was consulted by every login path but not by
// registration, so an account that had been suspended or soft-deleted could still enrol a new
// authenticator — and enrollment outlives a suspension, because DisableUser preserves passkeys by
// design.
func TestAccountGate_DisabledAccountCannotRegister(t *testing.T) {
	ctx := context.Background()
	lc := &lifecycle{}
	sink := &captureSink{}
	svc := newGatedPasskeyService(t, lc.gate(), sink)
	userID := uuid.Must(uuid.NewV7())

	lc.disabled = true

	_, _, err := svc.BeginRegistration(ctx, "", userID, "user@example.com", "User")
	require.ErrorIs(t, err, passkey.ErrAccountDisabled,
		"a suspended account must not be able to start enrolling an authenticator")

	stored, err := passkeymemory.NewStore().GetCredentials(ctx, "", userID)
	require.NoError(t, err)
	assert.Empty(t, stored)

	// Soft-deleted accounts are refused the same way.
	lc.disabled, lc.deleted = false, true
	_, _, err = svc.BeginRegistration(ctx, "", userID, "user@example.com", "User")
	require.ErrorIs(t, err, passkey.ErrAccountDeleted)

	// A live account is unaffected.
	lc.deleted = false
	_, _, err = svc.BeginRegistration(ctx, "", userID, "user@example.com", "User")
	assert.NoError(t, err, "the gate must not block a live account")
}

// TestFinishRegistration_RefusesAccountSuspendedMidCeremony covers the window a ceremony opens: an
// enrollment begun while the account was live must not be stored once the account has been
// suspended, because the credential is what persists.
func TestFinishRegistration_RefusesAccountSuspendedMidCeremony(t *testing.T) {
	ctx := context.Background()
	lc := &lifecycle{}
	svc := newGatedPasskeyService(t, lc.gate(), &captureSink{})
	userID := uuid.Must(uuid.NewV7())

	auth := newSoftAuthenticator(t, testRPID, testOrigin)
	_, session, err := svc.BeginRegistration(ctx, "", userID, "user@example.com", "User")
	require.NoError(t, err, "the account is live when the ceremony starts")

	lc.disabled = true

	_, err = svc.FinishRegistration(ctx, "", userID, "user@example.com", "User", *session,
		auth.registrationRequest(t, session.Challenge))
	require.ErrorIs(t, err, passkey.ErrAccountDisabled,
		"a ceremony started while live must not enrol an authenticator after suspension")
}

// TestChallengeStore_IsBounded covers the unauthenticated resource-bound defect. Begin handlers are
// deliberately reachable without authentication, and each call records a fresh random challenge, so
// without a cap a caller's request volume translates directly into retained entries — and if
// insertion also rescanned the store, each write would cost more than the last.
func TestChallengeStore_IsBounded(t *testing.T) {
	ctx := context.Background()
	const max = 64
	store := passkeymemory.NewChallengeStore(passkeymemory.WithMaxChallenges(max))
	expiry := time.Now().Add(5 * time.Minute)

	for i := 0; i < max; i++ {
		require.NoError(t, store.Put(ctx, "tenant", fmt.Sprintf("challenge-%d", i), expiry),
			"fill %d of the per-tenant budget", i+1)
	}

	err := store.Put(ctx, "tenant", "one-too-many", expiry)
	require.ErrorIs(t, err, passkeymemory.ErrChallengeStoreFull,
		"a full tenant must be refused rather than growing the store, and rather than evicting a live entry")
	assert.Equal(t, max, store.Len(), "the cap must hold and no live entry may be evicted")

	// A different tenant has its own budget: one tenant cannot exhaust another's.
	require.NoError(t, store.Put(ctx, "other-tenant", "challenge", expiry),
		"the cap is per tenant, so a flood in one tenant must not block another")

	// Consuming frees a slot, so a legitimate retry after a finished ceremony succeeds.
	ok, err := store.Consume(ctx, "tenant", "challenge-0")
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, store.Put(ctx, "tenant", "after-consume", expiry),
		"a consumed challenge must free its slot")

	// Expiry frees slots without a full rescan.
	shortStore := passkeymemory.NewChallengeStore(
		passkeymemory.WithMaxChallenges(2),
		passkeymemory.WithClock(func() time.Time { return time.Unix(1_700_000_000, 0) }),
	)
	past := time.Unix(1_699_999_999, 0)
	require.NoError(t, shortStore.Put(ctx, "t", "a", past))
	require.NoError(t, shortStore.Put(ctx, "t", "b", past))
	require.NoError(t, shortStore.Put(ctx, "t", "c", past),
		"expired entries must be reaped, freeing the budget")
}

// TestChallengeStore_ReplacedEntryDoesNotLeakBudget covers the interaction between the cap and a
// re-Put of the same challenge: replacing an entry must not consume a second slot.
func TestChallengeStore_ReplacedEntryDoesNotLeakBudget(t *testing.T) {
	ctx := context.Background()
	store := passkeymemory.NewChallengeStore(passkeymemory.WithMaxChallenges(1))
	expiry := time.Now().Add(time.Minute)

	require.NoError(t, store.Put(ctx, "t", "same", expiry))
	require.NoError(t, store.Put(ctx, "t", "same", expiry.Add(time.Minute)),
		"replacing the same challenge must not count against the cap twice")
}

// TestCredentialStore_IsBoundedAndIndexed covers the credential-store defect: nothing capped how
// many authenticators accumulated, and each save rescanned every credential in the tenant to
// enforce the uniqueness the pgx unique index provides. One account's registrations therefore made
// every other account's ceremonies in that tenant more expensive.
func TestCredentialStore_IsBoundedAndIndexed(t *testing.T) {
	ctx := context.Background()
	const perUser = 3
	store := passkeymemory.NewStore(passkeymemory.WithMaxCredentialsPerUser(perUser))
	userID := uuid.Must(uuid.NewV7())

	for i := 0; i < perUser; i++ {
		require.NoError(t, store.SaveCredential(ctx, "t", &passkey.Credential{
			ID: []byte(fmt.Sprintf("cred-%d", i)), UserID: userID, PublicKey: []byte{1},
		}))
	}
	err := store.SaveCredential(ctx, "t", &passkey.Credential{
		ID: []byte("one-too-many"), UserID: userID,
	})
	require.ErrorIs(t, err, passkeymemory.ErrTooManyCredentials,
		"the per-user cap must fail closed instead of evicting an existing authenticator")

	// Deleting frees a slot and the tenant-wide credential ID.
	require.NoError(t, store.DeleteCredential(ctx, "t", userID, []byte("cred-0")))
	require.NoError(t, store.SaveCredential(ctx, "t", &passkey.Credential{
		ID: []byte("replacement"), UserID: userID,
	}))

	// Deleting a different credential's ID is reported as not found rather than silently succeeding.
	assert.ErrorIs(t, store.DeleteCredential(ctx, "t", userID, []byte("never-existed")),
		passkey.ErrCredentialNotFound)
}

// TestCredentialStore_TenantWideUniqueness is the behaviour the index replaced the scan for: a
// credential ID stays unique across all users of a tenant, matching the pgx PRIMARY KEY.
func TestCredentialStore_TenantWideUniqueness(t *testing.T) {
	ctx := context.Background()
	store := passkeymemory.NewStore()
	owner, other := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())

	require.NoError(t, store.SaveCredential(ctx, "t", &passkey.Credential{ID: []byte("shared"), UserID: owner}))
	err := store.SaveCredential(ctx, "t", &passkey.Credential{ID: []byte("shared"), UserID: other})
	assert.ErrorIs(t, err, passkey.ErrCredentialExists,
		"a credential ID is unique tenant-wide even across users")

	// The same ID in another tenant is a different credential.
	require.NoError(t, store.SaveCredential(ctx, "other-tenant", &passkey.Credential{ID: []byte("shared"), UserID: other}),
		"credential IDs are scoped per tenant")

	// A tenant-wide cap also exists, so one account cannot fill a shared store.
	tiny := passkeymemory.NewStore(passkeymemory.WithMaxCredentialsPerTenant(2))
	require.NoError(t, tiny.SaveCredential(ctx, "t", &passkey.Credential{ID: []byte("a"), UserID: owner}))
	require.NoError(t, tiny.SaveCredential(ctx, "t", &passkey.Credential{ID: []byte("b"), UserID: other}))
	err = tiny.SaveCredential(ctx, "t", &passkey.Credential{
		ID: []byte("c"), UserID: uuid.Must(uuid.NewV7()),
	})
	assert.ErrorIs(t, err, passkeymemory.ErrTooManyCredentials,
		"the per-tenant cap must fail closed")
}

// TestCapacityErrorsAreIdentifiable proves the concrete store sentinels wrap the package-level one,
// so a handler can map "the store refused for capacity reasons" to a retryable status without
// importing the in-memory implementation.
func TestCapacityErrorsAreIdentifiable(t *testing.T) {
	assert.ErrorIs(t, passkeymemory.ErrChallengeStoreFull, passkey.ErrStoreCapacityReached)
	assert.ErrorIs(t, passkeymemory.ErrTooManyCredentials, passkey.ErrStoreCapacityReached)
}
