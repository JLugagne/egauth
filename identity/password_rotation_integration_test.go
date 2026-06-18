package identity_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests exercise the password-rotation policy end-to-end against the real in-memory
// store (not a MockStore), proving that the PasswordChangedAt stamp and MustChangePassword
// flag round-trip through the actual write path and are read back correctly by
// PasswordChangeRequired. They cover IC-2, IC-3, SC-3 and SC-6 of the M7 PRD.

// movableClock is a controllable clock whose value can be advanced between calls, so a single
// service instance can "age" a credential past its rotation max without rebuilding the service.
type movableClock struct{ t time.Time }

func (c *movableClock) now() time.Time     { return c.t }
func (c *movableClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// rotationTestService builds a service over a real in-memory store with the given clock and
// service options. The hasher and policy are permissive mocks so the scenarios focus on the
// rotation bookkeeping rather than hashing/strength behavior.
func rotationTestService(clock *movableClock, opts ...identity.ServiceOption) (identity.Service, *identitymemory.Store) {
	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{
		HashFunc:    func(ctx context.Context, p string) (string, error) { return "hashed-" + p, nil },
		CompareFunc: func(ctx context.Context, hash, pw string) error { return nil },
	}
	policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}
	base := []identity.ServiceOption{identity.WithClock(clock.now)}
	svc := identity.NewService(store, hasher, policy, append(base, opts...)...)
	return svc, store
}

// passwordChangedAt reads the stored password identity's PasswordChangedAt straight from the
// store, so a test can assert the stamp was actually re-written by the change/reset path.
func passwordChangedAt(t *testing.T, store *identitymemory.Store, tenantID string, userID uuid.UUID) time.Time {
	t.Helper()
	idents, err := store.FindIdentitiesByUserID(context.Background(), tenantID, userID)
	require.NoError(t, err)
	for _, id := range idents {
		if id.Provider == "password" && id.PasswordHash != nil {
			return id.PasswordChangedAt
		}
	}
	t.Fatalf("no password identity found for user %s", userID.String())
	return time.Time{}
}

// TestRotationIntegration_AgedThenChangeClears covers IC-2 and SC-6 via ChangePassword.
//
// A rotation-enabled user whose password was stamped past maxAge reports
// PasswordChangeRequired=true; after a successful ChangePassword the flag is cleared,
// PasswordChangedAt is re-stamped to the current clock, and the query reports false.
func TestRotationIntegration_AgedThenChangeClears(t *testing.T) {
	ctx := context.Background()
	const maxAge = 90 * 24 * time.Hour
	clock := &movableClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	svc, store := rotationTestService(clock, identity.WithPasswordRotation(maxAge))

	user, err := svc.Register(ctx, "tenant", "aged@example.com", "OriginalPass1!")
	require.NoError(t, err)

	// Register leaves PasswordChangedAt zero (a legacy stamp), which is never due. Run a
	// password change now to stamp a concrete, datable timestamp into the credential.
	require.NoError(t, svc.ChangePassword(ctx, "tenant", user.ID, "OriginalPass1!", "FreshPass1!"))
	stampedAt := clock.now()
	require.False(t, passwordChangedAt(t, store, "tenant", user.ID).IsZero(), "ChangePassword must stamp PasswordChangedAt")

	// Not yet due.
	required, err := svc.PasswordChangeRequired(ctx, "tenant", user.ID)
	require.NoError(t, err)
	assert.False(t, required, "a freshly-changed password must not be due")

	// Age the credential past maxAge.
	clock.advance(maxAge + time.Hour)
	required, err = svc.PasswordChangeRequired(ctx, "tenant", user.ID)
	require.NoError(t, err)
	assert.True(t, required, "a password older than maxAge must require a change")

	// Change it again at the advanced clock: the flag clears and the stamp is refreshed.
	require.NoError(t, svc.ChangePassword(ctx, "tenant", user.ID, "FreshPass1!", "EvenFresher1!"))
	newStamp := passwordChangedAt(t, store, "tenant", user.ID)
	assert.Equal(t, clock.now(), newStamp, "ChangePassword must re-stamp PasswordChangedAt to the current clock")
	assert.True(t, newStamp.After(stampedAt), "the re-stamp must advance past the original stamp")

	required, err = svc.PasswordChangeRequired(ctx, "tenant", user.ID)
	require.NoError(t, err)
	assert.False(t, required, "after a change at the current clock the password is no longer due")
}

// TestRotationIntegration_AgedThenResetClears covers SC-6 via the ResetPassword token flow.
//
// An aged, rotation-enabled credential reports due; after a ResetPassword (which consumes a
// real reset token) the stamp is refreshed and the query reports false.
func TestRotationIntegration_AgedThenResetClears(t *testing.T) {
	ctx := context.Background()
	const maxAge = 30 * 24 * time.Hour
	clock := &movableClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	svc, store := rotationTestService(clock, identity.WithPasswordRotation(maxAge))

	user, err := svc.Register(ctx, "tenant", "reset@example.com", "OriginalPass1!")
	require.NoError(t, err)
	require.NoError(t, svc.ChangePassword(ctx, "tenant", user.ID, "OriginalPass1!", "FreshPass1!"))

	clock.advance(maxAge + 24*time.Hour)
	required, err := svc.PasswordChangeRequired(ctx, "tenant", user.ID)
	require.NoError(t, err)
	require.True(t, required, "aged credential must be due before the reset")

	token, resetUser, err := svc.RequestPasswordReset(ctx, "tenant", "reset@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.Equal(t, user.ID, resetUser.ID)

	require.NoError(t, svc.ResetPassword(ctx, "tenant", token, "ResetPass1!"))
	assert.Equal(t, clock.now(), passwordChangedAt(t, store, "tenant", user.ID), "ResetPassword must re-stamp PasswordChangedAt")

	required, err = svc.PasswordChangeRequired(ctx, "tenant", user.ID)
	require.NoError(t, err)
	assert.False(t, required, "after the reset the credential is no longer due")
}

// TestRotationIntegration_PerTenantOptOut covers IC-3.
//
// Tenant A has rotation enabled with maxAge=30d; tenant B is opted out via the per-tenant
// resolver. The same aged credential is due for A but not for B.
func TestRotationIntegration_PerTenantOptOut(t *testing.T) {
	ctx := context.Background()
	const maxAge = 30 * 24 * time.Hour
	clock := &movableClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	// The resolver fully overrides the global: tenant A keeps maxAge, tenant B opts out.
	svc, _ := rotationTestService(clock,
		identity.WithPasswordRotation(maxAge),
		identity.WithPasswordRotationResolver(func(tenantID string) (time.Duration, bool) {
			if tenantID == "tenant-b" {
				return 0, false // opted out
			}
			return maxAge, true
		}),
	)

	userA, err := svc.Register(ctx, "tenant-a", "user@a.example.com", "OriginalPass1!")
	require.NoError(t, err)
	userB, err := svc.Register(ctx, "tenant-b", "user@b.example.com", "OriginalPass1!")
	require.NoError(t, err)

	// Stamp both credentials with a concrete timestamp, then age both past maxAge.
	require.NoError(t, svc.ChangePassword(ctx, "tenant-a", userA.ID, "OriginalPass1!", "FreshPass1!"))
	require.NoError(t, svc.ChangePassword(ctx, "tenant-b", userB.ID, "OriginalPass1!", "FreshPass1!"))
	clock.advance(maxAge + 48*time.Hour)

	requiredA, err := svc.PasswordChangeRequired(ctx, "tenant-a", userA.ID)
	require.NoError(t, err)
	assert.True(t, requiredA, "tenant A has rotation enabled: an aged credential is due")

	requiredB, err := svc.PasswordChangeRequired(ctx, "tenant-b", userB.ID)
	require.NoError(t, err)
	assert.False(t, requiredB, "tenant B opted out via the resolver: an aged credential is not due")
}

// TestRotationIntegration_AdminProvisioned covers SC-3.
//
// Both AdminCreateUser and SetTemporaryPassword provision a flagged credential that reports
// PasswordChangeRequired=true even with age-based rotation OFF, and the flag is cleared by a
// subsequent ChangePassword (admin path) or ResetPassword (temp path).
func TestRotationIntegration_AdminProvisioned(t *testing.T) {
	ctx := context.Background()
	clock := &movableClock{t: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)}
	// No WithPasswordRotation: prove the flag alone drives the requirement, independent of age.
	svc, store := rotationTestService(clock)

	t.Run("AdminCreateUser flags and ChangePassword clears", func(t *testing.T) {
		user, err := svc.AdminCreateUser(ctx, "tenant", "admin-made@example.com", "TempPass1!")
		require.NoError(t, err)

		required, err := svc.PasswordChangeRequired(ctx, "tenant", user.ID)
		require.NoError(t, err)
		assert.True(t, required, "an admin-provisioned account must require a password change")
		assert.Equal(t, clock.now(), passwordChangedAt(t, store, "tenant", user.ID), "AdminCreateUser must stamp PasswordChangedAt")

		require.NoError(t, svc.ChangePassword(ctx, "tenant", user.ID, "TempPass1!", "ChosenPass1!"))
		required, err = svc.PasswordChangeRequired(ctx, "tenant", user.ID)
		require.NoError(t, err)
		assert.False(t, required, "after the user chooses a password the flag must be cleared")
	})

	t.Run("SetTemporaryPassword flags and ResetPassword clears", func(t *testing.T) {
		user, err := svc.Register(ctx, "tenant", "temp-target@example.com", "OriginalPass1!")
		require.NoError(t, err)

		required, err := svc.PasswordChangeRequired(ctx, "tenant", user.ID)
		require.NoError(t, err)
		require.False(t, required, "a normal account must not be flagged before provisioning")

		require.NoError(t, svc.SetTemporaryPassword(ctx, "tenant", user.ID, "TempPass1!"))
		required, err = svc.PasswordChangeRequired(ctx, "tenant", user.ID)
		require.NoError(t, err)
		assert.True(t, required, "SetTemporaryPassword must force a change at next login")

		token, _, err := svc.RequestPasswordReset(ctx, "tenant", "temp-target@example.com")
		require.NoError(t, err)
		require.NotEmpty(t, token)
		require.NoError(t, svc.ResetPassword(ctx, "tenant", token, "ChosenPass1!"))

		required, err = svc.PasswordChangeRequired(ctx, "tenant", user.ID)
		require.NoError(t, err)
		assert.False(t, required, "after the reset the temporary-password flag must be cleared")
	})
}
