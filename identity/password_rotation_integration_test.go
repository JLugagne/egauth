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

// These tests exercise the temporary/one-time password policy end-to-end against the real
// in-memory store (not a MockStore), proving that the MustChangePassword flag and the
// informational PasswordChangedAt stamp round-trip through the actual write path and are read
// back correctly by PasswordChangeRequired. They cover SC-3 and SC-6 of the M7 PRD. egauth does
// NOT do age-based rotation (NIST SP 800-63B discourages fixed-interval expiry), so there is no
// aging scenario here — only the explicit-flag path.

// fixedClock is a deterministic clock so a test can assert the exact PasswordChangedAt stamp.
type fixedClock struct{ t time.Time }

func (c *fixedClock) now() time.Time { return c.t }

// tempPasswordTestService builds a service over a real in-memory store with the given clock. The
// hasher and policy are permissive mocks so the scenarios focus on the flag/stamp bookkeeping
// rather than hashing/strength behavior.
func tempPasswordTestService(clock *fixedClock) (identity.Service, *identitymemory.Store) {
	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{
		HashFunc:    func(ctx context.Context, p string) (string, error) { return "hashed-" + p, nil },
		CompareFunc: func(ctx context.Context, hash, pw string) error { return nil },
	}
	policy := &mockPolicy{VerifyFunc: func(ctx context.Context, p string) error { return nil }}
	svc := identity.NewService(store, hasher, policy, identity.WithClock(clock.now))
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

// TestTemporaryPasswordIntegration_AdminProvisioned covers SC-3 and SC-6.
//
// Both AdminCreateUser and SetTemporaryPassword provision a flagged credential that reports
// PasswordChangeRequired=true, and the flag is cleared by a subsequent ChangePassword (admin
// path) or ResetPassword (temp path). PasswordChangedAt is stamped along the way.
func TestTemporaryPasswordIntegration_AdminProvisioned(t *testing.T) {
	ctx := context.Background()
	clock := &fixedClock{t: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)}
	svc, store := tempPasswordTestService(clock)

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
