// Package storetest provides a shared contract test suite for mfa.Store implementations.
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/mfa"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// StoreContractTesting exercises any mfa.Store implementation for TOTP persistence, replay
// protection, recovery-code single-use semantics and (optionally) tenant isolation.
func StoreContractTesting(t *testing.T, store mfa.Store, useMultiTenant bool) {
	ctx := context.Background()
	var tenantA, tenantB string
	if useMultiTenant {
		tenantA, tenantB = "tenant-A", "tenant-B"
	}

	t.Run("empty tenant is the default partition", func(t *testing.T) {
		// An empty tenantID is a legal key (the single-tenant default partition).
		uid := uuid.New()
		require.NoError(t, store.SaveTOTP(ctx, "", &mfa.TOTPEnrollment{UserID: uid, Secret: "DEF", CreatedAt: time.Now()}),
			"empty tenant must be the valid default partition, not rejected")
		got, err := store.GetTOTP(ctx, "", uid)
		require.NoError(t, err)
		assert.Equal(t, "DEF", got.Secret)

		require.NoError(t, store.ReplaceRecoveryCodes(ctx, "", uid, []string{"d1"}),
			"empty tenant must be accepted for recovery codes too")
		require.NoError(t, store.ConsumeRecoveryCode(ctx, "", uid, "d1"))
	})

	t.Run("TOTP save/get/delete", func(t *testing.T) {
		uid := uuid.New()
		_, err := store.GetTOTP(ctx, tenantA, uid)
		assert.ErrorIs(t, err, mfa.ErrNotEnrolled, "unknown user must report not-enrolled")

		require.NoError(t, store.SaveTOTP(ctx, tenantA, &mfa.TOTPEnrollment{
			UserID: uid, Secret: "ABCDEF", CreatedAt: time.Now(),
		}))

		got, err := store.GetTOTP(ctx, tenantA, uid)
		require.NoError(t, err)
		assert.Equal(t, "ABCDEF", got.Secret)
		assert.False(t, got.Confirmed())

		// Upsert: confirm it.
		now := time.Now()
		got.ConfirmedAt = &now
		require.NoError(t, store.SaveTOTP(ctx, tenantA, got))
		got, err = store.GetTOTP(ctx, tenantA, uid)
		require.NoError(t, err)
		assert.True(t, got.Confirmed())

		require.NoError(t, store.DeleteTOTP(ctx, tenantA, uid))
		_, err = store.GetTOTP(ctx, tenantA, uid)
		assert.ErrorIs(t, err, mfa.ErrNotEnrolled)
		// Delete is idempotent.
		require.NoError(t, store.DeleteTOTP(ctx, tenantA, uid))
	})

	t.Run("TOTP replay guard is monotonic", func(t *testing.T) {
		uid := uuid.New()
		require.NoError(t, store.SaveTOTP(ctx, tenantA, &mfa.TOTPEnrollment{UserID: uid, Secret: "S", CreatedAt: time.Now()}))

		applied, err := store.MarkTOTPUsed(ctx, tenantA, uid, 100)
		require.NoError(t, err)
		assert.True(t, applied, "first step must be accepted")

		applied, err = store.MarkTOTPUsed(ctx, tenantA, uid, 100)
		require.NoError(t, err)
		assert.False(t, applied, "replaying the same step must be rejected")

		applied, err = store.MarkTOTPUsed(ctx, tenantA, uid, 99)
		require.NoError(t, err)
		assert.False(t, applied, "an older step must be rejected")

		applied, err = store.MarkTOTPUsed(ctx, tenantA, uid, 101)
		require.NoError(t, err)
		assert.True(t, applied, "a newer step must be accepted")
	})

	t.Run("recovery codes are single-use and replaceable", func(t *testing.T) {
		uid := uuid.New()
		require.NoError(t, store.ReplaceRecoveryCodes(ctx, tenantA, uid, []string{"h1", "h2", "h3"}))

		// Unknown hash.
		assert.ErrorIs(t, store.ConsumeRecoveryCode(ctx, tenantA, uid, "nope"), mfa.ErrRecoveryCodeNotFound)

		// Consume once succeeds, twice fails.
		require.NoError(t, store.ConsumeRecoveryCode(ctx, tenantA, uid, "h2"))
		assert.ErrorIs(t, store.ConsumeRecoveryCode(ctx, tenantA, uid, "h2"), mfa.ErrRecoveryCodeNotFound)

		// Replace discards the old set entirely.
		require.NoError(t, store.ReplaceRecoveryCodes(ctx, tenantA, uid, []string{"n1"}))
		assert.ErrorIs(t, store.ConsumeRecoveryCode(ctx, tenantA, uid, "h1"), mfa.ErrRecoveryCodeNotFound)
		require.NoError(t, store.ConsumeRecoveryCode(ctx, tenantA, uid, "n1"))

		// Delete is idempotent.
		require.NoError(t, store.DeleteRecoveryCodes(ctx, tenantA, uid))
		require.NoError(t, store.DeleteRecoveryCodes(ctx, tenantA, uid))
	})

	t.Run("SaveTOTP ErrTenantMismatch", func(t *testing.T) {
		uid := uuid.New()
		e := &mfa.TOTPEnrollment{UserID: uid, TenantID: "other-tenant", Secret: "S", CreatedAt: time.Now()}
		err := store.SaveTOTP(ctx, tenantA, e)
		assert.ErrorIs(t, err, mfa.ErrTenantMismatch,
			"SaveTOTP must reject a record whose TenantID conflicts with the tenantID arg")
	})

	if useMultiTenant {
		t.Run("tenant isolation", func(t *testing.T) {
			uid := uuid.New()
			require.NoError(t, store.SaveTOTP(ctx, tenantA, &mfa.TOTPEnrollment{UserID: uid, Secret: "A", CreatedAt: time.Now()}))

			_, err := store.GetTOTP(ctx, tenantB, uid)
			assert.ErrorIs(t, err, mfa.ErrNotEnrolled, "tenant B must not see tenant A's enrollment")

			require.NoError(t, store.ReplaceRecoveryCodes(ctx, tenantA, uid, []string{"hA"}))
			assert.ErrorIs(t, store.ConsumeRecoveryCode(ctx, tenantB, uid, "hA"), mfa.ErrRecoveryCodeNotFound)
			require.NoError(t, store.ConsumeRecoveryCode(ctx, tenantA, uid, "hA"))
		})
	}
}
