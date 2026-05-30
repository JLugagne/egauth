// Package storetest provides a shared conformance suite and a functional mock for mfa.Store.
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/libauth/mfa"
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
		// Without WithTenant, every backend must operate on the default (empty) tenant partition
		// rather than rejecting the call. A forgotten tenant is only an error under the explicit
		// WithStrictTenancy opt-in (see StrictTenancyTesting). This pins the cross-backend
		// agreement (I19): the pgx backend historically rejected an empty tenant on SaveTOTP and
		// ReplaceRecoveryCodes while the memory backend accepted it.
		uid := uuid.New()
		require.NoError(t, store.SaveTOTP(ctx, &mfa.TOTPEnrollment{UserID: uid, Secret: "DEF", CreatedAt: time.Now()}),
			"empty tenant must be the valid default partition, not rejected")
		got, err := store.GetTOTP(ctx, uid)
		require.NoError(t, err)
		assert.Equal(t, "DEF", got.Secret)

		require.NoError(t, store.ReplaceRecoveryCodes(ctx, uid, []string{"d1"}),
			"empty tenant must be accepted for recovery codes too")
		require.NoError(t, store.ConsumeRecoveryCode(ctx, uid, "d1"))
	})

	t.Run("TOTP save/get/delete", func(t *testing.T) {
		uid := uuid.New()
		_, err := store.GetTOTP(ctx, uid, mfa.WithTenant(tenantA))
		assert.ErrorIs(t, err, mfa.ErrNotEnrolled, "unknown user must report not-enrolled")

		require.NoError(t, store.SaveTOTP(ctx, &mfa.TOTPEnrollment{
			UserID: uid, Secret: "ABCDEF", CreatedAt: time.Now(),
		}, mfa.WithTenant(tenantA)))

		got, err := store.GetTOTP(ctx, uid, mfa.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, "ABCDEF", got.Secret)
		assert.False(t, got.Confirmed())

		// Upsert: confirm it.
		now := time.Now()
		got.ConfirmedAt = &now
		require.NoError(t, store.SaveTOTP(ctx, got, mfa.WithTenant(tenantA)))
		got, err = store.GetTOTP(ctx, uid, mfa.WithTenant(tenantA))
		require.NoError(t, err)
		assert.True(t, got.Confirmed())

		require.NoError(t, store.DeleteTOTP(ctx, uid, mfa.WithTenant(tenantA)))
		_, err = store.GetTOTP(ctx, uid, mfa.WithTenant(tenantA))
		assert.ErrorIs(t, err, mfa.ErrNotEnrolled)
		// Delete is idempotent.
		require.NoError(t, store.DeleteTOTP(ctx, uid, mfa.WithTenant(tenantA)))
	})

	t.Run("TOTP replay guard is monotonic", func(t *testing.T) {
		uid := uuid.New()
		require.NoError(t, store.SaveTOTP(ctx, &mfa.TOTPEnrollment{UserID: uid, Secret: "S", CreatedAt: time.Now()}, mfa.WithTenant(tenantA)))

		applied, err := store.MarkTOTPUsed(ctx, uid, 100, mfa.WithTenant(tenantA))
		require.NoError(t, err)
		assert.True(t, applied, "first step must be accepted")

		applied, err = store.MarkTOTPUsed(ctx, uid, 100, mfa.WithTenant(tenantA))
		require.NoError(t, err)
		assert.False(t, applied, "replaying the same step must be rejected")

		applied, err = store.MarkTOTPUsed(ctx, uid, 99, mfa.WithTenant(tenantA))
		require.NoError(t, err)
		assert.False(t, applied, "an older step must be rejected")

		applied, err = store.MarkTOTPUsed(ctx, uid, 101, mfa.WithTenant(tenantA))
		require.NoError(t, err)
		assert.True(t, applied, "a newer step must be accepted")
	})

	t.Run("recovery codes are single-use and replaceable", func(t *testing.T) {
		uid := uuid.New()
		require.NoError(t, store.ReplaceRecoveryCodes(ctx, uid, []string{"h1", "h2", "h3"}, mfa.WithTenant(tenantA)))

		// Unknown hash.
		assert.ErrorIs(t, store.ConsumeRecoveryCode(ctx, uid, "nope", mfa.WithTenant(tenantA)), mfa.ErrRecoveryCodeNotFound)

		// Consume once succeeds, twice fails.
		require.NoError(t, store.ConsumeRecoveryCode(ctx, uid, "h2", mfa.WithTenant(tenantA)))
		assert.ErrorIs(t, store.ConsumeRecoveryCode(ctx, uid, "h2", mfa.WithTenant(tenantA)), mfa.ErrRecoveryCodeNotFound)

		// Replace discards the old set entirely.
		require.NoError(t, store.ReplaceRecoveryCodes(ctx, uid, []string{"n1"}, mfa.WithTenant(tenantA)))
		assert.ErrorIs(t, store.ConsumeRecoveryCode(ctx, uid, "h1", mfa.WithTenant(tenantA)), mfa.ErrRecoveryCodeNotFound)
		require.NoError(t, store.ConsumeRecoveryCode(ctx, uid, "n1", mfa.WithTenant(tenantA)))

		// Delete is idempotent.
		require.NoError(t, store.DeleteRecoveryCodes(ctx, uid, mfa.WithTenant(tenantA)))
		require.NoError(t, store.DeleteRecoveryCodes(ctx, uid, mfa.WithTenant(tenantA)))
	})

	if useMultiTenant {
		t.Run("tenant isolation", func(t *testing.T) {
			uid := uuid.New()
			require.NoError(t, store.SaveTOTP(ctx, &mfa.TOTPEnrollment{UserID: uid, Secret: "A", CreatedAt: time.Now()}, mfa.WithTenant(tenantA)))

			_, err := store.GetTOTP(ctx, uid, mfa.WithTenant(tenantB))
			assert.ErrorIs(t, err, mfa.ErrNotEnrolled, "tenant B must not see tenant A's enrollment")

			require.NoError(t, store.ReplaceRecoveryCodes(ctx, uid, []string{"hA"}, mfa.WithTenant(tenantA)))
			assert.ErrorIs(t, store.ConsumeRecoveryCode(ctx, uid, "hA", mfa.WithTenant(tenantB)), mfa.ErrRecoveryCodeNotFound)
			require.NoError(t, store.ConsumeRecoveryCode(ctx, uid, "hA", mfa.WithTenant(tenantA)))
		})
	}
}

// StrictTenancyTesting asserts that a store built WithStrictTenancy rejects every tenant-scoped
// operation performed without a tenant (no WithTenant) via mfa.ErrTenantRequired, and that the
// same operations succeed once a tenant is supplied. Pass a store constructed WithStrictTenancy.
func StrictTenancyTesting(t *testing.T, strict mfa.Store) {
	ctx := context.Background()
	uid := uuid.New()

	t.Run("strict: every tenant-scoped op rejects an empty tenant", func(t *testing.T) {
		assert.ErrorIs(t, strict.SaveTOTP(ctx, &mfa.TOTPEnrollment{UserID: uid, Secret: "S", CreatedAt: time.Now()}),
			mfa.ErrTenantRequired, "SaveTOTP without a tenant must be rejected in strict mode")

		_, err := strict.GetTOTP(ctx, uid)
		assert.ErrorIs(t, err, mfa.ErrTenantRequired)

		assert.ErrorIs(t, strict.DeleteTOTP(ctx, uid), mfa.ErrTenantRequired)

		_, err = strict.MarkTOTPUsed(ctx, uid, 1)
		assert.ErrorIs(t, err, mfa.ErrTenantRequired)

		assert.ErrorIs(t, strict.ReplaceRecoveryCodes(ctx, uid, []string{"h"}), mfa.ErrTenantRequired)
		assert.ErrorIs(t, strict.ConsumeRecoveryCode(ctx, uid, "h"), mfa.ErrTenantRequired)
		assert.ErrorIs(t, strict.DeleteRecoveryCodes(ctx, uid), mfa.ErrTenantRequired)
	})

	t.Run("strict: the same ops succeed once a tenant is supplied", func(t *testing.T) {
		const tenant = "strict-tenant"
		require.NoError(t, strict.SaveTOTP(ctx, &mfa.TOTPEnrollment{UserID: uid, Secret: "S", CreatedAt: time.Now()}, mfa.WithTenant(tenant)))
		got, err := strict.GetTOTP(ctx, uid, mfa.WithTenant(tenant))
		require.NoError(t, err)
		assert.Equal(t, "S", got.Secret)

		require.NoError(t, strict.ReplaceRecoveryCodes(ctx, uid, []string{"r1"}, mfa.WithTenant(tenant)))
		require.NoError(t, strict.ConsumeRecoveryCode(ctx, uid, "r1", mfa.WithTenant(tenant)))
	})
}
