// Package storetest provides a shared conformance suite for otp.Store implementations.
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/libauth/otp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// StrictTenancyTesting asserts that a store built with strict tenancy rejects every operation
// performed without a tenant (no WithTenant) via ErrTenantRequired, and accepts the same
// operations once a tenant is supplied. Pass a store constructed WithStrictTenancy.
func StrictTenancyTesting(t *testing.T, strict otp.Store) {
	ctx := context.Background()
	sub := uuid.New()

	// No tenant -> ErrTenantRequired on every tenant-scoped op.
	err := strict.SaveOTP(ctx, &otp.OTP{SubjectID: sub, Purpose: "login", CodeHash: "h", ExpiresAt: time.Now().Add(time.Minute)})
	assert.ErrorIs(t, err, otp.ErrTenantRequired, "SaveOTP without a tenant must be rejected in strict mode")
	_, err = strict.GetOTP(ctx, sub, "login")
	assert.ErrorIs(t, err, otp.ErrTenantRequired)
	_, err = strict.IncrementOTPAttempts(ctx, sub, "login")
	assert.ErrorIs(t, err, otp.ErrTenantRequired)
	_, err = strict.ConsumeOTP(ctx, sub, "login")
	assert.ErrorIs(t, err, otp.ErrTenantRequired)
	err = strict.DeleteOTP(ctx, sub, "login")
	assert.ErrorIs(t, err, otp.ErrTenantRequired)

	// With a tenant the same ops work.
	require.NoError(t, strict.SaveOTP(ctx, &otp.OTP{SubjectID: sub, Purpose: "login", CodeHash: "h", ExpiresAt: time.Now().Add(time.Minute)}, otp.WithTenant("t1")))
	got, err := strict.GetOTP(ctx, sub, "login", otp.WithTenant("t1"))
	require.NoError(t, err)
	assert.Equal(t, "h", got.CodeHash)
}

// StoreContractTesting exercises any otp.Store implementation: save/get, attempt counting,
// replacement semantics, idempotent delete and (optionally) tenant isolation.
func StoreContractTesting(t *testing.T, store otp.Store, useMultiTenant bool) {
	ctx := context.Background()
	var tenantA, tenantB string
	if useMultiTenant {
		tenantA, tenantB = "tenant-A", "tenant-B"
	}

	t.Run("DeleteExpired purges only expired codes", func(t *testing.T) {
		expiredSub, liveSub := uuid.New(), uuid.New()
		require.NoError(t, store.SaveOTP(ctx, &otp.OTP{
			SubjectID: expiredSub, Purpose: "login", CodeHash: "exp", ExpiresAt: time.Now().Add(-time.Minute), CreatedAt: time.Now().Add(-time.Hour),
		}, otp.WithTenant(tenantA)))
		require.NoError(t, store.SaveOTP(ctx, &otp.OTP{
			SubjectID: liveSub, Purpose: "login", CodeHash: "live", ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
		}, otp.WithTenant(tenantA)))

		n, err := store.DeleteExpired(ctx, otp.WithTenant(tenantA))
		require.NoError(t, err)
		assert.GreaterOrEqual(t, n, int64(1))

		_, err = store.GetOTP(ctx, expiredSub, "login", otp.WithTenant(tenantA))
		assert.ErrorIs(t, err, otp.ErrCodeNotFound, "expired code must be gone")
		_, err = store.GetOTP(ctx, liveSub, "login", otp.WithTenant(tenantA))
		assert.NoError(t, err, "live code must be kept")
	})

	t.Run("save / get / attempts / delete", func(t *testing.T) {
		sub := uuid.New()
		_, err := store.GetOTP(ctx, sub, "login", otp.WithTenant(tenantA))
		assert.ErrorIs(t, err, otp.ErrCodeNotFound)

		require.NoError(t, store.SaveOTP(ctx, &otp.OTP{
			SubjectID: sub, Purpose: "login", CodeHash: "h1", ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
		}, otp.WithTenant(tenantA)))

		got, err := store.GetOTP(ctx, sub, "login", otp.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, "h1", got.CodeHash)
		assert.Equal(t, 0, got.Attempts)

		// Attempts increment and persist.
		n, err := store.IncrementOTPAttempts(ctx, sub, "login", otp.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		n, err = store.IncrementOTPAttempts(ctx, sub, "login", otp.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, 2, n)
		got, _ = store.GetOTP(ctx, sub, "login", otp.WithTenant(tenantA))
		assert.Equal(t, 2, got.Attempts)

		// Save replaces the prior code AND resets attempts.
		require.NoError(t, store.SaveOTP(ctx, &otp.OTP{
			SubjectID: sub, Purpose: "login", CodeHash: "h2", ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
		}, otp.WithTenant(tenantA)))
		got, _ = store.GetOTP(ctx, sub, "login", otp.WithTenant(tenantA))
		assert.Equal(t, "h2", got.CodeHash)
		assert.Equal(t, 0, got.Attempts, "re-issuing must reset the attempt counter")

		// Different purpose is independent.
		_, err = store.GetOTP(ctx, sub, "step_up", otp.WithTenant(tenantA))
		assert.ErrorIs(t, err, otp.ErrCodeNotFound)

		// Delete is idempotent.
		require.NoError(t, store.DeleteOTP(ctx, sub, "login", otp.WithTenant(tenantA)))
		_, err = store.GetOTP(ctx, sub, "login", otp.WithTenant(tenantA))
		assert.ErrorIs(t, err, otp.ErrCodeNotFound)
		require.NoError(t, store.DeleteOTP(ctx, sub, "login", otp.WithTenant(tenantA)))

		// Incrementing a missing code reports not-found.
		_, err = store.IncrementOTPAttempts(ctx, sub, "login", otp.WithTenant(tenantA))
		assert.ErrorIs(t, err, otp.ErrCodeNotFound)
	})

	t.Run("ConsumeOTP is a guarded single-use delete", func(t *testing.T) {
		sub := uuid.New()
		// Consuming a non-existent code reports not-removed (no error).
		ok, err := store.ConsumeOTP(ctx, sub, "login", otp.WithTenant(tenantA))
		require.NoError(t, err)
		assert.False(t, ok)

		require.NoError(t, store.SaveOTP(ctx, &otp.OTP{
			SubjectID: sub, Purpose: "login", CodeHash: "h", ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
		}, otp.WithTenant(tenantA)))

		// Exactly one consume wins; a second reports not-removed.
		ok, err = store.ConsumeOTP(ctx, sub, "login", otp.WithTenant(tenantA))
		require.NoError(t, err)
		assert.True(t, ok)
		ok, err = store.ConsumeOTP(ctx, sub, "login", otp.WithTenant(tenantA))
		require.NoError(t, err)
		assert.False(t, ok, "the code may be consumed only once")
	})

	if useMultiTenant {
		t.Run("tenant isolation", func(t *testing.T) {
			sub := uuid.New()
			require.NoError(t, store.SaveOTP(ctx, &otp.OTP{
				SubjectID: sub, Purpose: "login", CodeHash: "hA", ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
			}, otp.WithTenant(tenantA)))

			_, err := store.GetOTP(ctx, sub, "login", otp.WithTenant(tenantB))
			assert.ErrorIs(t, err, otp.ErrCodeNotFound, "tenant B must not see tenant A's code")
		})
	}
}
