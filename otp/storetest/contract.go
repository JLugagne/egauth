// Package storetest provides a shared conformance suite for otp.Store implementations.
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/otp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		require.NoError(t, store.SaveOTP(ctx, tenantA, &otp.OTP{
			SubjectID: expiredSub, Purpose: "login", CodeHash: "exp", ExpiresAt: time.Now().Add(-time.Minute), CreatedAt: time.Now().Add(-time.Hour),
		}))
		require.NoError(t, store.SaveOTP(ctx, tenantA, &otp.OTP{
			SubjectID: liveSub, Purpose: "login", CodeHash: "live", ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
		}))

		n, err := store.DeleteExpired(ctx, tenantA)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, n, int64(1))

		_, err = store.GetOTP(ctx, tenantA, expiredSub, "login")
		assert.ErrorIs(t, err, otp.ErrCodeNotFound, "expired code must be gone")
		_, err = store.GetOTP(ctx, tenantA, liveSub, "login")
		assert.NoError(t, err, "live code must be kept")
	})

	t.Run("save / get / attempts / delete", func(t *testing.T) {
		sub := uuid.New()
		_, err := store.GetOTP(ctx, tenantA, sub, "login")
		assert.ErrorIs(t, err, otp.ErrCodeNotFound)

		require.NoError(t, store.SaveOTP(ctx, tenantA, &otp.OTP{
			SubjectID: sub, Purpose: "login", CodeHash: "h1", ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
		}))

		got, err := store.GetOTP(ctx, tenantA, sub, "login")
		require.NoError(t, err)
		assert.Equal(t, "h1", got.CodeHash)
		assert.Equal(t, 0, got.Attempts)

		// Attempts increment and persist.
		n, err := store.IncrementOTPAttempts(ctx, tenantA, sub, "login")
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		n, err = store.IncrementOTPAttempts(ctx, tenantA, sub, "login")
		require.NoError(t, err)
		assert.Equal(t, 2, n)
		got, _ = store.GetOTP(ctx, tenantA, sub, "login")
		assert.Equal(t, 2, got.Attempts)

		// Save replaces the prior code AND resets attempts.
		require.NoError(t, store.SaveOTP(ctx, tenantA, &otp.OTP{
			SubjectID: sub, Purpose: "login", CodeHash: "h2", ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
		}))
		got, _ = store.GetOTP(ctx, tenantA, sub, "login")
		assert.Equal(t, "h2", got.CodeHash)
		assert.Equal(t, 0, got.Attempts, "re-issuing must reset the attempt counter")

		// Different purpose is independent.
		_, err = store.GetOTP(ctx, tenantA, sub, "step_up")
		assert.ErrorIs(t, err, otp.ErrCodeNotFound)

		// Delete is idempotent.
		require.NoError(t, store.DeleteOTP(ctx, tenantA, sub, "login"))
		_, err = store.GetOTP(ctx, tenantA, sub, "login")
		assert.ErrorIs(t, err, otp.ErrCodeNotFound)
		require.NoError(t, store.DeleteOTP(ctx, tenantA, sub, "login"))

		// Incrementing a missing code reports not-found.
		_, err = store.IncrementOTPAttempts(ctx, tenantA, sub, "login")
		assert.ErrorIs(t, err, otp.ErrCodeNotFound)
	})

	t.Run("ConsumeOTP is a guarded single-use delete", func(t *testing.T) {
		sub := uuid.New()
		// Consuming a non-existent code reports not-removed (no error).
		ok, err := store.ConsumeOTP(ctx, tenantA, sub, "login")
		require.NoError(t, err)
		assert.False(t, ok)

		require.NoError(t, store.SaveOTP(ctx, tenantA, &otp.OTP{
			SubjectID: sub, Purpose: "login", CodeHash: "h", ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
		}))

		// Exactly one consume wins; a second reports not-removed.
		ok, err = store.ConsumeOTP(ctx, tenantA, sub, "login")
		require.NoError(t, err)
		assert.True(t, ok)
		ok, err = store.ConsumeOTP(ctx, tenantA, sub, "login")
		require.NoError(t, err)
		assert.False(t, ok, "the code may be consumed only once")
	})

	t.Run("SaveOTP rejects a record whose tenant differs from the argument", func(t *testing.T) {
		sub := uuid.New()
		err := store.SaveOTP(ctx, "different-tenant", &otp.OTP{
			SubjectID: sub, Purpose: "login", CodeHash: "h", TenantID: "tenant-on-record",
			ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
		})
		assert.ErrorIs(t, err, otp.ErrTenantMismatch, "record tenant != argument must be rejected")
	})

	if useMultiTenant {
		t.Run("tenant isolation", func(t *testing.T) {
			sub := uuid.New()
			require.NoError(t, store.SaveOTP(ctx, tenantA, &otp.OTP{
				SubjectID: sub, Purpose: "login", CodeHash: "hA", ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
			}))

			_, err := store.GetOTP(ctx, tenantB, sub, "login")
			assert.ErrorIs(t, err, otp.ErrCodeNotFound, "tenant B must not see tenant A's code")
		})
	}
}
