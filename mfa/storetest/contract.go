// Package storetest provides a shared contract test suite for mfa.Store implementations.
package storetest

import (
	"context"
	"sync"
	"sync/atomic"
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

	t.Run("failed-attempt counter increments, persists and resets on success", func(t *testing.T) {
		uid := uuid.New()
		now := time.Now()

		// Incrementing a missing factor reports not-enrolled.
		_, err := store.IncrementTOTPAttempts(ctx, tenantA, uid, now)
		assert.ErrorIs(t, err, mfa.ErrNotEnrolled)

		require.NoError(t, store.SaveTOTP(ctx, tenantA, &mfa.TOTPEnrollment{UserID: uid, Secret: "S", CreatedAt: now}))

		got, err := store.GetTOTP(ctx, tenantA, uid)
		require.NoError(t, err)
		assert.Equal(t, 0, got.FailedAttempts, "a fresh enrollment starts at zero")

		// Increments return the new count, persist FailedAttempts, and record LastAttemptAt.
		t1 := now.Add(time.Second)
		n, err := store.IncrementTOTPAttempts(ctx, tenantA, uid, t1)
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		t2 := t1.Add(time.Second)
		n, err = store.IncrementTOTPAttempts(ctx, tenantA, uid, t2)
		require.NoError(t, err)
		assert.Equal(t, 2, n)
		got, _ = store.GetTOTP(ctx, tenantA, uid)
		assert.Equal(t, 2, got.FailedAttempts)
		// Truncate to microsecond precision: SQL stores (e.g. PostgreSQL) have µs resolution,
		// not nanosecond, so comparing the stored-and-retrieved value against the original
		// nanosecond timestamp would spuriously fail on a pgx store.
		assert.Equal(t, t2.Truncate(time.Microsecond).UTC(), got.LastAttemptAt.Truncate(time.Microsecond).UTC(), "LastAttemptAt must reflect the most recent increment's now")

		// A successful TOTP step (MarkTOTPUsed) resets the counter and LastAttemptAt to zero.
		applied, err := store.MarkTOTPUsed(ctx, tenantA, uid, 1)
		require.NoError(t, err)
		require.True(t, applied)
		got, _ = store.GetTOTP(ctx, tenantA, uid)
		assert.Equal(t, 0, got.FailedAttempts, "an accepted code clears the lock-out budget")
		assert.True(t, got.LastAttemptAt.IsZero(), "MarkTOTPUsed must clear LastAttemptAt")

		// A consumed recovery code also resets the counter and LastAttemptAt.
		require.NoError(t, store.ReplaceRecoveryCodes(ctx, tenantA, uid, []string{"rc1"}))
		_, err = store.IncrementTOTPAttempts(ctx, tenantA, uid, t1)
		require.NoError(t, err)
		require.NoError(t, store.ConsumeRecoveryCode(ctx, tenantA, uid, "rc1"))
		got, _ = store.GetTOTP(ctx, tenantA, uid)
		assert.Equal(t, 0, got.FailedAttempts, "a valid recovery code clears the lock-out budget")
		assert.True(t, got.LastAttemptAt.IsZero(), "ConsumeRecoveryCode must clear LastAttemptAt")

		// Re-saving (re-enroll) resets the counter via the upsert.
		_, err = store.IncrementTOTPAttempts(ctx, tenantA, uid, t1)
		require.NoError(t, err)
		require.NoError(t, store.SaveTOTP(ctx, tenantA, &mfa.TOTPEnrollment{UserID: uid, Secret: "S2", CreatedAt: time.Now()}))
		got, _ = store.GetTOTP(ctx, tenantA, uid)
		assert.Equal(t, 0, got.FailedAttempts, "re-enrolling must reset the counter")

		require.NoError(t, store.DeleteTOTP(ctx, tenantA, uid))
	})

	t.Run("ResetTOTPAttempts clears the counter and LastAttemptAt", func(t *testing.T) {
		uid := uuid.New()
		now := time.Now()

		// ResetTOTPAttempts on a missing factor must return ErrNotEnrolled.
		err := store.ResetTOTPAttempts(ctx, tenantA, uid)
		assert.ErrorIs(t, err, mfa.ErrNotEnrolled, "reset on missing enrollment must return ErrNotEnrolled")

		require.NoError(t, store.SaveTOTP(ctx, tenantA, &mfa.TOTPEnrollment{UserID: uid, Secret: "S", CreatedAt: now}))

		// Increment a few times to set a non-zero counter and LastAttemptAt.
		_, _ = store.IncrementTOTPAttempts(ctx, tenantA, uid, now.Add(time.Second))
		_, _ = store.IncrementTOTPAttempts(ctx, tenantA, uid, now.Add(2*time.Second))
		got, err := store.GetTOTP(ctx, tenantA, uid)
		require.NoError(t, err)
		assert.Equal(t, 2, got.FailedAttempts)
		assert.False(t, got.LastAttemptAt.IsZero())

		// ResetTOTPAttempts must zero both fields.
		require.NoError(t, store.ResetTOTPAttempts(ctx, tenantA, uid))
		got, err = store.GetTOTP(ctx, tenantA, uid)
		require.NoError(t, err)
		assert.Equal(t, 0, got.FailedAttempts, "ResetTOTPAttempts must zero FailedAttempts")
		assert.True(t, got.LastAttemptAt.IsZero(), "ResetTOTPAttempts must zero LastAttemptAt")

		// Calling ResetTOTPAttempts on an already-zero counter must succeed (idempotent).
		require.NoError(t, store.ResetTOTPAttempts(ctx, tenantA, uid))

		require.NoError(t, store.DeleteTOTP(ctx, tenantA, uid))
	})

	t.Run("IncrementTOTPAttempts is atomic under concurrency", func(t *testing.T) {
		uid := uuid.New()
		require.NoError(t, store.SaveTOTP(ctx, tenantA, &mfa.TOTPEnrollment{UserID: uid, Secret: "S", CreatedAt: time.Now()}))

		const goroutines = 64
		seen := make([]int64, goroutines+1) // count occurrences of each returned value
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				n, err := store.IncrementTOTPAttempts(ctx, tenantA, uid, time.Now())
				if err == nil && n >= 1 && n <= goroutines {
					atomic.AddInt64(&seen[n], 1)
				}
			}()
		}
		close(start)
		wg.Wait()

		// Each concurrent increment must hand out a UNIQUE count (no two callers see the same
		// value), proving the reserve-before-compare gate cannot be raced past the limit.
		for v := 1; v <= goroutines; v++ {
			assert.LessOrEqualf(t, seen[v], int64(1), "value %d handed out more than once (not atomic)", v)
		}
		got, err := store.GetTOTP(ctx, tenantA, uid)
		require.NoError(t, err)
		assert.Equal(t, goroutines, got.FailedAttempts, "every increment must be counted exactly once")

		require.NoError(t, store.DeleteTOTP(ctx, tenantA, uid))
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
