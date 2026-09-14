package mfa_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/mfa"
	"github.com/JLugagne/egauth/mfa/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyTOTP_LockoutDecaysAfterDuration verifies that a locked-out TOTP factor becomes
// usable again once the configurable LockoutDuration has elapsed (time-bound lockout).
// Before the fix this test FAILS: the lockout is permanent and the correct code is still
// rejected after the window expires.
func TestVerifyTOTP_LockoutDecaysAfterDuration(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	const maxAttempts = 3
	const lockoutDuration = 15 * time.Minute

	svc := mfa.NewService(
		memory.NewStore(),
		mfa.WithClock(clk.now),
		mfa.WithMaxAttempts(maxAttempts),
		mfa.WithLockoutDuration(lockoutDuration),
	)
	uid := uuid.Must(uuid.NewV7())
	secret, _ := enrollAndConfirm(t, ctx, svc, clk, uid)

	// Advance one period so a new code window is available.
	clk.t = clk.t.Add(mfa.DefaultPeriod)

	// Exhaust the attempt budget to lock the factor.
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrTooManyAttempts)

	// The factor is now locked; even the correct code must be rejected at this point.
	clk.t = clk.t.Add(mfa.DefaultPeriod)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, clk.code(t, secret)), mfa.ErrTooManyAttempts,
		"factor must remain locked before the lockout duration elapses")

	// Advance past the lockout window.
	clk.t = clk.t.Add(lockoutDuration + time.Second)

	// After the window the lockout must have decayed: the correct code is now accepted.
	require.NoError(t, svc.VerifyTOTP(ctx, "", uid, clk.code(t, secret)),
		"a valid code must be accepted once LockoutDuration has elapsed")
}

// TestVerifyRecoveryCode_LockoutDecaysAfterDuration mirrors the TOTP test for the
// recovery-code path: after the lockout window expires, a valid recovery code is accepted.
func TestVerifyRecoveryCode_LockoutDecaysAfterDuration(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	const maxAttempts = 3
	const lockoutDuration = 15 * time.Minute

	svc := mfa.NewService(
		memory.NewStore(),
		mfa.WithClock(clk.now),
		mfa.WithMaxAttempts(maxAttempts),
		mfa.WithLockoutDuration(lockoutDuration),
	)
	uid := uuid.Must(uuid.NewV7())
	_, recovery := enrollAndConfirm(t, ctx, svc, clk, uid)

	// Exhaust the attempt budget via wrong recovery codes.
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, "", uid, "WRONG-1"), mfa.ErrRecoveryCodeNotFound)
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, "", uid, "WRONG-2"), mfa.ErrRecoveryCodeNotFound)
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, "", uid, "WRONG-3"), mfa.ErrTooManyAttempts)

	// Factor is locked; valid recovery code must still be rejected.
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, "", uid, recovery[0]), mfa.ErrTooManyAttempts,
		"recovery path must also be locked before the lockout duration elapses")

	// Advance past the lockout window.
	clk.t = clk.t.Add(lockoutDuration + time.Second)

	// After the window the lockout must have decayed: the valid recovery code is accepted.
	require.NoError(t, svc.VerifyRecoveryCode(ctx, "", uid, recovery[0]),
		"a valid recovery code must be accepted once LockoutDuration has elapsed")
}

// TestUnlockMFA_AdminPrimitive verifies that UnlockMFA immediately clears the lockout,
// regardless of elapsed time, providing the admin escape hatch required by the audit finding.
func TestUnlockMFA_AdminPrimitive(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	const maxAttempts = 3

	svc := mfa.NewService(
		memory.NewStore(),
		mfa.WithClock(clk.now),
		mfa.WithMaxAttempts(maxAttempts),
	)
	uid := uuid.Must(uuid.NewV7())
	secret, _ := enrollAndConfirm(t, ctx, svc, clk, uid)

	clk.t = clk.t.Add(mfa.DefaultPeriod)

	// Lock the factor.
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrTooManyAttempts)

	// Factor is locked; correct code rejected.
	clk.t = clk.t.Add(mfa.DefaultPeriod)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, clk.code(t, secret)), mfa.ErrTooManyAttempts)

	// Admin unlocks — WITHOUT advancing time.
	require.NoError(t, svc.UnlockMFA(ctx, "", uid), "UnlockMFA must succeed for an enrolled user")

	// The correct code is now accepted immediately after the admin unlock.
	clk.t = clk.t.Add(mfa.DefaultPeriod)
	require.NoError(t, svc.VerifyTOTP(ctx, "", uid, clk.code(t, secret)),
		"a valid code must be accepted immediately after UnlockMFA")
}

// TestWithLockoutDurationZeroIsPermanent pins the documented meaning of the strictest lockout
// configuration. The constructor used to rewrite a zero duration to DefaultLockoutDuration, which
// made "the caller left it alone" and "the caller asked for a permanent lockout" indistinguishable:
// a deployment that deliberately chose "after 5 bad codes this factor is dead until an operator
// intervenes" silently got 5 guesses every 15 minutes, forever, with no signal that the permanent
// lockout never took effect.
func TestWithLockoutDurationZeroIsPermanent(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	svc := mfa.NewService(memory.NewStore(),
		mfa.WithLockoutDuration(0),
		mfa.WithClock(clock),
	)
	uid := uuid.Must(uuid.NewV7())
	enroll, err := svc.EnrollTOTP(ctx, "", uid, "user@example.com")
	require.NoError(t, err)
	code, err := mfa.GenerateCode(enroll.Secret, now, mfa.DefaultDigits, mfa.DefaultPeriod)
	require.NoError(t, err)
	_, err = svc.ConfirmTOTP(ctx, "", uid, code)
	require.NoError(t, err)

	// Burn the budget.
	for i := 0; i < mfa.DefaultMaxAttempts; i++ {
		now = now.Add(time.Second)
		require.Error(t, svc.VerifyTOTP(ctx, "", uid, "000000"))
	}
	now = now.Add(time.Second)
	require.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrTooManyAttempts,
		"precondition: the factor is locked")

	// Walk far past the default window. A permanent lockout must not decay.
	now = now.Add(24 * time.Hour)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrTooManyAttempts,
		"WithLockoutDuration(0) must stay locked past DefaultLockoutDuration, as documented")

	// And an operator can still release it explicitly.
	require.NoError(t, svc.UnlockMFA(ctx, "", uid))
}

// TestDefaultLockoutDurationStillDecays is the control: the seeded default must keep decaying, so
// fixing the zero case did not turn every deployment into a permanent lockout.
func TestDefaultLockoutDurationStillDecays(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clock))
	uid := uuid.Must(uuid.NewV7())
	enroll, err := svc.EnrollTOTP(ctx, "", uid, "user@example.com")
	require.NoError(t, err)
	code, err := mfa.GenerateCode(enroll.Secret, now, mfa.DefaultDigits, mfa.DefaultPeriod)
	require.NoError(t, err)
	_, err = svc.ConfirmTOTP(ctx, "", uid, code)
	require.NoError(t, err)

	for i := 0; i < mfa.DefaultMaxAttempts; i++ {
		now = now.Add(time.Second)
		require.Error(t, svc.VerifyTOTP(ctx, "", uid, "000000"))
	}
	now = now.Add(time.Second)
	require.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrTooManyAttempts)

	now = now.Add(mfa.DefaultLockoutDuration + time.Second)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode,
		"the default window must still decay to a fresh budget")
}

// TestNegativeLockoutDurationMeansPermanent documents the boundary: a negative duration has no
// meaning as a window, so it selects the strictest behaviour rather than being silently rewritten.
func TestNegativeLockoutDurationMeansPermanent(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	svc := mfa.NewService(memory.NewStore(), mfa.WithLockoutDuration(-time.Minute), mfa.WithClock(clock))
	uid := uuid.Must(uuid.NewV7())
	enroll, err := svc.EnrollTOTP(ctx, "", uid, "user@example.com")
	require.NoError(t, err)
	code, err := mfa.GenerateCode(enroll.Secret, now, mfa.DefaultDigits, mfa.DefaultPeriod)
	require.NoError(t, err)
	_, err = svc.ConfirmTOTP(ctx, "", uid, code)
	require.NoError(t, err)

	for i := 0; i < mfa.DefaultMaxAttempts; i++ {
		now = now.Add(time.Second)
		require.Error(t, svc.VerifyTOTP(ctx, "", uid, "000000"))
	}
	now = now.Add(time.Second)
	require.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrTooManyAttempts)
	now = now.Add(24 * time.Hour)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrTooManyAttempts)
}
