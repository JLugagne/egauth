package mfa_test

// Regression test for CLUSTER 2 / DEFECT 2: WithLockoutDuration(0) is documented in
// SECURITY.md and in both the field doc and option godoc in mfa/service.go to make a locked
// second factor PERMANENTLY locked until UnlockMFA is called or the factor is disabled.
//
// Prior to the fix, NewService's "untouched zero" normalization could not distinguish a
// deliberate WithLockoutDuration(0) from a caller who never touched the option at all, so it
// always overwrote 0 with DefaultLockoutDuration — making the documented "permanent lockout"
// setting unreachable through the public API.

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

// TestWithLockoutDuration_Zero_IsPermanentUntilUnlock verifies that WithLockoutDuration(0)
// really disables time-based decay: even after a full day, a correct code is still rejected,
// and only an explicit UnlockMFA call clears the lockout.
func TestWithLockoutDuration_Zero_IsPermanentUntilUnlock(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	const maxAttempts = 3

	svc := mfa.NewService(
		memory.NewStore(),
		mfa.WithClock(clk.now),
		mfa.WithMaxAttempts(maxAttempts),
		mfa.WithLockoutDuration(0),
	)
	uid := uuid.Must(uuid.NewV7())
	secret, _ := enrollAndConfirm(t, ctx, svc, clk, uid)

	clk.t = clk.t.Add(mfa.DefaultPeriod)

	// Exhaust the attempt budget to lock the factor.
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrTooManyAttempts)

	// Advance a full day: with a real 0 = "no decay", the lockout must NOT have cleared.
	clk.t = clk.t.Add(24 * time.Hour)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, clk.code(t, secret)), mfa.ErrTooManyAttempts,
		"WithLockoutDuration(0) must make the lockout permanent; it must not decay after 24h")

	// Only the admin escape hatch clears it.
	require.NoError(t, svc.UnlockMFA(ctx, "", uid))
	require.NoError(t, svc.VerifyTOTP(ctx, "", uid, clk.code(t, secret)),
		"a valid code must be accepted after an explicit UnlockMFA call")
}
