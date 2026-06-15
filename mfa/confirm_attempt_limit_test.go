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

// TestConfirmTOTP_AttemptLimit is a regression test for the missing attempt-limit in
// ConfirmTOTP (audit finding TASK-076). Before the fix, ConfirmTOTP called validateTOTP
// with no reserveAttempt call, allowing unbounded online guessing of the enrollment-
// confirmation code.
func TestConfirmTOTP_AttemptLimit(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	const maxAttempts = 3
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithMaxAttempts(maxAttempts))
	uid := uuid.Must(uuid.NewV7())

	// Enroll but do NOT confirm — we want a pending, unconfirmed enrollment.
	_, err := svc.EnrollTOTP(ctx, "", uid, "user@example.com")
	require.NoError(t, err)

	// Advance one period so the confirming code window is always fresh.
	clk.t = clk.t.Add(mfa.DefaultPeriod)

	// Helper to call ConfirmTOTP and return only the error.
	confirm := func(code string) error {
		_, e := svc.ConfirmTOTP(ctx, "", uid, code)
		return e
	}

	// Exhaust the limit with wrong codes. The first (maxAttempts-1) must return
	// ErrInvalidCode; the last allowed attempt locks and returns ErrTooManyAttempts.
	assert.ErrorIs(t, confirm("000000"), mfa.ErrInvalidCode, "attempt 1 should be ErrInvalidCode")
	assert.ErrorIs(t, confirm("000000"), mfa.ErrInvalidCode, "attempt 2 should be ErrInvalidCode")
	assert.ErrorIs(t, confirm("000000"), mfa.ErrTooManyAttempts, "attempt 3 (at limit) should lock and delete enrollment")

	// After exhaustion the enrollment must have been deleted, so the flow must restart
	// from EnrollTOTP — any further ConfirmTOTP call must return ErrNotEnrolled.
	assert.ErrorIs(t, confirm("000000"), mfa.ErrNotEnrolled,
		"after exhaustion the enrollment must be deleted; ConfirmTOTP must return ErrNotEnrolled")
}
