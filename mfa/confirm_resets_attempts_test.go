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

// TestConfirmTOTP_ResetsFailedAttemptsOnSuccess is a regression test: failed confirmation
// attempts must NOT bleed into the post-enrollment login attempt budget. Before the fix,
// ConfirmTOTP's success path persisted the enrollment snapshot read BEFORE the attempt was
// reserved, so the failed-attempt counter accumulated during confirmation survived into the
// confirmed enrollment — leaving a freshly enrolled user one wrong login code away from a
// lockout. A successful confirm must clear the counter, mirroring VerifyTOTP success.
func TestConfirmTOTP_ResetsFailedAttemptsOnSuccess(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	store := memory.NewStore()
	svc := mfa.NewService(store, mfa.WithClock(clk.now), mfa.WithMaxAttempts(5))
	uid := uuid.Must(uuid.NewV7())

	enr, err := svc.EnrollTOTP(ctx, "", uid, "user@example.com")
	require.NoError(t, err)

	// Advance one period so the confirming code window is fresh.
	clk.t = clk.t.Add(mfa.DefaultPeriod)

	// Two failed confirmation attempts, then a successful one.
	_, err = svc.ConfirmTOTP(ctx, "", uid, "000000")
	require.ErrorIs(t, err, mfa.ErrInvalidCode)
	_, err = svc.ConfirmTOTP(ctx, "", uid, "000000")
	require.ErrorIs(t, err, mfa.ErrInvalidCode)

	code, err := mfa.GenerateCode(enr.Secret, clk.t, mfa.DefaultDigits, mfa.DefaultPeriod)
	require.NoError(t, err)
	_, err = svc.ConfirmTOTP(ctx, "", uid, code)
	require.NoError(t, err)

	// The confirmed enrollment must carry a clean attempt budget.
	stored, err := store.GetTOTP(ctx, "", uid)
	require.NoError(t, err)
	assert.Equal(t, 0, stored.FailedAttempts, "successful confirm must reset the failed-attempt counter")
	assert.True(t, stored.LastAttemptAt.IsZero(), "successful confirm must clear LastAttemptAt")
}
