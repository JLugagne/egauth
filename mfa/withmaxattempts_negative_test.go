package mfa_test

// Regression test for CLUSTER 2 / DEFECT 1: WithMaxAttempts with a NEGATIVE value must NOT
// disable second-factor attempt limiting. SECURITY.md and the WithMaxAttempts godoc both claim
// a non-positive value falls back to the safe default; only WithNoAttemptLimit may disable it.
//
// Prior to the fix, NewService's normalization switch mapped ANY negative maxAttempts (not just
// the WithNoAttemptLimit sentinel) to the internal "disabled" value, so WithMaxAttempts(-1)
// silently turned off attempt limiting.

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/mfa"
	"github.com/JLugagne/egauth/mfa/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestWithMaxAttempts_NegativeValue_UsesDefault verifies that WithMaxAttempts(-1) does NOT
// disable attempt limiting — it must fall back to DefaultMaxAttempts.
func TestWithMaxAttempts_NegativeValue_UsesDefault(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}

	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithMaxAttempts(-1))
	uid := uuid.Must(uuid.NewV7())
	enrollAndConfirm(t, ctx, svc, clk, uid)

	clk.t = clk.t.Add(mfa.DefaultPeriod)

	for i := 0; i < mfa.DefaultMaxAttempts-1; i++ {
		assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode,
			"attempt %d should be ErrInvalidCode", i+1)
	}

	// The attempt at DefaultMaxAttempts must lock the factor with ErrTooManyAttempts.
	// If the negative value had disabled limiting, this would still be ErrInvalidCode.
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrTooManyAttempts,
		"WithMaxAttempts(-1) must not disable attempt limiting; factor must lock after DefaultMaxAttempts failures")
}
