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

// clock is a mutable time source so tests can advance time across TOTP periods.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newServiceFixture(t *testing.T) (mfa.Service, *clock, uuid.UUID) {
	t.Helper()
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(c.now), mfa.WithIssuer("Acme"))
	return svc, c, uuid.New()
}

// code returns a valid TOTP for the given secret at the fixture's current time.
func (c *clock) code(t *testing.T, secret string) string {
	t.Helper()
	code, err := mfa.GenerateCode(secret, c.t, mfa.DefaultDigits, mfa.DefaultPeriod)
	require.NoError(t, err)
	return code
}

func TestService_EnrollConfirmVerifyFlow(t *testing.T) {
	ctx := context.Background()
	svc, clk, uid := newServiceFixture(t)

	enrolled, err := svc.IsEnrolled(ctx, uid)
	require.NoError(t, err)
	assert.False(t, enrolled)

	enrollment, err := svc.EnrollTOTP(ctx, uid, "user@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, enrollment.Secret)
	assert.Contains(t, enrollment.URI, "otpauth://totp/")

	// Unconfirmed enrollment must not count as enrolled or satisfy a verify.
	enrolled, err = svc.IsEnrolled(ctx, uid)
	require.NoError(t, err)
	assert.False(t, enrolled)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, uid, clk.code(t, enrollment.Secret)), mfa.ErrNotConfirmed)

	// Wrong confirmation code is rejected.
	_, err = svc.ConfirmTOTP(ctx, uid, "000000")
	assert.ErrorIs(t, err, mfa.ErrInvalidCode)

	// Confirm with a valid code → recovery codes returned, factor active.
	recovery, err := svc.ConfirmTOTP(ctx, uid, clk.code(t, enrollment.Secret))
	require.NoError(t, err)
	assert.Len(t, recovery, mfa.DefaultRecoveryCodeCount)

	enrolled, err = svc.IsEnrolled(ctx, uid)
	require.NoError(t, err)
	assert.True(t, enrolled)

	// Re-enrolling a confirmed factor is refused.
	_, err = svc.EnrollTOTP(ctx, uid, "user@example.com")
	assert.ErrorIs(t, err, mfa.ErrAlreadyEnrolled)

	// The confirming code was consumed (same time-step) → cannot be replayed for login.
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, uid, clk.code(t, enrollment.Secret)), mfa.ErrInvalidCode)

	// Advance a period: a fresh code verifies, then replaying it fails.
	clk.t = clk.t.Add(mfa.DefaultPeriod)
	fresh := clk.code(t, enrollment.Secret)
	require.NoError(t, svc.VerifyTOTP(ctx, uid, fresh))
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, uid, fresh), mfa.ErrInvalidCode, "replay must be rejected")
}

func TestService_RecoveryCodes(t *testing.T) {
	ctx := context.Background()
	svc, clk, uid := newServiceFixture(t)

	enrollment, err := svc.EnrollTOTP(ctx, uid, "user@example.com")
	require.NoError(t, err)
	recovery, err := svc.ConfirmTOTP(ctx, uid, clk.code(t, enrollment.Secret))
	require.NoError(t, err)
	require.NotEmpty(t, recovery)

	// A recovery code works once, then is consumed.
	require.NoError(t, svc.VerifyRecoveryCode(ctx, uid, recovery[0]))
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, uid, recovery[0]), mfa.ErrRecoveryCodeNotFound)

	// Regeneration invalidates the remaining old codes.
	fresh, err := svc.RegenerateRecoveryCodes(ctx, uid)
	require.NoError(t, err)
	assert.Len(t, fresh, mfa.DefaultRecoveryCodeCount)
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, uid, recovery[1]), mfa.ErrRecoveryCodeNotFound)
	require.NoError(t, svc.VerifyRecoveryCode(ctx, uid, fresh[0]))
}

func TestService_Disable(t *testing.T) {
	ctx := context.Background()
	svc, clk, uid := newServiceFixture(t)

	enrollment, err := svc.EnrollTOTP(ctx, uid, "user@example.com")
	require.NoError(t, err)
	recovery, err := svc.ConfirmTOTP(ctx, uid, clk.code(t, enrollment.Secret))
	require.NoError(t, err)

	require.NoError(t, svc.DisableTOTP(ctx, uid))

	enrolled, err := svc.IsEnrolled(ctx, uid)
	require.NoError(t, err)
	assert.False(t, enrolled)

	clk.t = clk.t.Add(mfa.DefaultPeriod)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, uid, clk.code(t, enrollment.Secret)), mfa.ErrNotEnrolled)
	// Recovery codes are gone too.
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, uid, recovery[0]), mfa.ErrRecoveryCodeNotFound)

	// Disable is idempotent.
	require.NoError(t, svc.DisableTOTP(ctx, uid))
}
