package otp_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/otp"
	"github.com/JLugagne/egauth/otp/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func wrongCode(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}

func TestService_IssueVerify_SingleUse(t *testing.T) {
	ctx := context.Background()
	svc := otp.NewService(memory.NewStore())
	sub := uuid.New()

	ch, err := svc.Issue(ctx, "t1", sub, "login")
	require.NoError(t, err)
	require.NotNil(t, ch)
	assert.Len(t, ch.Code, otp.DefaultDigits)
	assert.Regexp(t, `^\d+$`, ch.Code, "code must be numeric")
	assert.Equal(t, "t1", ch.TenantID)

	require.NoError(t, svc.Verify(ctx, "t1", sub, "login", ch.Code))
	// Single-use: the code is consumed.
	assert.ErrorIs(t, svc.Verify(ctx, "t1", sub, "login", ch.Code), otp.ErrCodeNotFound)
}

func TestService_WrongCodeIsAttemptLimited(t *testing.T) {
	ctx := context.Background()
	svc := otp.NewService(memory.NewStore(), otp.WithMaxAttempts(3))
	sub := uuid.New()

	ch, err := svc.Issue(ctx, "t1", sub, "login")
	require.NoError(t, err)
	bad := wrongCode(ch.Code)

	assert.ErrorIs(t, svc.Verify(ctx, "t1", sub, "login", bad), otp.ErrInvalidCode)
	assert.ErrorIs(t, svc.Verify(ctx, "t1", sub, "login", bad), otp.ErrInvalidCode)
	// Third wrong guess hits the limit and burns the code.
	assert.ErrorIs(t, svc.Verify(ctx, "t1", sub, "login", bad), otp.ErrTooManyAttempts)
	// Even the correct code no longer works.
	assert.ErrorIs(t, svc.Verify(ctx, "t1", sub, "login", ch.Code), otp.ErrCodeNotFound)
}

func TestService_Expired(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := otp.NewService(memory.NewStore(), otp.WithClock(clk.now), otp.WithTTL(time.Minute))
	sub := uuid.New()

	ch, err := svc.Issue(ctx, "t1", sub, "login")
	require.NoError(t, err)

	clk.t = clk.t.Add(2 * time.Minute)
	assert.ErrorIs(t, svc.Verify(ctx, "t1", sub, "login", ch.Code), otp.ErrCodeNotFound)
}

func TestService_ReissueReplacesAndResetsAttempts(t *testing.T) {
	ctx := context.Background()
	svc := otp.NewService(memory.NewStore(), otp.WithMaxAttempts(3))
	sub := uuid.New()

	ch1, err := svc.Issue(ctx, "t1", sub, "login")
	require.NoError(t, err)
	// Burn two attempts on the first code.
	_ = svc.Verify(ctx, "t1", sub, "login", wrongCode(ch1.Code))
	_ = svc.Verify(ctx, "t1", sub, "login", wrongCode(ch1.Code))

	// Re-issue: new code, attempts reset.
	ch2, err := svc.Issue(ctx, "t1", sub, "login")
	require.NoError(t, err)
	// The old code is no longer valid.
	assert.ErrorIs(t, svc.Verify(ctx, "t1", sub, "login", ch1.Code), otp.ErrInvalidCode)
	// The new code works (attempt counter was reset, so the prior 2 + this don't exceed 3).
	require.NoError(t, svc.Verify(ctx, "t1", sub, "login", ch2.Code))
}

func TestService_Invalidate(t *testing.T) {
	ctx := context.Background()
	svc := otp.NewService(memory.NewStore())
	sub := uuid.New()

	ch, err := svc.Issue(ctx, "t1", sub, "login")
	require.NoError(t, err)
	require.NoError(t, svc.Invalidate(ctx, "t1", sub, "login"))
	assert.ErrorIs(t, svc.Verify(ctx, "t1", sub, "login", ch.Code), otp.ErrCodeNotFound)
}

func TestService_PurposesAreIndependent(t *testing.T) {
	ctx := context.Background()
	svc := otp.NewService(memory.NewStore())
	sub := uuid.New()

	login, err := svc.Issue(ctx, "t1", sub, "login")
	require.NoError(t, err)
	stepUp, err := svc.Issue(ctx, "t1", sub, "step_up")
	require.NoError(t, err)

	// A login code must not satisfy a step-up challenge.
	assert.ErrorIs(t, svc.Verify(ctx, "t1", sub, "step_up", login.Code), otp.ErrInvalidCode)
	require.NoError(t, svc.Verify(ctx, "t1", sub, "step_up", stepUp.Code))
	// The login code is still independently valid.
	require.NoError(t, svc.Verify(ctx, "t1", sub, "login", login.Code))
}

func TestOTPNewServiceNilStorePanics(t *testing.T) {
	assert.Panics(t, func() {
		otp.NewService(nil)
	}, "NewService with a nil store must panic at construction, not on the first request")
}

// TestNewService_DigitsBounds verifies that NewService enforces a safe digit
// range [6, 10]. Values below 6 or above 10 must panic so that the comment's
// promise ("clamp to safe minimums") matches the actual behaviour.
func TestNewService_DigitsBounds(t *testing.T) {
	store := memory.NewStore()

	// digits=3 is below the safe minimum — must panic.
	assert.Panics(t, func() {
		otp.NewService(store, otp.WithDigits(3))
	}, "NewService with digits=3 must panic: code space is too small to be secure")

	// digits=6 is the exact minimum — must succeed.
	assert.NotPanics(t, func() {
		otp.NewService(store, otp.WithDigits(6))
	}, "NewService with digits=6 must not panic: 6 is the documented safe minimum")

	// digits=10 is the exact maximum — must succeed.
	assert.NotPanics(t, func() {
		otp.NewService(store, otp.WithDigits(10))
	}, "NewService with digits=10 must not panic: 10 is the documented safe maximum")

	// digits=11 is above the safe maximum — must panic.
	assert.Panics(t, func() {
		otp.NewService(store, otp.WithDigits(11))
	}, "NewService with digits=11 must panic: excessively large digit count is a footgun")
}
