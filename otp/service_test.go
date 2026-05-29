package otp_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/libauth/otp"
	"github.com/JLugagne/libauth/otp/memory"
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

	ch, err := svc.Issue(ctx, sub, "login", otp.WithTenant("t1"))
	require.NoError(t, err)
	require.NotNil(t, ch)
	assert.Len(t, ch.Code, otp.DefaultDigits)
	assert.Regexp(t, `^\d+$`, ch.Code, "code must be numeric")
	assert.Equal(t, "t1", ch.TenantID)

	require.NoError(t, svc.Verify(ctx, sub, "login", ch.Code, otp.WithTenant("t1")))
	// Single-use: the code is consumed.
	assert.ErrorIs(t, svc.Verify(ctx, sub, "login", ch.Code, otp.WithTenant("t1")), otp.ErrCodeNotFound)
}

func TestService_WrongCodeIsAttemptLimited(t *testing.T) {
	ctx := context.Background()
	svc := otp.NewService(memory.NewStore(), otp.WithMaxAttempts(3))
	sub := uuid.New()

	ch, err := svc.Issue(ctx, sub, "login", otp.WithTenant("t1"))
	require.NoError(t, err)
	bad := wrongCode(ch.Code)

	assert.ErrorIs(t, svc.Verify(ctx, sub, "login", bad, otp.WithTenant("t1")), otp.ErrInvalidCode)
	assert.ErrorIs(t, svc.Verify(ctx, sub, "login", bad, otp.WithTenant("t1")), otp.ErrInvalidCode)
	// Third wrong guess hits the limit and burns the code.
	assert.ErrorIs(t, svc.Verify(ctx, sub, "login", bad, otp.WithTenant("t1")), otp.ErrTooManyAttempts)
	// Even the correct code no longer works.
	assert.ErrorIs(t, svc.Verify(ctx, sub, "login", ch.Code, otp.WithTenant("t1")), otp.ErrCodeNotFound)
}

func TestService_Expired(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := otp.NewService(memory.NewStore(), otp.WithClock(clk.now), otp.WithTTL(time.Minute))
	sub := uuid.New()

	ch, err := svc.Issue(ctx, sub, "login", otp.WithTenant("t1"))
	require.NoError(t, err)

	clk.t = clk.t.Add(2 * time.Minute)
	assert.ErrorIs(t, svc.Verify(ctx, sub, "login", ch.Code, otp.WithTenant("t1")), otp.ErrCodeNotFound)
}

func TestService_ReissueReplacesAndResetsAttempts(t *testing.T) {
	ctx := context.Background()
	svc := otp.NewService(memory.NewStore(), otp.WithMaxAttempts(3))
	sub := uuid.New()

	ch1, err := svc.Issue(ctx, sub, "login", otp.WithTenant("t1"))
	require.NoError(t, err)
	// Burn two attempts on the first code.
	_ = svc.Verify(ctx, sub, "login", wrongCode(ch1.Code), otp.WithTenant("t1"))
	_ = svc.Verify(ctx, sub, "login", wrongCode(ch1.Code), otp.WithTenant("t1"))

	// Re-issue: new code, attempts reset.
	ch2, err := svc.Issue(ctx, sub, "login", otp.WithTenant("t1"))
	require.NoError(t, err)
	// The old code is no longer valid.
	assert.ErrorIs(t, svc.Verify(ctx, sub, "login", ch1.Code, otp.WithTenant("t1")), otp.ErrInvalidCode)
	// The new code works (attempt counter was reset, so the prior 2 + this don't exceed 3).
	require.NoError(t, svc.Verify(ctx, sub, "login", ch2.Code, otp.WithTenant("t1")))
}

func TestService_Invalidate(t *testing.T) {
	ctx := context.Background()
	svc := otp.NewService(memory.NewStore())
	sub := uuid.New()

	ch, err := svc.Issue(ctx, sub, "login", otp.WithTenant("t1"))
	require.NoError(t, err)
	require.NoError(t, svc.Invalidate(ctx, sub, "login", otp.WithTenant("t1")))
	assert.ErrorIs(t, svc.Verify(ctx, sub, "login", ch.Code, otp.WithTenant("t1")), otp.ErrCodeNotFound)
}

func TestService_PurposesAreIndependent(t *testing.T) {
	ctx := context.Background()
	svc := otp.NewService(memory.NewStore())
	sub := uuid.New()

	login, err := svc.Issue(ctx, sub, "login", otp.WithTenant("t1"))
	require.NoError(t, err)
	stepUp, err := svc.Issue(ctx, sub, "step_up", otp.WithTenant("t1"))
	require.NoError(t, err)

	// A login code must not satisfy a step-up challenge.
	assert.ErrorIs(t, svc.Verify(ctx, sub, "step_up", login.Code, otp.WithTenant("t1")), otp.ErrInvalidCode)
	require.NoError(t, svc.Verify(ctx, sub, "step_up", stepUp.Code, otp.WithTenant("t1")))
	// The login code is still independently valid.
	require.NoError(t, svc.Verify(ctx, sub, "login", login.Code, otp.WithTenant("t1")))
}
