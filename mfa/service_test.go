package mfa_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
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
	return svc, c, uuid.Must(uuid.NewV7())
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

	enrolled, err := svc.IsEnrolled(ctx, "", uid)
	require.NoError(t, err)
	assert.False(t, enrolled)

	enrollment, err := svc.EnrollTOTP(ctx, "", uid, "user@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, enrollment.Secret)
	assert.Contains(t, enrollment.URI, "otpauth://totp/")

	// Unconfirmed enrollment must not count as enrolled or satisfy a verify.
	enrolled, err = svc.IsEnrolled(ctx, "", uid)
	require.NoError(t, err)
	assert.False(t, enrolled)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, clk.code(t, enrollment.Secret)), mfa.ErrNotConfirmed)

	// Wrong confirmation code is rejected.
	_, err = svc.ConfirmTOTP(ctx, "", uid, "000000")
	assert.ErrorIs(t, err, mfa.ErrInvalidCode)

	// Confirm with a valid code → recovery codes returned, factor active.
	recovery, err := svc.ConfirmTOTP(ctx, "", uid, clk.code(t, enrollment.Secret))
	require.NoError(t, err)
	assert.Len(t, recovery, mfa.DefaultRecoveryCodeCount)

	enrolled, err = svc.IsEnrolled(ctx, "", uid)
	require.NoError(t, err)
	assert.True(t, enrolled)

	// Re-enrolling a confirmed factor is refused.
	_, err = svc.EnrollTOTP(ctx, "", uid, "user@example.com")
	assert.ErrorIs(t, err, mfa.ErrAlreadyEnrolled)

	// The confirming code was consumed (same time-step) → cannot be replayed for login.
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, clk.code(t, enrollment.Secret)), mfa.ErrInvalidCode)

	// Advance a period: a fresh code verifies, then replaying it fails.
	clk.t = clk.t.Add(mfa.DefaultPeriod)
	fresh := clk.code(t, enrollment.Secret)
	require.NoError(t, svc.VerifyTOTP(ctx, "", uid, fresh))
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, fresh), mfa.ErrInvalidCode, "replay must be rejected")
}

func TestService_RecoveryCodes(t *testing.T) {
	ctx := context.Background()
	svc, clk, uid := newServiceFixture(t)

	enrollment, err := svc.EnrollTOTP(ctx, "", uid, "user@example.com")
	require.NoError(t, err)
	recovery, err := svc.ConfirmTOTP(ctx, "", uid, clk.code(t, enrollment.Secret))
	require.NoError(t, err)
	require.NotEmpty(t, recovery)

	// A recovery code works once, then is consumed.
	require.NoError(t, svc.VerifyRecoveryCode(ctx, "", uid, recovery[0]))
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, "", uid, recovery[0]), mfa.ErrRecoveryCodeNotFound)

	// Regeneration invalidates the remaining old codes.
	fresh, err := svc.RegenerateRecoveryCodes(ctx, "", uid)
	require.NoError(t, err)
	assert.Len(t, fresh, mfa.DefaultRecoveryCodeCount)
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, "", uid, recovery[1]), mfa.ErrRecoveryCodeNotFound)
	require.NoError(t, svc.VerifyRecoveryCode(ctx, "", uid, fresh[0]))
}

func TestService_Disable(t *testing.T) {
	ctx := context.Background()
	svc, clk, uid := newServiceFixture(t)

	enrollment, err := svc.EnrollTOTP(ctx, "", uid, "user@example.com")
	require.NoError(t, err)
	recovery, err := svc.ConfirmTOTP(ctx, "", uid, clk.code(t, enrollment.Secret))
	require.NoError(t, err)

	require.NoError(t, svc.DisableTOTP(ctx, "", uid))

	enrolled, err := svc.IsEnrolled(ctx, "", uid)
	require.NoError(t, err)
	assert.False(t, enrolled)

	clk.t = clk.t.Add(mfa.DefaultPeriod)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, clk.code(t, enrollment.Secret)), mfa.ErrNotEnrolled)
	// Recovery codes are gone too.
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, "", uid, recovery[0]), mfa.ErrRecoveryCodeNotFound)

	// Disable is idempotent.
	require.NoError(t, svc.DisableTOTP(ctx, "", uid))
}

// enrollAndConfirm enrolls and confirms a TOTP factor for uid against svc, returning the secret.
func enrollAndConfirm(t *testing.T, ctx context.Context, svc mfa.Service, clk *clock, uid uuid.UUID) (string, []string) {
	t.Helper()
	enrollment, err := svc.EnrollTOTP(ctx, "", uid, "user@example.com")
	require.NoError(t, err)
	recovery, err := svc.ConfirmTOTP(ctx, "", uid, clk.code(t, enrollment.Secret))
	require.NoError(t, err)
	return enrollment.Secret, recovery
}

func TestVerifyTOTPAttemptLimit(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	const maxAttempts = 3
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithMaxAttempts(maxAttempts))
	uid := uuid.Must(uuid.NewV7())
	secret, _ := enrollAndConfirm(t, ctx, svc, clk, uid)

	// Advance one period so a fresh (un-replayed) code would otherwise be accepted.
	clk.t = clk.t.Add(mfa.DefaultPeriod)

	// The first maxAttempts-1 wrong guesses are plain invalid; the maxAttempts-th locks.
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrTooManyAttempts)

	// Once locked, even the CORRECT code is rejected.
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, clk.code(t, secret)), mfa.ErrTooManyAttempts)
}

func TestVerifyTOTP_SuccessResetsAttemptCounter(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithMaxAttempts(3))
	uid := uuid.Must(uuid.NewV7())
	secret, _ := enrollAndConfirm(t, ctx, svc, clk, uid)

	clk.t = clk.t.Add(mfa.DefaultPeriod)
	// Two wrong guesses, then a correct one resets the budget.
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode)
	require.NoError(t, svc.VerifyTOTP(ctx, "", uid, clk.code(t, secret)))

	// The counter was reset: a fresh window again tolerates the full budget.
	clk.t = clk.t.Add(mfa.DefaultPeriod)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode)
	require.NoError(t, svc.VerifyTOTP(ctx, "", uid, clk.code(t, secret)), "reset budget must still accept a valid code")
}

func TestVerifyRecoveryCodeAttemptLimit(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	const maxAttempts = 3
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithMaxAttempts(maxAttempts))
	uid := uuid.Must(uuid.NewV7())
	_, recovery := enrollAndConfirm(t, ctx, svc, clk, uid)

	// Wrong recovery codes share the second-factor budget and lock the factor.
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, "", uid, "WRONG-CODE-0001"), mfa.ErrRecoveryCodeNotFound)
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, "", uid, "WRONG-CODE-0002"), mfa.ErrRecoveryCodeNotFound)
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, "", uid, "WRONG-CODE-0003"), mfa.ErrTooManyAttempts)

	// Locked: even a VALID recovery code is now rejected.
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, "", uid, recovery[0]), mfa.ErrTooManyAttempts)
	// But the TOTP path is NOT locked (isolated budget).
	clk.t = clk.t.Add(mfa.DefaultPeriod)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode)
}

// TestVerifyRecoveryCode_IsolatedFromTOTPLockout verifies that exhausting TOTP failed attempts
// does not lock out recovery code verification (SEC-MFA-05).
func TestVerifyRecoveryCode_IsolatedFromTOTPLockout(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	const maxAttempts = 3
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithMaxAttempts(maxAttempts))
	uid := uuid.Must(uuid.NewV7())
	secret, recovery := enrollAndConfirm(t, ctx, svc, clk, uid)

	// Exhaust TOTP attempts
	for i := 0; i < maxAttempts; i++ {
		_ = svc.VerifyTOTP(ctx, "", uid, "000000")
	}
	// TOTP is locked
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrTooManyAttempts)

	// Valid recovery code must succeed despite TOTP lockout
	require.NoError(t, svc.VerifyRecoveryCode(ctx, "", uid, recovery[0]),
		"valid recovery code must succeed even when TOTP attempts are exhausted")

	// Successful recovery code verification resets the TOTP counter
	clk.t = clk.t.Add(mfa.DefaultPeriod)
	require.NoError(t, svc.VerifyTOTP(ctx, "", uid, clk.code(t, secret)),
		"successful recovery code verification must reset TOTP attempt budget")
}

// TestVerifyTOTP_IsolatedFromRecoveryCodeLockout verifies that exhausting recovery code attempts
// does not lock out TOTP verification.
func TestVerifyTOTP_IsolatedFromRecoveryCodeLockout(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	const maxAttempts = 3
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithMaxAttempts(maxAttempts))
	uid := uuid.Must(uuid.NewV7())
	secret, _ := enrollAndConfirm(t, ctx, svc, clk, uid)

	// Exhaust recovery code attempts
	for i := 0; i < maxAttempts; i++ {
		_ = svc.VerifyRecoveryCode(ctx, "", uid, "WRONG-CODE-0000")
	}
	// Recovery codes are locked
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, "", uid, "WRONG-CODE-0000"), mfa.ErrTooManyAttempts)

	// TOTP must still succeed with valid code
	clk.t = clk.t.Add(mfa.DefaultPeriod)
	require.NoError(t, svc.VerifyTOTP(ctx, "", uid, clk.code(t, secret)),
		"valid TOTP code must succeed even when recovery codes are locked out")
}

func TestVerifyRecoveryCode_SuccessResetsAttemptCounter(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithMaxAttempts(3))
	uid := uuid.Must(uuid.NewV7())
	_, recovery := enrollAndConfirm(t, ctx, svc, clk, uid)

	// Two wrong guesses, then a valid recovery code resets the shared budget.
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, "", uid, "WRONG-CODE-0001"), mfa.ErrRecoveryCodeNotFound)
	assert.ErrorIs(t, svc.VerifyRecoveryCode(ctx, "", uid, "WRONG-CODE-0002"), mfa.ErrRecoveryCodeNotFound)
	require.NoError(t, svc.VerifyRecoveryCode(ctx, "", uid, recovery[0]))

	// Budget reset: the TOTP path again tolerates the full set of wrong guesses.
	clk.t = clk.t.Add(mfa.DefaultPeriod)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode)
}

func TestVerifyTOTP_NoAttemptLimit(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithNoAttemptLimit())
	uid := uuid.Must(uuid.NewV7())
	secret, _ := enrollAndConfirm(t, ctx, svc, clk, uid)

	clk.t = clk.t.Add(mfa.DefaultPeriod)
	// Far more wrong guesses than any default limit: none lock the factor.
	for range 50 {
		assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrInvalidCode)
	}
	// A valid code still succeeds afterwards.
	require.NoError(t, svc.VerifyTOTP(ctx, "", uid, clk.code(t, secret)))
}

// TestVerifyTOTP_ConcurrentAttemptLimit asserts that concurrent WRONG guesses cannot run more
// code comparisons than maxAttempts — the atomic reserve-before-compare holds under parallelism.
func TestVerifyTOTP_ConcurrentAttemptLimit(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	const maxAttempts = 5
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithMaxAttempts(maxAttempts))
	uid := uuid.Must(uuid.NewV7())
	enrollAndConfirm(t, ctx, svc, clk, uid)
	clk.t = clk.t.Add(mfa.DefaultPeriod)

	const n = 50
	var invalid int64 // ErrInvalidCode == a comparison actually ran and failed
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range n {
		wg.Go(func() {
			<-start
			if err := svc.VerifyTOTP(ctx, "", uid, "000000"); err == mfa.ErrInvalidCode {
				atomic.AddInt64(&invalid, 1)
			}
		})
	}
	close(start)
	wg.Wait()

	// Only guesses within the budget reach the compare; the rest are rejected as
	// ErrTooManyAttempts without one. So evaluated guesses are bounded by the limit.
	assert.LessOrEqual(t, invalid, int64(maxAttempts), "concurrent wrong guesses must not exceed the attempt ceiling")
	// And the factor is locked afterwards.
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, "", uid, "000000"), mfa.ErrTooManyAttempts)
}

// failingConfirmStore wraps mfa.Store but injects a failure during ConfirmEnrollment.
type failingConfirmStore struct {
	mfa.Store
	failConfirm bool
}

func (s *failingConfirmStore) ConfirmEnrollment(ctx context.Context, tenantID string, enrollment *mfa.TOTPEnrollment, codeHashes []string) error {
	if s.failConfirm {
		return errors.New("simulated error during confirm enrollment")
	}
	return s.Store.ConfirmEnrollment(ctx, tenantID, enrollment, codeHashes)
}

func TestConfirmTOTP_AtomicOnRecoveryFailure(t *testing.T) {
	ctx := context.Background()
	baseStore := memory.NewStore()
	store := &failingConfirmStore{Store: baseStore}
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(store, mfa.WithClock(clk.now))
	uid := uuid.Must(uuid.NewV7())

	enrollment, err := svc.EnrollTOTP(ctx, "", uid, "user@example.com")
	require.NoError(t, err)

	code, err := mfa.GenerateCode(enrollment.Secret, clk.now(), mfa.DefaultDigits, mfa.DefaultPeriod)
	require.NoError(t, err)

	// Simulate failure in ConfirmEnrollment
	store.failConfirm = true

	codes, err := svc.ConfirmTOTP(ctx, "", uid, code)
	assert.Error(t, err)
	assert.Nil(t, codes)

	// User must not be confirmed if ConfirmEnrollment fails
	enrolled, err := svc.IsEnrolled(ctx, "", uid)
	require.NoError(t, err)
	assert.False(t, enrolled, "user must not be confirmed if ConfirmEnrollment fails")

	got, err := store.GetTOTP(ctx, "", uid)
	require.NoError(t, err)
	assert.False(t, got.Confirmed())
	assert.Nil(t, got.ConfirmedAt)

	// Restore and retry
	store.failConfirm = false
	codes, err = svc.ConfirmTOTP(ctx, "", uid, code)
	require.NoError(t, err)
	require.NotEmpty(t, codes)

	enrolled, err = svc.IsEnrolled(ctx, "", uid)
	require.NoError(t, err)
	assert.True(t, enrolled)

	// Recovery codes work
	require.NoError(t, svc.VerifyRecoveryCode(ctx, "", uid, codes[0]))
}
