// Package storetest holds the conformance suite of mfa.Store implementations.
package storetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/mfa"
)

const goroutines = 16

// Fixtures is what the store implementation's test hands the suite through Seed.
type Fixtures struct {
	// SeedV016 inserts an enrollment with aad_version 0 holding sealed, the way a v0.16 deployment
	// left it. Stores refuse such a write through SaveTOTP, so each implementation provides its own.
	SeedV016 func(t *testing.T, s mfa.Store, sub principal.Subject, sealed []byte)
}

var fixtures sync.Map

// Seed hands Run, for t and its subtests, the fixtures it needs. Call it before Run on the same t.
func Seed(t *testing.T, f Fixtures) {
	t.Helper()
	fixtures.Store(t, f)
	t.Cleanup(func() { fixtures.Delete(t) })
}

// Run exercises the mfa.Store contract against stores returned by newStore. Each subtest gets a
// fresh, empty store. Run fails t unless Seed was called on it.
func Run(t *testing.T, newStore func(*testing.T) mfa.Store) {
	t.Helper()
	v, ok := fixtures.Load(t)
	if !ok {
		t.Fatal("storetest: call Seed(t, Fixtures{...}) before Run")
	}
	f := v.(Fixtures)
	if f.SeedV016 == nil {
		t.Fatal("storetest: Fixtures.SeedV016 is required")
	}
	suites := map[string]func(*testing.T, *harness){
		"Base":                  baseSuite,
		"TOTPRoundTrip":         totpRoundTrip,
		"SaveRefusals":          saveRefusals,
		"HasConfirmedTOTP":      hasConfirmed,
		"EnrolledCounts":        enrolledCounts,
		"ConfirmEnrollment":     confirmEnrollment,
		"ConfirmAtomic":         confirmAtomic,
		"ConfirmKeepsGuards":    confirmKeepsGuards,
		"ReplayGuard":           replayGuard,
		"ReplayGuardConcurrent": replayConcurrent,
		"TOTPLockout":           totpLockout,
		"TOTPLockoutDecay":      totpLockoutDecay,
		"TOTPLockoutRefusals":   lockoutRefusals,
		"TOTPLockoutParallel":   totpLockoutParallel,
		"RecoveryLockout":       recoveryLockout,
		"LockoutsAreIsolated":   lockoutsIsolated,
		"RecoveryCodes":         recoveryCodes,
		"RecoveryConsumeRace":   recoveryConsumeRace,
		"DeleteForSubject":      deleteForSubject,
		"EraseTenant":           eraseTenant,
		"SingleTenant":          singleTenant,
		"SealedOpaque":          sealedOpaque,
		"LegacyUpgrade":         legacyUpgrade,
		"ReplaceSealedCAS":      replaceSealedCAS,
	}
	for name, fn := range suites {
		t.Run(name, func(t *testing.T) { fn(t, &harness{s: newStore(t), f: f}) })
	}
}

type harness struct {
	s mfa.Store
	f Fixtures
}

var base = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

func tenant(t *testing.T, name string) principal.TenantID {
	t.Helper()
	id, err := principal.ParseTenantID(name)
	require.NoError(t, err)
	return id
}

func subjectIn(t *testing.T, tn string) principal.Subject {
	t.Helper()
	return principal.Subject{Tenant: tenant(t, tn), User: uuid.New()}
}

func enrollment(sub principal.Subject, sealed string) mfa.Enrollment {
	return mfa.Enrollment{Subject: sub, Sealed: []byte(sealed), AADVersion: mfa.AADVersionCurrent, CreatedAt: base}
}

func confirmed(sub principal.Subject, sealed string) mfa.Enrollment {
	e := enrollment(sub, sealed)
	e.ConfirmedAt = new(base.Add(time.Minute))
	return e
}

func lockout(sub principal.Subject, now time.Time, max int, d time.Duration) mfa.Lockout {
	return mfa.Lockout{Subject: sub, Now: now, Max: max, Duration: d}
}

func (h *harness) get(t *testing.T, sub principal.Subject) mfa.Enrollment {
	t.Helper()
	e, err := h.s.GetTOTP(context.Background(), sub)
	require.NoError(t, err)
	return e
}

func (h *harness) inc(t *testing.T, l mfa.Lockout) int {
	t.Helper()
	n, err := h.s.IncrementTOTPAttempts(context.Background(), l)
	require.NoError(t, err)
	return n
}

func (h *harness) incRecovery(t *testing.T, l mfa.Lockout) int {
	t.Helper()
	n, err := h.s.IncrementRecoveryAttempts(context.Background(), l)
	require.NoError(t, err)
	return n
}

func (h *harness) enrolled(t *testing.T) (bool, int64) {
	t.Helper()
	any, err := h.s.AnyEnrolled(context.Background())
	require.NoError(t, err)
	n, err := h.s.CountEnrolled(context.Background())
	require.NoError(t, err)
	return any, n
}

func baseSuite(t *testing.T, h *harness) {
	ctx := context.Background()
	require.NoError(t, h.s.Ping(ctx))
	require.True(t, h.s.Durability().Valid())
	require.NoError(t, h.s.EraseTenant(ctx, principal.TenantID{}))
}

func totpRoundTrip(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	_, err := h.s.GetTOTP(ctx, sub)
	require.ErrorIs(t, err, store.ErrNotFound)

	e := enrollment(sub, "sealed-one")
	e.LastUsedStep = 41
	e.FailedAttempts = 2
	e.LastAttemptAt = base.Add(time.Second)
	require.NoError(t, h.s.SaveTOTP(ctx, e))
	got := h.get(t, sub)
	require.Equal(t, sub, got.Subject)
	require.Equal(t, []byte("sealed-one"), got.Sealed)
	require.Equal(t, mfa.AADVersionCurrent, got.AADVersion)
	require.False(t, got.Confirmed())
	require.EqualValues(t, 41, got.LastUsedStep)
	require.Equal(t, 2, got.FailedAttempts)
	require.True(t, e.LastAttemptAt.Equal(got.LastAttemptAt))
	require.True(t, base.Equal(got.CreatedAt))

	got.Sealed[0] = 'X'
	require.Equal(t, []byte("sealed-one"), h.get(t, sub).Sealed, "a returned slice never aliases the store")

	e2 := confirmed(sub, "sealed-two")
	require.NoError(t, h.s.SaveTOTP(ctx, e2))
	got = h.get(t, sub)
	require.Equal(t, []byte("sealed-two"), got.Sealed, "one enrollment per subject, the last save wins")
	require.True(t, got.Confirmed())
	require.True(t, e2.ConfirmedAt.Equal(*got.ConfirmedAt))

	require.NoError(t, h.s.DeleteTOTP(ctx, sub))
	require.NoError(t, h.s.DeleteTOTP(ctx, sub), "idempotent")
	_, err = h.s.GetTOTP(ctx, sub)
	require.ErrorIs(t, err, store.ErrNotFound)

	other := principal.Subject{Tenant: tenant(t, "tenant-b"), User: sub.User}
	require.NoError(t, h.s.SaveTOTP(ctx, enrollment(sub, "a")))
	require.NoError(t, h.s.SaveTOTP(ctx, enrollment(other, "b")))
	require.Equal(t, []byte("a"), h.get(t, sub).Sealed, "the same user id in another tenant is another subject")
	require.Equal(t, []byte("b"), h.get(t, other).Sealed)
}

func saveRefusals(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	legacy := enrollment(sub, "x")
	legacy.AADVersion = mfa.AADVersionLegacy
	require.ErrorIs(t, h.s.SaveTOTP(ctx, legacy), mfa.ErrLegacyAADVersion)
	require.ErrorIs(t, h.s.ConfirmEnrollment(ctx, legacy, []string{"h"}), mfa.ErrLegacyAADVersion)
	_, err := h.s.GetTOTP(ctx, sub)
	require.ErrorIs(t, err, store.ErrNotFound, "a refused write leaves nothing behind")
	ok, err := h.s.AnyEnrolled(ctx)
	require.NoError(t, err)
	require.False(t, ok)

	require.Error(t, h.s.SaveTOTP(ctx, enrollment(principal.Subject{}, "x")))
	require.Error(t, h.s.SaveTOTP(ctx, enrollment(sub, "")))
	bad := enrollment(sub, "x")
	bad.AADVersion = 7
	require.Error(t, h.s.SaveTOTP(ctx, bad))
}

func hasConfirmed(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	has := func() bool {
		ok, err := h.s.HasConfirmedTOTP(ctx, sub)
		require.NoError(t, err)
		return ok
	}
	require.False(t, has())
	require.NoError(t, h.s.SaveTOTP(ctx, enrollment(sub, "x")))
	require.False(t, has(), "an unconfirmed enrollment never satisfies a second-factor check")
	require.NoError(t, h.s.ConfirmEnrollment(ctx, confirmed(sub, "x"), []string{"c1"}))
	require.True(t, has())
	require.NoError(t, h.s.DeleteTOTP(ctx, sub))
	require.False(t, has())
}

func enrolledCounts(t *testing.T, h *harness) {
	ctx := context.Background()
	any, n := h.enrolled(t)
	require.False(t, any)
	require.Zero(t, n)

	a, b, c := subjectIn(t, "tenant-a"), subjectIn(t, "tenant-b"), subjectIn(t, "tenant-b")
	require.NoError(t, h.s.SaveTOTP(ctx, enrollment(a, "x")))
	any, n = h.enrolled(t)
	require.True(t, any, "an unconfirmed enrollment counts")
	require.EqualValues(t, 1, n)

	require.NoError(t, h.s.ReplaceRecoveryCodes(ctx, a, []string{"h1"}))
	_, n = h.enrolled(t)
	require.EqualValues(t, 1, n, "a subject with a TOTP row and codes counts once")

	require.NoError(t, h.s.ReplaceRecoveryCodes(ctx, b, []string{"h2"}))
	_, n = h.enrolled(t)
	require.EqualValues(t, 2, n, "unused recovery codes count across tenants")

	require.NoError(t, h.s.ReplaceRecoveryCodes(ctx, c, []string{"h3"}))
	require.NoError(t, h.s.ConsumeRecoveryCode(ctx, c, "h3"))
	_, n = h.enrolled(t)
	require.EqualValues(t, 2, n, "only used codes do not count")

	require.NoError(t, h.s.DeleteForSubject(ctx, a))
	require.NoError(t, h.s.DeleteRecoveryCodes(ctx, b))
	any, n = h.enrolled(t)
	require.False(t, any)
	require.Zero(t, n)
}

func confirmEnrollment(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	require.NoError(t, h.s.SaveTOTP(ctx, enrollment(sub, "x")))
	require.NoError(t, h.s.ReplaceRecoveryCodes(ctx, sub, []string{"old"}))
	require.NoError(t, h.s.ConfirmEnrollment(ctx, confirmed(sub, "x"), []string{"c1", "c2"}))
	require.True(t, h.get(t, sub).Confirmed())
	require.ErrorIs(t, h.s.ConsumeRecoveryCode(ctx, sub, "old"), store.ErrNotFound, "confirmation replaces earlier codes")
	require.NoError(t, h.s.ConsumeRecoveryCode(ctx, sub, "c1"))
	require.NoError(t, h.s.ConsumeRecoveryCode(ctx, sub, "c2"))
}

func confirmAtomic(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	require.NoError(t, h.s.SaveTOTP(ctx, enrollment(sub, "x")))
	require.NoError(t, h.s.ReplaceRecoveryCodes(ctx, sub, []string{"keep"}))

	require.Error(t, h.s.ConfirmEnrollment(ctx, confirmed(sub, "y"), []string{"dup", "dup"}))
	require.Error(t, h.s.ConfirmEnrollment(ctx, confirmed(sub, "y"), []string{""}))
	require.Error(t, h.s.ConfirmEnrollment(ctx, enrollment(sub, "y"), []string{"c"}), "confirmation needs ConfirmedAt")
	got := h.get(t, sub)
	require.False(t, got.Confirmed(), "a failed confirmation changes neither the enrollment")
	require.Equal(t, []byte("x"), got.Sealed)
	require.NoError(t, h.s.ConsumeRecoveryCode(ctx, sub, "keep"), "nor the recovery codes")

	require.Error(t, h.s.ReplaceRecoveryCodes(ctx, sub, []string{"a", "a"}))
	require.Error(t, h.s.ReplaceRecoveryCodes(ctx, principal.Subject{}, []string{"a"}))
}

func confirmKeepsGuards(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	require.NoError(t, h.s.SaveTOTP(ctx, enrollment(sub, "x")))
	read := h.get(t, sub)
	ok, err := h.s.MarkTOTPUsed(ctx, sub, 100)
	require.NoError(t, err)
	require.True(t, ok)
	read.ConfirmedAt = new(base.Add(time.Minute))
	require.NoError(t, h.s.ConfirmEnrollment(ctx, read, []string{"c1"}))
	got := h.get(t, sub)
	require.True(t, got.Confirmed())
	require.EqualValues(t, 100, got.LastUsedStep, "confirming a stale read never rolls the replay guard back")
	ok, err = h.s.MarkTOTPUsed(ctx, sub, 100)
	require.NoError(t, err)
	require.False(t, ok, "the code that confirmed the enrollment is never accepted twice")

	ahead := h.get(t, sub)
	ahead.LastUsedStep = 500
	require.NoError(t, h.s.ConfirmEnrollment(ctx, ahead, []string{"c2"}))
	require.EqualValues(t, 500, h.get(t, sub).LastUsedStep, "the guard keeps the greatest step")

	locked := subjectIn(t, "tenant-a")
	require.NoError(t, h.s.SaveTOTP(ctx, enrollment(locked, "y")))
	stale := h.get(t, locked)
	for i := range 3 {
		h.inc(t, lockout(locked, base.Add(time.Duration(i)*time.Second), 3, time.Hour))
	}
	before := h.get(t, locked)
	stale.ConfirmedAt = new(base.Add(time.Minute))
	require.NoError(t, h.s.ConfirmEnrollment(ctx, stale, []string{"c1"}))
	after := h.get(t, locked)
	require.Equal(t, 3, after.FailedAttempts, "confirming a stale read never resets the lockout")
	require.True(t, before.LastAttemptAt.Equal(after.LastAttemptAt))
	require.Equal(t, 4, h.inc(t, lockout(locked, base.Add(time.Minute), 3, time.Hour)), "the factor stays locked")
}

func replayGuard(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	ok, err := h.s.MarkTOTPUsed(ctx, sub, 100)
	require.NoError(t, err)
	require.False(t, ok, "no enrollment, nothing to mark")

	require.NoError(t, h.s.SaveTOTP(ctx, confirmed(sub, "x")))
	h.inc(t, lockout(sub, base, 5, time.Hour))
	h.inc(t, lockout(sub, base, 5, time.Hour))
	for _, c := range []struct {
		step int64
		want bool
	}{{100, true}, {100, false}, {99, false}, {1, false}, {101, true}, {101, false}, {500, true}, {499, false}} {
		ok, err := h.s.MarkTOTPUsed(ctx, sub, c.step)
		require.NoError(t, err)
		require.Equal(t, c.want, ok, "step %d", c.step)
	}
	got := h.get(t, sub)
	require.EqualValues(t, 500, got.LastUsedStep)
	require.Zero(t, got.FailedAttempts, "a fresh accepted step resets the failed-attempt counter")
	require.True(t, got.LastAttemptAt.IsZero())
}

func replayConcurrent(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	require.NoError(t, h.s.SaveTOTP(ctx, confirmed(sub, "x")))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			ok, err := h.s.MarkTOTPUsed(ctx, sub, 777)
			if err == nil && ok {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, wins.Load(), "a step is accepted exactly once")
}

func totpLockout(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	_, err := h.s.IncrementTOTPAttempts(ctx, lockout(sub, base, 3, time.Hour))
	require.ErrorIs(t, err, store.ErrNotFound, "no enrollment, no counter")

	require.NoError(t, h.s.SaveTOTP(ctx, confirmed(sub, "x")))
	for want := 1; want <= 3; want++ {
		require.Equal(t, want, h.inc(t, lockout(sub, base.Add(time.Duration(want)*time.Second), 3, time.Hour)))
	}
	locked := h.get(t, sub)
	require.Equal(t, 3, locked.FailedAttempts)
	for i := range 4 {
		require.Equal(t, 4, h.inc(t, lockout(sub, base.Add(time.Minute+time.Duration(i)*time.Second), 3, time.Hour)),
			"a locked factor reports an over-limit count")
	}
	still := h.get(t, sub)
	require.Equal(t, 3, still.FailedAttempts, "the stored count does not grow while locked")
	require.True(t, locked.LastAttemptAt.Equal(still.LastAttemptAt), "a locked factor cannot extend its own lockout")

	require.NoError(t, h.s.ResetTOTPAttempts(ctx, sub))
	got := h.get(t, sub)
	require.Zero(t, got.FailedAttempts)
	require.True(t, got.LastAttemptAt.IsZero())
	require.Equal(t, 1, h.inc(t, lockout(sub, base, 3, time.Hour)))
	require.NoError(t, h.s.ResetTOTPAttempts(ctx, subjectIn(t, "tenant-a")), "resetting an unknown subject is a no-op")

	other := subjectIn(t, "tenant-a")
	require.NoError(t, h.s.SaveTOTP(ctx, confirmed(other, "y")))
	require.Equal(t, 1, h.inc(t, lockout(other, base, 3, time.Hour)), "counters are per subject")
}

func totpLockoutDecay(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	require.NoError(t, h.s.SaveTOTP(ctx, confirmed(sub, "x")))
	d := time.Hour
	h.inc(t, lockout(sub, base, 2, d))
	h.inc(t, lockout(sub, base, 2, d))
	require.Equal(t, 3, h.inc(t, lockout(sub, base.Add(d), 2, d)), "exactly the duration later is still locked")
	require.Equal(t, 1, h.inc(t, lockout(sub, base.Add(d+time.Second), 2, d)), "past the duration the counter restarts")
	require.Equal(t, 2, h.inc(t, lockout(sub, base.Add(d+2*time.Second), 2, d)))
	require.Equal(t, 3, h.inc(t, lockout(sub, base.Add(d+3*time.Second), 2, d)))

	forever := subjectIn(t, "tenant-a")
	require.NoError(t, h.s.SaveTOTP(ctx, confirmed(forever, "y")))
	h.inc(t, lockout(forever, base, 1, 0))
	require.Equal(t, 2, h.inc(t, lockout(forever, base.Add(1000*time.Hour), 1, 0)), "a zero duration never decays")
}

func lockoutRefusals(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	require.NoError(t, h.s.SaveTOTP(ctx, confirmed(sub, "x")))
	for name, l := range map[string]mfa.Lockout{
		"zero subject":      lockout(principal.Subject{}, base, 3, time.Hour),
		"zero max":          lockout(sub, base, 0, time.Hour),
		"negative max":      lockout(sub, base, -1, time.Hour),
		"negative duration": lockout(sub, base, 3, -time.Second),
		"zero now":          lockout(sub, time.Time{}, 3, time.Hour),
	} {
		_, err := h.s.IncrementTOTPAttempts(ctx, l)
		require.Error(t, err, name)
		require.NotErrorIs(t, err, store.ErrNotFound, name)
		_, err = h.s.IncrementRecoveryAttempts(ctx, l)
		require.Error(t, err, name)
	}
	require.Zero(t, h.get(t, sub).FailedAttempts)
}

func totpLockoutParallel(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	require.NoError(t, h.s.SaveTOTP(ctx, confirmed(sub, "x")))
	const max = 5
	var within atomic.Int32
	var wg sync.WaitGroup
	for range 4 * goroutines {
		wg.Go(func() {
			n, err := h.s.IncrementTOTPAttempts(ctx, lockout(sub, base, max, time.Hour))
			if err == nil && n <= max {
				within.Add(1)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, max, within.Load(), "concurrent guesses never get more than Max comparisons")
	require.Equal(t, max, h.get(t, sub).FailedAttempts)
}

func recoveryLockout(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	for want := 1; want <= 3; want++ {
		require.Equal(t, want, h.incRecovery(t, lockout(sub, base.Add(time.Duration(want)*time.Second), 3, time.Hour)),
			"the recovery counter works without a TOTP enrollment")
	}
	for range 3 {
		require.Equal(t, 4, h.incRecovery(t, lockout(sub, base.Add(time.Minute), 3, time.Hour)))
	}
	require.Equal(t, 1, h.incRecovery(t, lockout(sub, base.Add(2*time.Hour), 3, time.Hour)), "decay restarts the counter")
	require.NoError(t, h.s.ResetRecoveryAttempts(ctx, sub))
	require.Equal(t, 1, h.incRecovery(t, lockout(sub, base, 3, time.Hour)))
	require.NoError(t, h.s.ResetRecoveryAttempts(ctx, sub))
	require.NoError(t, h.s.ResetRecoveryAttempts(ctx, sub), "idempotent")

	var wins atomic.Int32
	var wg sync.WaitGroup
	racer := subjectIn(t, "tenant-a")
	for range 4 * goroutines {
		wg.Go(func() {
			n, err := h.s.IncrementRecoveryAttempts(ctx, lockout(racer, base, 4, time.Hour))
			if err == nil && n <= 4 {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 4, wins.Load(), "concurrent first guesses never exceed Max")
}

func lockoutsIsolated(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	require.NoError(t, h.s.SaveTOTP(ctx, confirmed(sub, "x")))
	for range 3 {
		h.inc(t, lockout(sub, base, 3, time.Hour))
	}
	require.Equal(t, 4, h.inc(t, lockout(sub, base, 3, time.Hour)))
	require.Equal(t, 1, h.incRecovery(t, lockout(sub, base, 3, time.Hour)), "exhausting TOTP does not lock the recovery codes")
	for range 2 {
		h.incRecovery(t, lockout(sub, base, 3, time.Hour))
	}
	require.NoError(t, h.s.ResetTOTPAttempts(ctx, sub))
	require.Equal(t, 4, h.incRecovery(t, lockout(sub, base, 3, time.Hour)), "resetting TOTP leaves the recovery counter")
	require.Equal(t, 1, h.inc(t, lockout(sub, base, 3, time.Hour)))
}

func recoveryCodes(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	other := subjectIn(t, "tenant-b")
	require.ErrorIs(t, h.s.ConsumeRecoveryCode(ctx, sub, "c1"), store.ErrNotFound)
	require.NoError(t, h.s.SaveTOTP(ctx, confirmed(sub, "x")))
	require.NoError(t, h.s.ReplaceRecoveryCodes(ctx, sub, []string{"c1", "c2"}))
	require.NoError(t, h.s.ReplaceRecoveryCodes(ctx, other, []string{"c1"}))

	require.ErrorIs(t, h.s.ConsumeRecoveryCode(ctx, sub, "nope"), store.ErrNotFound)
	require.ErrorIs(t, h.s.ConsumeRecoveryCode(ctx, sub, ""), store.ErrNotFound)

	h.inc(t, lockout(sub, base, 5, time.Hour))
	h.inc(t, lockout(sub, base, 5, time.Hour))
	h.incRecovery(t, lockout(sub, base, 5, time.Hour))
	require.NoError(t, h.s.ConsumeRecoveryCode(ctx, sub, "c1"))
	require.Zero(t, h.get(t, sub).FailedAttempts, "a recovery code resets the TOTP counter")
	require.Equal(t, 1, h.incRecovery(t, lockout(sub, base, 5, time.Hour)), "and the recovery counter")

	require.ErrorIs(t, h.s.ConsumeRecoveryCode(ctx, sub, "c1"), store.ErrNotFound, "a code is single-use")
	require.NoError(t, h.s.ConsumeRecoveryCode(ctx, other, "c1"), "codes are per subject")

	require.NoError(t, h.s.ReplaceRecoveryCodes(ctx, sub, []string{"n1"}))
	require.ErrorIs(t, h.s.ConsumeRecoveryCode(ctx, sub, "c2"), store.ErrNotFound, "replacing discards the old codes")
	require.ErrorIs(t, h.s.ConsumeRecoveryCode(ctx, sub, "c1"), store.ErrNotFound, "a used code is not revived")
	require.Equal(t, 1, h.incRecovery(t, lockout(sub, base, 5, time.Hour)), "replacing clears the recovery counter")
	require.NoError(t, h.s.ConsumeRecoveryCode(ctx, sub, "n1"))

	require.NoError(t, h.s.ReplaceRecoveryCodes(ctx, sub, []string{"z"}))
	require.NoError(t, h.s.DeleteRecoveryCodes(ctx, sub))
	require.NoError(t, h.s.DeleteRecoveryCodes(ctx, sub), "idempotent")
	require.ErrorIs(t, h.s.ConsumeRecoveryCode(ctx, sub, "z"), store.ErrNotFound)
	require.True(t, h.get(t, sub).Confirmed(), "deleting codes keeps the enrollment")
}

func recoveryConsumeRace(t *testing.T, h *harness) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	require.NoError(t, h.s.ReplaceRecoveryCodes(ctx, sub, []string{"once"}))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			if h.s.ConsumeRecoveryCode(ctx, sub, "once") == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, wins.Load())
}

func populate(t *testing.T, h *harness, sub principal.Subject) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, h.s.ConfirmEnrollment(ctx, confirmed(sub, "x"), []string{"c1"}))
	h.inc(t, lockout(sub, base, 5, time.Hour))
	h.incRecovery(t, lockout(sub, base, 5, time.Hour))
}

func deleteForSubject(t *testing.T, h *harness) {
	ctx := context.Background()
	gone, kept := subjectIn(t, "tenant-a"), subjectIn(t, "tenant-a")
	populate(t, h, gone)
	populate(t, h, kept)
	require.NoError(t, h.s.DeleteForSubject(ctx, gone))
	require.NoError(t, h.s.DeleteForSubject(ctx, gone), "idempotent")
	_, err := h.s.GetTOTP(ctx, gone)
	require.ErrorIs(t, err, store.ErrNotFound)
	require.ErrorIs(t, h.s.ConsumeRecoveryCode(ctx, gone, "c1"), store.ErrNotFound)
	require.Equal(t, 1, h.incRecovery(t, lockout(gone, base, 5, time.Hour)), "the recovery counter went with it")
	require.True(t, h.get(t, kept).Confirmed())
	require.Equal(t, 2, h.inc(t, lockout(kept, base, 5, time.Hour)), "other subjects keep their counters")
	require.NoError(t, h.s.ConsumeRecoveryCode(ctx, kept, "c1"))
}

func eraseTenant(t *testing.T, h *harness) {
	ctx := context.Background()
	a, b := subjectIn(t, "tenant-a"), subjectIn(t, "tenant-b")
	populate(t, h, a)
	populate(t, h, b)
	require.NoError(t, h.s.EraseTenant(ctx, a.Tenant))
	_, err := h.s.GetTOTP(ctx, a)
	require.ErrorIs(t, err, store.ErrNotFound)
	require.ErrorIs(t, h.s.ConsumeRecoveryCode(ctx, a, "c1"), store.ErrNotFound)
	require.Equal(t, 1, h.incRecovery(t, lockout(a, base, 5, time.Hour)))
	require.True(t, h.get(t, b).Confirmed())
	require.NoError(t, h.s.ConsumeRecoveryCode(ctx, b, "c1"))
	_, n := h.enrolled(t)
	require.EqualValues(t, 1, n, "only the erased tenant's subject left the count")
}

func singleTenant(t *testing.T, h *harness) {
	ctx := context.Background()
	single := principal.Subject{User: uuid.New()}
	tenanted := principal.Subject{Tenant: tenant(t, "tenant-a"), User: single.User}
	populate(t, h, single)
	populate(t, h, tenanted)
	ok, err := h.s.HasConfirmedTOTP(ctx, single)
	require.NoError(t, err)
	require.True(t, ok)
	for _, sub := range []principal.Subject{single, tenanted} {
		ok, err := h.s.MarkTOTPUsed(ctx, sub, 10)
		require.NoError(t, err)
		require.True(t, ok, "the replay guard is per subject, the single tenant included")
	}
	_, n := h.enrolled(t)
	require.EqualValues(t, 2, n, "the same user in the single tenant and in a tenant is two subjects")

	require.NoError(t, h.s.EraseTenant(ctx, principal.TenantID{}))
	_, err = h.s.GetTOTP(ctx, single)
	require.ErrorIs(t, err, store.ErrNotFound)
	require.ErrorIs(t, h.s.ConsumeRecoveryCode(ctx, single, "c1"), store.ErrNotFound)
	require.True(t, h.get(t, tenanted).Confirmed(), "erasing the single tenant leaves the others")
	require.NoError(t, h.s.ConsumeRecoveryCode(ctx, tenanted, "c1"))
}

func newKEK(t *testing.T) *kek.Local {
	t.Helper()
	key := make([]byte, kek.KeyLength)
	_, err := rand.Read(key)
	require.NoError(t, err)
	k, err := kek.NewLocal(key)
	require.NoError(t, err)
	return k
}

func sealedOpaque(t *testing.T, h *harness) {
	ctx := context.Background()
	k := newKEK(t)
	sub := subjectIn(t, "tenant-a")
	ref, err := sealing.TOTPSecret(sub)
	require.NoError(t, err)
	plain := []byte("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	ct, err := sealing.Seal(ctx, k, ref, plain)
	require.NoError(t, err)
	require.NoError(t, h.s.SaveTOTP(ctx, mfa.Enrollment{Subject: sub, Sealed: ct, AADVersion: mfa.AADVersionCurrent, CreatedAt: base}))

	got := h.get(t, sub)
	require.Equal(t, ct, got.Sealed, "the store returns exactly the opaque bytes it was given")
	require.False(t, bytes.Contains(got.Sealed, plain), "the ciphertext is never the plaintext")
	opened, err := sealing.Open(ctx, k, ref, got.Sealed)
	require.NoError(t, err)
	require.Equal(t, plain, opened.Plaintext)
	require.False(t, opened.Stale)

	require.True(t, bytes.Contains(ref.AAD(), []byte(sub.Tenant.String())), "the associated data names the tenant")
	require.True(t, bytes.Contains(ref.AAD(), []byte(sub.User.String())), "and the user")
	single, err := sealing.TOTPSecret(principal.Subject{User: sub.User})
	require.NoError(t, err)
	_, err = sealing.Open(ctx, k, single, got.Sealed)
	require.Error(t, err, "the single tenant's associated data fails")
	elsewhere, err := sealing.TOTPSecret(principal.Subject{Tenant: tenant(t, "tenant-b"), User: sub.User})
	require.NoError(t, err)
	_, err = sealing.Open(ctx, k, elsewhere, got.Sealed)
	require.Error(t, err, "another tenant's associated data fails")
	otherUser, err := sealing.TOTPSecret(principal.Subject{Tenant: sub.Tenant, User: uuid.New()})
	require.NoError(t, err)
	_, err = sealing.Open(ctx, k, otherUser, got.Sealed)
	require.Error(t, err, "another user's associated data fails")
}

type legacyFixtures struct {
	Key   string
	Cases []struct{ Name, AAD, Plaintext, Blob string }
}

func loadLegacy(t *testing.T) (kek.LegacyOpener, map[string][2][]byte) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "kek", "testdata", "v016_fixtures.json"))
	require.NoError(t, err)
	var f legacyFixtures
	require.NoError(t, json.Unmarshal(raw, &f))
	key, err := hex.DecodeString(f.Key)
	require.NoError(t, err)
	opener, err := kek.LegacyLocalV016(key)
	require.NoError(t, err)
	out := map[string][2][]byte{}
	for _, c := range f.Cases {
		blob, err := hex.DecodeString(c.Blob)
		require.NoError(t, err)
		pt, err := hex.DecodeString(c.Plaintext)
		require.NoError(t, err)
		out[c.Name] = [2][]byte{blob, pt}
	}
	return opener, out
}

type legacyRow struct {
	sub       principal.Subject
	blob      []byte
	plaintext []byte
}

func seedLegacy(t *testing.T, h *harness) []legacyRow {
	t.Helper()
	_, cases := loadLegacy(t)
	fixtureUser := uuid.MustParse("6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5")
	rows := []legacyRow{
		{sub: principal.Subject{Tenant: tenant(t, "tenant-a"), User: fixtureUser}, blob: cases["mfa_totp tenant:user"][0], plaintext: cases["mfa_totp tenant:user"][1]},
		{sub: subjectIn(t, "tenant-z"), blob: cases["no aad"][0], plaintext: cases["no aad"][1]},
		{sub: principal.Subject{User: uuid.New()}, blob: cases["no aad"][0], plaintext: cases["no aad"][1]},
		{sub: subjectIn(t, "tenant-a"), blob: bytes.Repeat([]byte{7}, 64)},
	}
	for _, r := range rows {
		h.f.SeedV016(t, h.s, r.sub, r.blob)
	}
	return rows
}

func legacyUpgrade(t *testing.T, h *harness) {
	ctx := context.Background()
	legacy, _ := loadLegacy(t)
	rows := seedLegacy(t, h)
	fresh := subjectIn(t, "tenant-a")
	require.NoError(t, h.s.SaveTOTP(ctx, enrollment(fresh, "fresh")))

	n, err := h.s.CountLegacySealed(ctx)
	require.NoError(t, err)
	require.EqualValues(t, len(rows), n, "only aad_version 0 rows are legacy")

	var listed []mfa.V016Row
	cur := store.Cursor{}
	for {
		page, next, err := h.s.V016Sealed(ctx, cur, 2)
		require.NoError(t, err)
		if len(page) == 0 {
			require.Equal(t, cur, next, "an empty page keeps the cursor")
			break
		}
		require.LessOrEqual(t, len(page), 2)
		require.True(t, next.After(cur), "the cursor is monotonic")
		listed = append(listed, page...)
		cur = next
	}
	require.Len(t, listed, len(rows), "every legacy row is listed exactly once")
	_, _, err = h.s.V016Sealed(ctx, store.Cursor{}, 0)
	require.Error(t, err)

	byUser := map[principal.Subject]mfa.V016Row{}
	for _, r := range listed {
		byUser[r.Ref.Subject] = r
	}
	require.NotContains(t, byUser, fresh)

	k := newKEK(t)
	reported := 0
	for _, want := range rows {
		got, ok := byUser[want.sub]
		require.True(t, ok)
		require.Equal(t, want.blob, got.Sealed)
		ref, err := sealing.TOTPSecret(want.sub)
		require.NoError(t, err)
		pt, err := sealing.OpenLegacy(ctx, legacy, ref, got.Sealed)
		if want.plaintext == nil {
			require.ErrorIs(t, err, sealing.ErrLegacyUnopenable, "a row that opens under no candidate is reported, not skipped")
			reported++
			continue
		}
		require.NoError(t, err)
		require.Equal(t, want.plaintext, pt)
		ct, err := sealing.Seal(ctx, k, ref, pt)
		require.NoError(t, err)
		ok, err = h.s.ReplaceSealed(ctx, mfa.Reseal{Ref: got.Ref, Old: got.Sealed, New: ct})
		require.NoError(t, err)
		require.True(t, ok)
		now := h.get(t, want.sub)
		require.Equal(t, mfa.AADVersionCurrent, now.AADVersion)
		opened, err := sealing.Open(ctx, k, ref, now.Sealed)
		require.NoError(t, err)
		require.Equal(t, want.plaintext, opened.Plaintext, "the converted secret opens under the v0.17 AAD")
		require.False(t, bytes.Contains(now.Sealed, want.plaintext), "the converted ciphertext is never the plaintext")
		moved, err := sealing.TOTPSecret(principal.Subject{Tenant: tenant(t, "tenant-moved"), User: want.sub.User})
		require.NoError(t, err)
		_, err = sealing.Open(ctx, k, moved, now.Sealed)
		require.Error(t, err, "the converted secret is bound to its tenant")
	}
	require.Equal(t, 1, reported)
	n, err = h.s.CountLegacySealed(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "only the unopenable row remains")
}

func replaceSealedCAS(t *testing.T, h *harness) {
	ctx := context.Background()
	rows := seedLegacy(t, h)
	sub := rows[0].sub
	ref := mfa.SealedRef{Subject: sub}
	h.inc(t, lockout(sub, base, 5, time.Hour))
	h.inc(t, lockout(sub, base.Add(time.Second), 5, time.Hour))
	ok, err := h.s.MarkTOTPUsed(ctx, sub, 900)
	require.NoError(t, err)
	require.True(t, ok)
	h.inc(t, lockout(sub, base.Add(time.Minute), 5, time.Hour))
	before := h.get(t, sub)

	ok, err = h.s.ReplaceSealed(ctx, mfa.Reseal{Ref: ref, Old: []byte("not what was read"), New: []byte("n1")})
	require.NoError(t, err)
	require.False(t, ok, "a secret that is not the one read is never overwritten")
	require.Equal(t, before, h.get(t, sub))

	ok, err = h.s.ReplaceSealed(ctx, mfa.Reseal{Ref: ref, Old: rows[0].blob, New: []byte("n1")})
	require.NoError(t, err)
	require.True(t, ok)
	after := h.get(t, sub)
	require.Equal(t, []byte("n1"), after.Sealed)
	require.Equal(t, mfa.AADVersionCurrent, after.AADVersion)
	require.EqualValues(t, 900, after.LastUsedStep, "a re-seal never rolls the replay guard back")
	require.Equal(t, 1, after.FailedAttempts, "nor the counters")
	require.True(t, before.LastAttemptAt.Equal(after.LastAttemptAt))
	require.True(t, before.CreatedAt.Equal(after.CreatedAt))
	require.Nil(t, after.ConfirmedAt)

	ok, err = h.s.ReplaceSealed(ctx, mfa.Reseal{Ref: ref, Old: rows[0].blob, New: []byte("n2")})
	require.NoError(t, err)
	require.False(t, ok, "a second upgrader of the same row loses")
	require.Equal(t, []byte("n1"), h.get(t, sub).Sealed)

	ok, err = h.s.ReplaceSealed(ctx, mfa.Reseal{Ref: ref, Old: []byte("n1"), New: []byte("n3")})
	require.NoError(t, err)
	require.True(t, ok, "the lazy re-seal after a KEK rotation uses the same CAS")
	require.Equal(t, mfa.AADVersionCurrent, h.get(t, sub).AADVersion)

	ok, err = h.s.ReplaceSealed(ctx, mfa.Reseal{Ref: mfa.SealedRef{Subject: subjectIn(t, "tenant-a")}, Old: []byte("a"), New: []byte("b")})
	require.NoError(t, err)
	require.False(t, ok)
	for name, r := range map[string]mfa.Reseal{
		"zero subject": {Ref: mfa.SealedRef{}, Old: []byte("a"), New: []byte("b")},
		"empty old":    {Ref: ref, New: []byte("b")},
		"empty new":    {Ref: ref, Old: []byte("n3")},
	} {
		_, err := h.s.ReplaceSealed(ctx, r)
		require.Error(t, err, name)
	}
	require.Equal(t, []byte("n3"), h.get(t, sub).Sealed)

	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Go(func() {
			ok, err := h.s.ReplaceSealed(ctx, mfa.Reseal{Ref: ref, Old: []byte("n3"), New: []byte{byte('A' + i)}})
			if err == nil && ok {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, wins.Load(), "concurrent upgraders: exactly one CAS wins")
}
