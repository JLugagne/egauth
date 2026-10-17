package mfasvc_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/mfasvc"
	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/store/mfa"
)

func TestParseFactorRequiresAnExplicitSecondFactor(t *testing.T) {
	cases := map[string]core.Factor{"totp": core.FactorTOTP, "recovery_code": core.FactorRecoveryCode}
	for in, want := range cases {
		got, err := mfasvc.ParseFactor(in)
		if err != nil || got != want {
			t.Fatalf("ParseFactor(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "otp", "TOTP", "rc", "pwd", "pk_stepup", "totp "} {
		if _, err := mfasvc.ParseFactor(in); !errors.Is(err, mfasvc.ErrInvalidFactor) {
			t.Fatalf("ParseFactor(%q) err = %v; want ErrInvalidFactor", in, err)
		}
	}
}

func TestVerifyRefusesFactorsItDoesNotOwn(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	w.enrolled(sub)
	for _, f := range []core.Factor{{}, core.FactorPassword, core.FactorEmailCode, core.FactorPasskeyStepUp} {
		if _, err := w.svc.Verify(context.Background(), sub, f, "123456"); !errors.Is(err, mfasvc.ErrInvalidFactor) {
			t.Fatalf("Verify(%q) err = %v; want ErrInvalidFactor", f.Code(), err)
		}
	}
}

func TestVerifyTOTPYieldsTheTOTPFactorAndLeavesMFAVerifiedToTheCaller(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	secret, _ := w.enrolled(sub)
	v, err := w.svc.Verify(context.Background(), sub, core.FactorTOTP, totpAt(t, secret, w.clock.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if v.Subject() != sub || len(v.Factors()) != 1 || v.Factors()[0] != core.FactorTOTP || v.Identifies() {
		t.Fatalf("verified = %v %v identifies=%v", v.Subject(), v.Factors(), v.Identifies())
	}
	if e, ok := w.sink.last(event.MFAVerified); ok {
		t.Fatalf("Verify emitted MFAVerified before the flow completed: %+v", e)
	}
}

func TestWrongTOTPNeverSpendsTheRecoveryBudget(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := w.user("ann@example.com")
	secret, codes := w.enrolled(sub)
	wrong := wrongCode(totpAt(t, secret, w.clock.Now()))
	for range mfasvc.MaxAttempts * 3 {
		if _, err := w.svc.Verify(ctx, sub, core.FactorTOTP, wrong); err == nil {
			t.Fatal("a wrong TOTP verified")
		}
	}
	if _, err := w.svc.Verify(ctx, sub, core.FactorTOTP, totpAt(t, secret, w.clock.Now())); !errors.Is(err, mfasvc.ErrTooManyAttempts) {
		t.Fatalf("locked TOTP err = %v; want ErrTooManyAttempts", err)
	}
	v, err := w.svc.Verify(ctx, sub, core.FactorRecoveryCode, codes[0])
	if err != nil {
		t.Fatalf("recovery code after a TOTP lockout: %v (I-22)", err)
	}
	if v.Factors()[0] != core.FactorRecoveryCode {
		t.Fatalf("factor = %v", v.Factors())
	}
}

func TestWrongRecoveryCodesNeverSpendTheTOTPBudget(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := w.user("ann@example.com")
	secret, codes := w.enrolled(sub)
	for range mfasvc.MaxAttempts * 2 {
		if _, err := w.svc.Verify(ctx, sub, core.FactorRecoveryCode, "AAAA-BBBB-CCCC-DDDD"); err == nil {
			t.Fatal("a wrong recovery code verified")
		}
	}
	if _, err := w.svc.Verify(ctx, sub, core.FactorRecoveryCode, codes[0]); !errors.Is(err, mfasvc.ErrTooManyAttempts) {
		t.Fatalf("locked recovery err = %v; want ErrTooManyAttempts", err)
	}
	if _, err := w.svc.Verify(ctx, sub, core.FactorTOTP, totpAt(t, secret, w.clock.Now())); err != nil {
		t.Fatalf("TOTP after a recovery lockout: %v", err)
	}
}

func TestTOTPLockoutIsPerSubjectAndDecays(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := w.user("ann@example.com")
	other := w.user("bob@example.com")
	secret, _ := w.enrolled(sub)
	otherSecret, _ := w.enrolled(other)
	wrong := wrongCode(totpAt(t, secret, w.clock.Now()))
	for i := range mfasvc.MaxAttempts {
		if _, err := w.svc.Verify(ctx, sub, core.FactorTOTP, wrong); !errors.Is(err, mfasvc.ErrInvalidCode) {
			t.Fatalf("attempt %d err = %v; want ErrInvalidCode", i, err)
		}
	}
	if _, err := w.svc.Verify(ctx, sub, core.FactorTOTP, totpAt(t, secret, w.clock.Now())); !errors.Is(err, mfasvc.ErrTooManyAttempts) {
		t.Fatalf("right code while locked err = %v; want ErrTooManyAttempts", err)
	}
	if _, err := w.svc.Verify(ctx, other, core.FactorTOTP, totpAt(t, otherSecret, w.clock.Now())); err != nil {
		t.Fatalf("another subject is locked too: %v", err)
	}
	w.clock.Advance(mfasvc.LockoutDuration + time.Minute)
	if _, err := w.svc.Verify(ctx, sub, core.FactorTOTP, totpAt(t, secret, w.clock.Now())); err != nil {
		t.Fatalf("after decay: %v", err)
	}
}

func TestConcurrentGuessesNeverExceedTheLockout(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := w.user("ann@example.com")
	secret, _ := w.enrolled(sub)
	wrong := wrongCode(totpAt(t, secret, w.clock.Now()))
	var compared atomic.Int64
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			_, err := w.svc.Verify(ctx, sub, core.FactorTOTP, wrong)
			if !errors.Is(err, mfasvc.ErrTooManyAttempts) {
				compared.Add(1)
			}
		})
	}
	wg.Wait()
	if n := compared.Load(); n != mfasvc.MaxAttempts {
		t.Fatalf("%d concurrent guesses were compared; the bound is %d (C-40)", n, mfasvc.MaxAttempts)
	}
	if _, err := w.svc.Verify(ctx, sub, core.FactorTOTP, totpAt(t, secret, w.clock.Now())); !errors.Is(err, mfasvc.ErrTooManyAttempts) {
		t.Fatalf("right code after the concurrent burst err = %v; want ErrTooManyAttempts", err)
	}
}

func TestTOTPStepIsSingleUse(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := w.user("ann@example.com")
	secret, _ := w.enrolled(sub)
	code := totpAt(t, secret, w.clock.Now())
	if _, err := w.svc.Verify(ctx, sub, core.FactorTOTP, code); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Verify(ctx, sub, core.FactorTOTP, code); !errors.Is(err, mfasvc.ErrInvalidCode) {
		t.Fatalf("replayed code err = %v; want ErrInvalidCode", err)
	}
	if _, err := w.svc.Verify(ctx, sub, core.FactorTOTP, totpAt(t, secret, w.clock.Now().Add(-30*time.Second))); !errors.Is(err, mfasvc.ErrInvalidCode) {
		t.Fatalf("an older step after a newer one err = %v; want ErrInvalidCode", err)
	}
	w.clock.Advance(30 * time.Second)
	code = totpAt(t, secret, w.clock.Now())
	var ok atomic.Int64
	var wg sync.WaitGroup
	for range mfasvc.MaxAttempts - 2 {
		wg.Go(func() {
			if _, err := w.svc.Verify(ctx, sub, core.FactorTOTP, code); err == nil {
				ok.Add(1)
			}
		})
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d concurrent verifications of one code succeeded; want exactly 1", ok.Load())
	}
}

func TestRecoveryCodeIsSingleUse(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := w.user("ann@example.com")
	_, codes := w.enrolled(sub)
	if _, err := w.svc.Verify(ctx, sub, core.FactorRecoveryCode, strings.ToLower(strings.ReplaceAll(codes[1], "-", " "))); err != nil {
		t.Fatalf("a recovery code typed without dashes: %v", err)
	}
	if _, err := w.svc.Verify(ctx, sub, core.FactorRecoveryCode, codes[1]); !errors.Is(err, mfasvc.ErrInvalidCode) {
		t.Fatalf("reused recovery code err = %v; want ErrInvalidCode", err)
	}
}

func TestUnconfirmedTOTPNeverVerifies(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	b := w.enroll(w.session(sub))
	if _, err := w.svc.Verify(context.Background(), sub, core.FactorTOTP, totpAt(t, b.Secret, w.clock.Now())); !errors.Is(err, mfasvc.ErrInvalidCode) {
		t.Fatalf("unconfirmed TOTP err = %v; want ErrInvalidCode", err)
	}
}

func TestRecoveryCodesNeedAnotherSecondFactor(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := w.user("ann@example.com")
	_, codes := w.enrolled(sub)
	if err := w.mfa.DeleteTOTP(ctx, sub); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Verify(ctx, sub, core.FactorRecoveryCode, codes[0]); !errors.Is(err, mfasvc.ErrInvalidCode) {
		t.Fatalf("orphan recovery code err = %v; want ErrInvalidCode (D1)", err)
	}
	w.addPasskey(sub)
	if _, err := w.svc.Verify(ctx, sub, core.FactorRecoveryCode, codes[0]); err != nil {
		t.Fatalf("recovery code with an active passkey: %v", err)
	}
}

func TestVerifyFailsClosedOnStoreErrors(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	secret, codes := w.enrolled(sub)
	w.mfa = failingMFA{Store: w.mfa}
	w.build()
	if _, err := w.svc.Verify(context.Background(), sub, core.FactorTOTP, totpAt(t, secret, w.clock.Now())); !errors.Is(err, httpx.ErrServiceUnavailable) {
		t.Fatalf("TOTP err = %v; want ErrServiceUnavailable", err)
	}
	if _, err := w.svc.Verify(context.Background(), sub, core.FactorRecoveryCode, codes[0]); !errors.Is(err, httpx.ErrServiceUnavailable) {
		t.Fatalf("recovery err = %v; want ErrServiceUnavailable", err)
	}
}

func TestTOTPSecretIsSealedForItsSubject(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := w.user("ann@example.com")
	other := w.user("bob@example.com")
	b := w.enroll(w.session(sub))
	e, err := w.mfa.GetTOTP(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if e.AADVersion != mfa.AADVersionCurrent || strings.Contains(string(e.Sealed), b.Secret) {
		t.Fatalf("stored secret is not sealed: version %d", e.AADVersion)
	}
	ref, _ := sealing.TOTPSecret(sub)
	if o, err := sealing.Open(ctx, w.kek, ref, e.Sealed); err != nil || string(o.Plaintext) != b.Secret {
		t.Fatalf("open with the subject's AAD: %v", err)
	}
	wrongRef, _ := sealing.TOTPSecret(other)
	if _, err := sealing.Open(ctx, w.kek, wrongRef, e.Sealed); err == nil {
		t.Fatal("the secret opens under another subject's AAD")
	}
}

type failingMFA struct{ mfa.Store }

var errDown = errors.New("store down")

func (failingMFA) IncrementTOTPAttempts(context.Context, mfa.Lockout) (int, error) { return 0, errDown }

func (failingMFA) IncrementRecoveryAttempts(context.Context, mfa.Lockout) (int, error) {
	return 0, errDown
}
