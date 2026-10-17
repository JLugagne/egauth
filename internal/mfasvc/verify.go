package mfasvc

import (
	"context"
	"errors"
	"strings"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/mfa"
)

const (
	fieldTOTP         = "totp"
	fieldRecoveryCode = "recovery_code"
)

// ParseFactor reads the explicit factor field of a second-factor request: "totp" or
// "recovery_code", exactly. Anything else, an empty value included, returns ErrInvalidFactor, so a
// TOTP failure can never fall back to a recovery code (I-22).
func ParseFactor(field string) (core.Factor, error) {
	switch field {
	case fieldTOTP:
		return core.FactorTOTP, nil
	case fieldRecoveryCode:
		return core.FactorRecoveryCode, nil
	}
	return core.Factor{}, ErrInvalidFactor
}

// Verify is the only TOTP and recovery-code check (G6). f selects the factor explicitly and only
// that factor's budget is charged: core.FactorTOTP checks a code of the subject's confirmed TOTP,
// core.FactorRecoveryCode consumes one recovery code while a confirmed TOTP or an active passkey
// exists (D1). One attempt is reserved in the per-subject lockout before any comparison, so
// concurrent guesses never exceed MaxAttempts per LockoutDuration; a TOTP step is accepted once and
// never below the last accepted one. A malformed code is refused without being charged.
//
// It returns the Verified of f, ErrInvalidFactor for any other factor, ErrInvalidCode for a wrong,
// replayed, unconfirmed or missing code, ErrTooManyAttempts while locked, and an error joined with
// httpx.ErrServiceUnavailable when a store or the KEK fails: it never verifies on an error. It
// emits no MFAVerified: the caller does once the flow it completes has issued (DESIGN 5.1).
func (s *Service) Verify(ctx context.Context, sub core.Subject, f core.Factor, code string) (core.Verified, error) {
	if sub.IsZero() {
		return core.Verified{}, ErrInvalidCode
	}
	var err error
	switch f {
	case core.FactorTOTP:
		_, _, err = s.verifyTOTP(ctx, sub, code, true)
	case core.FactorRecoveryCode:
		err = s.verifyRecovery(ctx, sub, code)
	default:
		return core.Verified{}, ErrInvalidFactor
	}
	if err != nil {
		s.failed(ctx, sub, f, err)
		return core.Verified{}, err
	}
	var v core.Verified
	if f == core.FactorTOTP {
		v, err = factors.TOTP(sub, s.clock.Now())
	} else {
		v, err = factors.RecoveryCode(sub, s.clock.Now())
	}
	if err != nil {
		return core.Verified{}, err
	}
	return v, nil
}

func (s *Service) failed(ctx context.Context, sub core.Subject, f core.Factor, err error) {
	reason := ErrInvalidCode.Code()
	switch {
	case errors.Is(err, ErrTooManyAttempts):
		reason = ErrTooManyAttempts.Code()
	case !errors.Is(err, ErrInvalidCode):
		return
	}
	_ = s.audit.Emit(ctx, event.MFAVerificationFailed, scopeOf(sub), audit.Detail{Reason: reason}, nil, audit.A(event.KeyFactor, f.Code()))
}

func (s *Service) lockout(sub core.Subject) mfa.Lockout {
	return mfa.Lockout{Subject: sub, Now: s.clock.Now(), Max: MaxAttempts, Duration: LockoutDuration}
}

func (s *Service) verifyTOTP(ctx context.Context, sub core.Subject, code string, confirmed bool) (mfa.Enrollment, int64, error) {
	code = strings.TrimSpace(code)
	if !wellFormedTOTP(code) {
		return mfa.Enrollment{}, 0, ErrInvalidCode
	}
	e, err := s.mfa.GetTOTP(ctx, sub)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return mfa.Enrollment{}, 0, ErrInvalidCode
	case err != nil:
		return mfa.Enrollment{}, 0, unavailable(err)
	case e.Confirmed() != confirmed:
		return mfa.Enrollment{}, 0, ErrInvalidCode
	}
	n, err := s.mfa.IncrementTOTPAttempts(ctx, s.lockout(sub))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return mfa.Enrollment{}, 0, ErrInvalidCode
	case err != nil:
		return mfa.Enrollment{}, 0, unavailable(err)
	case n > MaxAttempts:
		return mfa.Enrollment{}, 0, ErrTooManyAttempts
	}
	key, err := s.openSecret(ctx, sub, e.Sealed)
	if err != nil {
		return mfa.Enrollment{}, 0, unavailable(err)
	}
	step, ok := matchTOTP(key, code, s.clock.Now())
	if !ok {
		s.lockedNow(ctx, sub, n)
		return mfa.Enrollment{}, 0, ErrInvalidCode
	}
	fresh, err := s.mfa.MarkTOTPUsed(ctx, sub, step)
	if err != nil {
		return mfa.Enrollment{}, 0, unavailable(err)
	}
	if !fresh {
		s.lockedNow(ctx, sub, n)
		return mfa.Enrollment{}, 0, ErrInvalidCode
	}
	return e, step, nil
}

func (s *Service) lockedNow(ctx context.Context, sub core.Subject, n int) {
	if n != MaxAttempts {
		return
	}
	_ = s.audit.Emit(ctx, event.AccountLocked, scopeOf(sub), audit.Detail{Reason: "mfa_lockout"}, nil, audit.A(event.KeyCount, n))
}

func (s *Service) openSecret(ctx context.Context, sub core.Subject, sealed []byte) ([]byte, error) {
	ref, err := sealing.TOTPSecret(sub)
	if err != nil {
		return nil, err
	}
	o, err := sealing.Open(ctx, s.kek, ref, sealed)
	if err != nil {
		return nil, err
	}
	if o.Stale {
		s.reseal(ctx, sub, ref, sealed, o.Plaintext)
	}
	return decodeSecret(string(o.Plaintext))
}

func (s *Service) reseal(ctx context.Context, sub core.Subject, ref sealing.Ref, old, plaintext []byte) {
	fresh, err := sealing.Seal(ctx, s.kek, ref, plaintext)
	if err != nil {
		return
	}
	_, _ = s.mfa.ReplaceSealed(ctx, mfa.Reseal{Ref: mfa.SealedRef{Subject: sub}, Old: old, New: fresh})
}

func (s *Service) verifyRecovery(ctx context.Context, sub core.Subject, code string) error {
	norm := normalizeRecoveryCode(code)
	if norm == "" || len(code) > maxRecoveryInput {
		return ErrInvalidCode
	}
	has, err := s.hasSecondFactor(ctx, sub)
	if err != nil {
		return unavailable(err)
	}
	if !has {
		return ErrInvalidCode
	}
	n, err := s.mfa.IncrementRecoveryAttempts(ctx, s.lockout(sub))
	switch {
	case err != nil:
		return unavailable(err)
	case n > MaxAttempts:
		return ErrTooManyAttempts
	}
	err = s.mfa.ConsumeRecoveryCode(ctx, sub, hashRecoveryCode(norm))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.lockedNow(ctx, sub, n)
		return ErrInvalidCode
	case err != nil:
		return unavailable(err)
	}
	_ = s.mfa.ResetRecoveryAttempts(ctx, sub)
	return nil
}

func (s *Service) hasSecondFactor(ctx context.Context, sub core.Subject) (bool, error) {
	totp, err := s.mfa.HasConfirmedTOTP(ctx, sub)
	if err != nil || totp {
		return totp, err
	}
	return s.passkeys.HasActive(ctx, sub)
}
