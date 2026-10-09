package issuance

import (
	"context"
	"errors"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
)

// TOTPEnrollment reports whether a subject has a confirmed TOTP; mfa.Store satisfies it.
type TOTPEnrollment interface {
	HasConfirmedTOTP(ctx context.Context, s core.Subject) (bool, error)
}

// PasskeyEnrollment reports whether a subject has an active (non-suspended) passkey;
// passkey.Store satisfies it.
type PasskeyEnrollment interface {
	HasActive(ctx context.Context, s core.Subject) (bool, error)
}

// Enrollment is the only producer of core.MFADecision (D1, G6). The decision is read from
// persisted enrollment, never from configuration or Modules: a subject must present a second
// factor exactly when it has a confirmed TOTP or an active passkey, so two deployments sharing
// storage cannot disagree (C-01). Recovery codes complete the requirement but never raise it. It is
// safe for concurrent use and serves admission, reauthentication, renewal (session.Authority) and
// the sensitive gate (httpx.EnrollmentReader) alike.
type Enrollment struct {
	totp     TOTPEnrollment
	passkeys PasskeyEnrollment
}

// NewEnrollment returns ErrInvalidConfig when either store is missing, a typed nil included.
func NewEnrollment(totp TOTPEnrollment, passkeys PasskeyEnrollment) (*Enrollment, error) {
	var errs []error
	if !present(totp) {
		errs = append(errs, errors.New("TOTP"))
	}
	if !present(passkeys) {
		errs = append(errs, errors.New("Passkeys"))
	}
	if len(errs) > 0 {
		return nil, errors.Join(ErrInvalidConfig, errors.Join(errs...))
	}
	return &Enrollment{totp: totp, passkeys: passkeys}, nil
}

// MFADecision returns the decision for s: totp and recovery_code for a confirmed TOTP, pk_stepup and
// recovery_code for an active passkey, nothing otherwise. A store failure returns the zero decision,
// which every transition refuses, joined with httpx.ErrUnavailable (503).
func (e *Enrollment) MFADecision(ctx context.Context, s core.Subject) (core.MFADecision, error) {
	return e.enrolled(ctx, s)
}

// MFARequired reports whether s must present a second factor. On a store failure it reports true
// with an error joined with httpx.ErrUnavailable, so a caller that ignores the error still fails
// closed.
func (e *Enrollment) MFARequired(ctx context.Context, s core.Subject) (bool, error) {
	d, err := e.enrolled(ctx, s)
	if err != nil {
		return true, err
	}
	return d.Required(), nil
}

func (e *Enrollment) enrolled(ctx context.Context, s core.Subject) (core.MFADecision, error) {
	totp, err := e.totp.HasConfirmedTOTP(ctx, s)
	if err != nil {
		return core.MFADecision{}, errors.Join(httpx.ErrUnavailable, errors.New("issuance: reading TOTP enrollment"), err)
	}
	pk, err := e.passkeys.HasActive(ctx, s)
	if err != nil {
		return core.MFADecision{}, errors.Join(httpx.ErrUnavailable, errors.New("issuance: reading passkey enrollment"), err)
	}
	var fs []core.Factor
	if totp {
		fs = append(fs, core.FactorTOTP)
	}
	if pk {
		fs = append(fs, core.FactorPasskeyStepUp)
	}
	if len(fs) > 0 {
		fs = append(fs, core.FactorRecoveryCode)
	}
	return core.NewMFADecision(fs), nil
}
