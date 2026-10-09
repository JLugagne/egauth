// Package mfasvc owns the TOTP factor and the recovery codes. Verify is the only TOTP and
// recovery-code check of the library (DESIGN §5.4, I-22): the MFA flow, /reauth and the endpoints
// of this package all charge the same per-subject lockouts and the same LastUsedStep replay guard
// in mfa.Store, so restarting a flow or switching endpoints never resets the budget (C-40). The
// endpoints are /mfa/totp/enroll, /mfa/totp/confirm, /mfa/totp/disable and
// /mfa/recovery-codes/regenerate; they reach the session only through the httpx.Issuer seam.
package mfasvc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/passkey"
)

// The per-subject lockout of each second factor: MaxAttempts failures lock the factor until
// LockoutDuration has passed since the last charged attempt. The TOTP and recovery-code budgets are
// separate, so failures of one never lock the other (I-22). They are constants so that no caller
// can weaken them.
const (
	MaxAttempts     = 5
	LockoutDuration = 15 * time.Minute
)

// RecoveryCodeCount is the number of recovery codes minted by confirm and regenerate.
const RecoveryCodeCount = 10

var (
	// ErrInvalidConfig is returned by New, joined with one error per missing member.
	ErrInvalidConfig = errors.New("mfasvc: invalid service configuration")
	// ErrNilIssuer is returned by Endpoints for a nil issuer.
	ErrNilIssuer = errors.New("mfasvc: nil issuer")
)

// The problems the MFA endpoints and Verify answer besides those of httpx.
var (
	ErrInvalidFactor       = httpx.NewProblem(http.StatusBadRequest, "invalid_factor")
	ErrInvalidCode         = httpx.NewProblem(http.StatusUnauthorized, "invalid_code")
	ErrTooManyAttempts     = httpx.NewProblem(http.StatusTooManyRequests, "too_many_attempts")
	ErrAlreadyEnrolled     = httpx.NewProblem(http.StatusConflict, "totp_already_enrolled")
	ErrNoPendingEnrollment = httpx.NewProblem(http.StatusConflict, "totp_not_pending")
	ErrNotEnrolled         = httpx.NewProblem(http.StatusConflict, "totp_not_enrolled")
	ErrNoSecondFactor      = httpx.NewProblem(http.StatusConflict, "no_second_factor")
)

// Mutator is the shared mutation path of identitysvc.Service: Apply bumps the security epoch and
// writes the lifecycle outbox in one transaction, then dispatches it.
type Mutator interface {
	Apply(ctx context.Context, m identity.Mutation) (identity.Applied, error)
}

// Config is what New needs. Every member is required except Clock, whose zero value reads the wall
// clock.
type Config struct {
	MFA      mfa.Store
	Passkeys passkey.Store
	// Identity is read for the account label of the provisioning URI.
	Identity  identity.Store
	Mutations Mutator
	// KEK seals the TOTP secrets through internal/sealing.
	KEK kek.KEK
	// TOTPIssuer names the deployment in authenticator apps (Modules.MFA.TOTPIssuer).
	TOTPIssuer string
	Clock      clock.Clock
	Audit      httpx.Audit
}

func (c Config) String() string {
	return "mfasvc.Config{TOTPIssuer: " + strconv.Quote(c.TOTPIssuer) + ", KEK: REDACTED}"
}

func (c Config) GoString() string { return c.String() }

func (c Config) LogValue() slog.Value {
	return slog.GroupValue(slog.String("totp_issuer", c.TOTPIssuer), slog.String("kek", "REDACTED"))
}

// Service is the MFA service. It is immutable and safe for concurrent use.
type Service struct {
	mfa        mfa.Store
	passkeys   passkey.Store
	identity   identity.Store
	mutations  Mutator
	kek        kek.KEK
	totpIssuer string
	clock      clock.Clock
	audit      httpx.Audit
}

// New validates cfg and reports every missing member at once as ErrInvalidConfig joined with the
// member names; a typed nil counts as missing.
func New(cfg Config) (*Service, error) {
	var errs []error
	need := func(ok bool, name string) {
		if !ok {
			errs = append(errs, errors.New(name))
		}
	}
	need(present(cfg.MFA), "MFA")
	need(present(cfg.Passkeys), "Passkeys")
	need(present(cfg.Identity), "Identity")
	need(present(cfg.Mutations), "Mutations")
	need(present(cfg.KEK), "KEK")
	need(strings.TrimSpace(cfg.TOTPIssuer) != "", "TOTPIssuer")
	need(present(cfg.Audit), "Audit")
	if len(errs) > 0 {
		return nil, errors.Join(ErrInvalidConfig, errors.Join(errs...))
	}
	return &Service{
		mfa:        cfg.MFA,
		passkeys:   cfg.Passkeys,
		identity:   cfg.Identity,
		mutations:  cfg.Mutations,
		kek:        cfg.KEK,
		totpIssuer: cfg.TOTPIssuer,
		clock:      cfg.Clock,
		audit:      cfg.Audit,
	}, nil
}

func present(v any) bool {
	if v == nil {
		return false
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return !rv.IsNil()
	}
	return true
}

// Endpoints returns the MFA management endpoints served by s through issuer. It returns
// ErrNilIssuer or the error of routes.NewEndpoint. Every endpoint is Sensitive, so it runs only for
// an established, fresh session that is multi-factor when the subject is enrolled.
//
// Their guarantees:
//   - /mfa/totp/enroll stores a new unconfirmed secret, sealed for the subject, and answers it with
//     its otpauth URI. A confirmed TOTP is refused with 409: it must be disabled first. The lockout
//     counters of an unconfirmed enrollment survive a re-enroll.
//   - /mfa/totp/confirm verifies a code of the unconfirmed secret through the shared lockout, then
//     bumps the epoch (FactorTOTPEnrolled) before confirming, so a crash in between only ends
//     sessions (§7.1). It stores fresh recovery codes, then reissues the session through the seam
//     with the factor added and secondAt unchanged (C-45). The codes are answered even when the
//     reissue fails, with session_ended set.
//   - /mfa/totp/disable requires an explicit factor and a valid code through Verify, bumps the epoch
//     (FactorTOTPRemoved), removes the TOTP and, unless an active passkey remains, every recovery
//     code (D1). Every session of the subject ends, the current one included.
//   - /mfa/recovery-codes/regenerate requires a confirmed TOTP or an active passkey, bumps the epoch
//     (FactorRecoveryCodesRegenerated) and replaces every code. Every session of the subject ends.
func (s *Service) Endpoints(issuer httpx.Issuer) ([]routes.Endpoint, error) {
	if issuer == nil {
		return nil, ErrNilIssuer
	}
	h := &handlers{Service: s, issuer: issuer}
	fns := []struct {
		path string
		f    httpx.EndpointFunc
	}{
		{routes.MFATOTPEnroll, h.enroll},
		{routes.MFATOTPConfirm, h.confirm},
		{routes.MFATOTPDisable, h.disable},
		{routes.MFARecoveryCodesRegenerate, h.regenerate},
	}
	out := make([]routes.Endpoint, 0, len(fns))
	for _, e := range fns {
		ep, err := routes.NewEndpoint(e.path, e.f)
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, nil
}

type handlers struct {
	*Service
	issuer httpx.Issuer
}

func scopeOf(sub core.Subject) audit.Scope {
	return audit.Scope{TenantID: sub.Tenant.String(), UserID: sub.User.String()}
}

func unavailable(err error) error {
	return errors.Join(httpx.ErrServiceUnavailable, err)
}
