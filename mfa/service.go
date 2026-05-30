package mfa

import (
	"context"
	"errors"
	"time"

	"github.com/JLugagne/libauth/event"
	"github.com/google/uuid"
)

// DefaultIssuer labels credentials in the authenticator app when none is configured.
const DefaultIssuer = "libauth"

// Enrollment is returned when starting TOTP enrollment: the shared secret and the otpauth URI
// to render as a QR code. Both must be shown to the user only during enrollment.
type Enrollment struct {
	Secret string
	URI    string
}

// Service orchestrates the MFA flows over a Store.
type Service interface {
	// EnrollTOTP starts (or restarts) TOTP enrollment, returning the secret and provisioning
	// URI. The enrollment is unconfirmed until ConfirmTOTP succeeds. It returns
	// ErrAlreadyEnrolled if a confirmed factor already exists (call DisableTOTP first).
	EnrollTOTP(ctx context.Context, userID uuid.UUID, account string, opts ...Option) (*Enrollment, error)
	// ConfirmTOTP verifies a code against the pending enrollment, marks it confirmed, and
	// returns a fresh set of single-use recovery codes (shown once).
	ConfirmTOTP(ctx context.Context, userID uuid.UUID, code string, opts ...Option) ([]string, error)
	// VerifyTOTP checks a login second-factor code against a confirmed enrollment, with replay
	// protection. Returns ErrInvalidCode / ErrNotEnrolled / ErrNotConfirmed.
	VerifyTOTP(ctx context.Context, userID uuid.UUID, code string, opts ...Option) error
	// VerifyRecoveryCode consumes a single-use recovery code.
	VerifyRecoveryCode(ctx context.Context, userID uuid.UUID, code string, opts ...Option) error
	// RegenerateRecoveryCodes invalidates the user's existing codes and returns a fresh set.
	RegenerateRecoveryCodes(ctx context.Context, userID uuid.UUID, opts ...Option) ([]string, error)
	// DisableTOTP removes the enrollment and all recovery codes. Idempotent. Disabling a second
	// factor is sensitive: callers SHOULD gate its route behind step-up re-authentication by
	// wrapping DisableHandler with tokens.RequireAuth(..., tokens.WithMaxAuthAge(d)) so a stale
	// or hijacked session cannot silently strip MFA.
	DisableTOTP(ctx context.Context, userID uuid.UUID, opts ...Option) error
	// IsEnrolled reports whether the user has a CONFIRMED TOTP factor.
	IsEnrolled(ctx context.Context, userID uuid.UUID, opts ...Option) (bool, error)
}

type service struct {
	store             Store
	issuer            string
	digits            int
	period            time.Duration
	skew              int
	recoveryCodeCount int
	now               func() time.Time
	events            event.Sink
}

// ServiceOption configures the MFA Service.
type ServiceOption func(*service)

// WithIssuer sets the issuer label shown in the authenticator app (default "libauth").
func WithIssuer(issuer string) ServiceOption { return func(s *service) { s.issuer = issuer } }

// WithDigits sets the number of TOTP digits (default 6).
func WithDigits(d int) ServiceOption { return func(s *service) { s.digits = d } }

// WithPeriod sets the TOTP period (default 30s).
func WithPeriod(p time.Duration) ServiceOption { return func(s *service) { s.period = p } }

// WithSkew sets the tolerated clock-drift window in periods on each side (default 1).
func WithSkew(n int) ServiceOption { return func(s *service) { s.skew = n } }

// WithRecoveryCodeCount sets how many recovery codes are minted per set (default 10).
func WithRecoveryCodeCount(n int) ServiceOption { return func(s *service) { s.recoveryCodeCount = n } }

// WithClock overrides the time source (primarily for tests).
func WithClock(now func() time.Time) ServiceOption { return func(s *service) { s.now = now } }

// WithEventSink registers a security-event sink (see the event package) that receives MFA
// enrollment, confirmation, verification-failure and disable events. Optional; without it no
// events are emitted.
func WithEventSink(sink event.Sink) ServiceOption { return func(s *service) { s.events = sink } }

// emit sends a security event to the configured sink (a no-op when none is set).
func (s *service) emit(ctx context.Context, e event.Event) { event.Emit(ctx, s.events, e) }

// tenantOf extracts the tenant from the call options for event annotation ("" when unset).
func tenantOf(opts []Option) string {
	if t := ApplyOptions(opts).TenantID; t != nil {
		return *t
	}
	return ""
}

// NewService builds an MFA Service with RFC 6238 defaults.
func NewService(store Store, opts ...ServiceOption) Service {
	s := &service{
		store:             store,
		issuer:            DefaultIssuer,
		digits:            DefaultDigits,
		period:            DefaultPeriod,
		skew:              DefaultSkew,
		recoveryCodeCount: DefaultRecoveryCodeCount,
		now:               time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *service) EnrollTOTP(ctx context.Context, userID uuid.UUID, account string, opts ...Option) (*Enrollment, error) {
	// A confirmed factor must be explicitly disabled before re-enrolling, so an attacker who
	// gains a momentary session cannot silently swap the second factor.
	existing, err := s.store.GetTOTP(ctx, userID, opts...)
	if err != nil && !errors.Is(err, ErrNotEnrolled) {
		return nil, err
	}
	if existing.Confirmed() {
		return nil, ErrAlreadyEnrolled
	}

	secret, err := GenerateSecret()
	if err != nil {
		return nil, err
	}
	enrollment := &TOTPEnrollment{
		UserID:    userID,
		Secret:    secret,
		CreatedAt: s.now(),
	}
	if err := s.store.SaveTOTP(ctx, enrollment, opts...); err != nil {
		return nil, err
	}

	s.emit(ctx, event.Event{Type: event.MFAEnrolled, UserID: userID.String(), TenantID: tenantOf(opts)})
	return &Enrollment{
		Secret: secret,
		URI:    ProvisioningURI(secret, s.issuer, account, s.digits, s.period),
	}, nil
}

func (s *service) ConfirmTOTP(ctx context.Context, userID uuid.UUID, code string, opts ...Option) ([]string, error) {
	enrollment, err := s.store.GetTOTP(ctx, userID, opts...)
	if err != nil {
		return nil, err
	}
	if enrollment.Confirmed() {
		return nil, ErrAlreadyEnrolled
	}

	step, ok := validateTOTP(enrollment.Secret, code, s.now(), s.digits, s.period, s.skew)
	if !ok {
		return nil, ErrInvalidCode
	}

	now := s.now()
	enrollment.ConfirmedAt = &now
	enrollment.LastUsedStep = step // the confirming code cannot be replayed for login
	if err := s.store.SaveTOTP(ctx, enrollment, opts...); err != nil {
		return nil, err
	}

	s.emit(ctx, event.Event{Type: event.MFAConfirmed, UserID: userID.String(), TenantID: tenantOf(opts)})
	return s.mintRecoveryCodes(ctx, userID, opts...)
}

func (s *service) VerifyTOTP(ctx context.Context, userID uuid.UUID, code string, opts ...Option) error {
	enrollment, err := s.store.GetTOTP(ctx, userID, opts...)
	if err != nil {
		return err
	}
	if !enrollment.Confirmed() {
		return ErrNotConfirmed
	}

	step, ok := validateTOTP(enrollment.Secret, code, s.now(), s.digits, s.period, s.skew)
	if !ok {
		s.emit(ctx, event.Event{Type: event.MFAVerificationFailed, UserID: userID.String(), TenantID: tenantOf(opts), Reason: "invalid_code"})
		return ErrInvalidCode
	}

	// Replay protection: only accept a step strictly newer than the last one used.
	applied, err := s.store.MarkTOTPUsed(ctx, userID, step, opts...)
	if err != nil {
		return err
	}
	if !applied {
		s.emit(ctx, event.Event{Type: event.MFAVerificationFailed, UserID: userID.String(), TenantID: tenantOf(opts), Reason: "replay"})
		return ErrInvalidCode
	}
	return nil
}

func (s *service) VerifyRecoveryCode(ctx context.Context, userID uuid.UUID, code string, opts ...Option) error {
	return s.store.ConsumeRecoveryCode(ctx, userID, HashRecoveryCode(code), opts...)
}

func (s *service) RegenerateRecoveryCodes(ctx context.Context, userID uuid.UUID, opts ...Option) ([]string, error) {
	enrollment, err := s.store.GetTOTP(ctx, userID, opts...)
	if err != nil {
		return nil, err
	}
	if !enrollment.Confirmed() {
		return nil, ErrNotConfirmed
	}
	return s.mintRecoveryCodes(ctx, userID, opts...)
}

func (s *service) DisableTOTP(ctx context.Context, userID uuid.UUID, opts ...Option) error {
	if err := s.store.DeleteRecoveryCodes(ctx, userID, opts...); err != nil {
		return err
	}
	if err := s.store.DeleteTOTP(ctx, userID, opts...); err != nil {
		return err
	}
	s.emit(ctx, event.Event{Type: event.MFADisabled, UserID: userID.String(), TenantID: tenantOf(opts)})
	return nil
}

func (s *service) IsEnrolled(ctx context.Context, userID uuid.UUID, opts ...Option) (bool, error) {
	enrollment, err := s.store.GetTOTP(ctx, userID, opts...)
	if err != nil {
		if errors.Is(err, ErrNotEnrolled) {
			return false, nil
		}
		return false, err
	}
	return enrollment.Confirmed(), nil
}

func (s *service) mintRecoveryCodes(ctx context.Context, userID uuid.UUID, opts ...Option) ([]string, error) {
	plaintext, hashes, err := generateRecoveryCodes(s.recoveryCodeCount)
	if err != nil {
		return nil, err
	}
	if err := s.store.ReplaceRecoveryCodes(ctx, userID, hashes, opts...); err != nil {
		return nil, err
	}
	return plaintext, nil
}
