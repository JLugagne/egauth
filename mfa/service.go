package mfa

import (
	"context"
	"errors"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/google/uuid"
)

// DefaultIssuer labels credentials in the authenticator app when none is configured.
const DefaultIssuer = "egauth"

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
	EnrollTOTP(ctx context.Context, tenantID string, userID uuid.UUID, account string) (*Enrollment, error)
	// ConfirmTOTP verifies a code against the pending enrollment, marks it confirmed, and
	// returns a fresh set of single-use recovery codes (shown once).
	ConfirmTOTP(ctx context.Context, tenantID string, userID uuid.UUID, code string) ([]string, error)
	// VerifyTOTP checks a login second-factor code against a confirmed enrollment, with replay
	// protection. Returns ErrInvalidCode / ErrNotEnrolled / ErrNotConfirmed.
	VerifyTOTP(ctx context.Context, tenantID string, userID uuid.UUID, code string) error
	// VerifyRecoveryCode consumes a single-use recovery code.
	VerifyRecoveryCode(ctx context.Context, tenantID string, userID uuid.UUID, code string) error
	// RegenerateRecoveryCodes invalidates the user's existing codes and returns a fresh set.
	RegenerateRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID) ([]string, error)
	// DisableTOTP removes the enrollment and all recovery codes. Idempotent. Disabling a second
	// factor is sensitive: callers SHOULD gate its route behind step-up re-authentication by
	// wrapping DisableHandler with tokens.RequireAuth(..., tokens.WithMaxAuthAge(d)) so a stale
	// or hijacked session cannot silently strip MFA.
	DisableTOTP(ctx context.Context, tenantID string, userID uuid.UUID) error
	// IsEnrolled reports whether the user has a CONFIRMED TOTP factor.
	IsEnrolled(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error)
	// UnlockMFA is an admin escape hatch that immediately resets the failed-attempt counter
	// for the user's second factor, regardless of elapsed time. Use this when the operator
	// wants to unblock a user without waiting for the lockout window to expire and without
	// forcing a full DisableTOTP / re-enrollment cycle. Returns ErrNotEnrolled if the user
	// has no enrollment.
	UnlockMFA(ctx context.Context, tenantID string, userID uuid.UUID) error
}

type service struct {
	store             Store
	issuer            string
	digits            int
	period            time.Duration
	skew              int
	recoveryCodeCount int
	// maxAttempts is the failed-verification ceiling for the second factor. 0 disables
	// limiting entirely (set via WithNoAttemptLimit); any positive value is the active limit.
	maxAttempts int
	// attemptLimitDisabled is set ONLY by WithNoAttemptLimit. Attempt limiting can no longer be
	// disabled by arithmetic on maxAttempts (e.g. a negative WithMaxAttempts argument); this
	// flag is the one and only opt-out.
	attemptLimitDisabled bool
	// lockoutDuration is the time window after which a locked-out factor auto-resets.
	// 0 means no automatic decay — the lockout is permanent until UnlockMFA is called or the
	// factor is disabled. Defaults to DefaultLockoutDuration.
	lockoutDuration time.Duration
	// lockoutDurationSet distinguishes a deliberate WithLockoutDuration(0) (permanent lockout)
	// from an untouched field, so NewService only applies DefaultLockoutDuration when the
	// caller never called WithLockoutDuration at all.
	lockoutDurationSet bool
	now                func() time.Time
	events             event.Sink
}

// ServiceOption configures the MFA Service.
type ServiceOption func(*service)

// WithIssuer sets the issuer label shown in the authenticator app (default "egauth").
func WithIssuer(issuer string) ServiceOption { return func(s *service) { s.issuer = issuer } }

// WithDigits sets the number of TOTP digits (default 6).
func WithDigits(d int) ServiceOption { return func(s *service) { s.digits = d } }

// WithPeriod sets the TOTP period (default 30s).
func WithPeriod(p time.Duration) ServiceOption { return func(s *service) { s.period = p } }

// WithSkew sets the tolerated clock-drift window in periods on each side (default 1).
func WithSkew(n int) ServiceOption { return func(s *service) { s.skew = n } }

// WithRecoveryCodeCount sets how many recovery codes are minted per set (default 10).
func WithRecoveryCodeCount(n int) ServiceOption { return func(s *service) { s.recoveryCodeCount = n } }

// WithMaxAttempts sets how many failed second-factor verifications (TOTP or recovery code,
// combined) are tolerated before the factor is locked (default DefaultMaxAttempts). A
// non-positive value (zero OR negative) is treated as "use the default" — to turn limiting OFF
// use WithNoAttemptLimit, which makes the intent explicit and auditable.
func WithMaxAttempts(n int) ServiceOption { return func(s *service) { s.maxAttempts = n } }

// WithNoAttemptLimit DISABLES second-factor attempt limiting. This is insecure unless an
// external rate limiter fronts verification — the second factor becomes online-brute-forceable.
// Limiting is ON by default; only use this if you knowingly enforce the budget elsewhere.
func WithNoAttemptLimit() ServiceOption { return func(s *service) { s.attemptLimitDisabled = true } }

// WithLockoutDuration sets the time window after which a locked-out second factor
// automatically resets its attempt counter. The window is measured from the last failed
// attempt (TOTPEnrollment.LastAttemptAt). Once the window elapses, the next attempt is
// treated as a fresh budget. 0 disables time-based decay — the lockout is permanent until
// UnlockMFA is called or the factor is disabled. Default: DefaultLockoutDuration (15 min).
func WithLockoutDuration(d time.Duration) ServiceOption {
	return func(s *service) {
		s.lockoutDuration = d
		s.lockoutDurationSet = true
	}
}

// WithClock overrides the time source (primarily for tests).
func WithClock(now func() time.Time) ServiceOption { return func(s *service) { s.now = now } }

// WithEventSink registers a security-event sink (see the event package) that receives MFA
// enrollment, confirmation, verification-failure and disable events. Optional; without it no
// events are emitted.
func WithEventSink(sink event.Sink) ServiceOption { return func(s *service) { s.events = sink } }

// emit sends a security event to the configured sink (a no-op when none is set).
func (s *service) emit(ctx context.Context, e event.Event) { event.Emit(ctx, s.events, e) }

// NewService builds an MFA Service with RFC 6238 defaults. It panics on a nil store or on an
// option that sets a TOTP parameter to a value that cannot produce valid codes (digits outside
// the RFC 6238 range 6–8, non-positive period, negative skew, non-positive recovery-code count,
// or a nil clock) — fail fast at startup rather than minting unverifiable codes later.
func NewService(store Store, opts ...ServiceOption) Service {
	if store == nil {
		panic("mfa: NewService requires a non-nil Store")
	}
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
	switch {
	case s.digits < 6 || s.digits > 8:
		panic("mfa: digits must be between 6 and 8 (RFC 6238)")
	case s.period < time.Second:
		// timeStep divides by int64(period.Seconds()); a sub-second period truncates that
		// divisor to 0 and panics on the first Verify/Confirm/GenerateCode. Reject at
		// construction so the misconfiguration fails fast rather than at request time.
		panic("mfa: period must be at least 1 second")
	case s.skew < 0:
		panic("mfa: skew must not be negative")
	case s.recoveryCodeCount <= 0:
		panic("mfa: recovery-code count must be positive")
	case s.now == nil:
		panic("mfa: clock must not be nil")
	}
	// Attempt limiting is secure-by-default: ANY non-positive value (zero OR negative) from
	// WithMaxAttempts means "use the default ceiling", not "disable". Disabling is only
	// reachable via the explicit attemptLimitDisabled flag set by WithNoAttemptLimit, never by
	// arithmetic on maxAttempts.
	if s.maxAttempts <= 0 {
		s.maxAttempts = DefaultMaxAttempts
	}
	if s.attemptLimitDisabled {
		s.maxAttempts = 0 // the verify paths' documented "limiting disabled" sentinel
	}
	// Lockout decay is on by default: an UNTOUCHED lockoutDuration (WithLockoutDuration never
	// called) means "use the default window". A deliberate WithLockoutDuration(0) (or a
	// negative value) explicitly disables decay (permanent lockout until admin action) and
	// must survive normalization — lockoutDurationSet is what distinguishes the two cases.
	switch {
	case !s.lockoutDurationSet:
		s.lockoutDuration = DefaultLockoutDuration
	case s.lockoutDuration < 0:
		s.lockoutDuration = 0
	}
	return s
}

func (s *service) EnrollTOTP(ctx context.Context, tenantID string, userID uuid.UUID, account string) (*Enrollment, error) {
	// A confirmed factor must be explicitly disabled before re-enrolling, so an attacker who
	// gains a momentary session cannot silently swap the second factor.
	existing, err := s.store.GetTOTP(ctx, tenantID, userID)
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
	if err := s.store.SaveTOTP(ctx, tenantID, enrollment); err != nil {
		return nil, err
	}

	s.emit(ctx, event.Event{Type: event.MFAEnrolled, UserID: userID.String(), TenantID: tenantID})
	return &Enrollment{
		Secret: secret,
		URI:    ProvisioningURI(secret, s.issuer, account, s.digits, s.period),
	}, nil
}

func (s *service) ConfirmTOTP(ctx context.Context, tenantID string, userID uuid.UUID, code string) ([]string, error) {
	enrollment, err := s.store.GetTOTP(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	if enrollment.Confirmed() {
		return nil, ErrAlreadyEnrolled
	}

	// Reserve an attempt slot atomically BEFORE the constant-time compare, matching the
	// same discipline used by VerifyTOTP. This prevents unbounded online guessing of the
	// enrollment-confirmation code (audit finding TASK-076).
	n, err := s.reserveAttempt(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	if s.overLimit(n) {
		s.emitBlocked(ctx, tenantID, userID, "totp-confirm")
		return nil, ErrTooManyAttempts
	}

	step, ok := validateTOTP(enrollment.Secret, code, s.now(), s.digits, s.period, s.skew)
	if !ok {
		if s.atLimit(n) {
			// The last allowed guess was wrong: delete the pending enrollment so the
			// attacker cannot keep trying and the user must restart from EnrollTOTP.
			s.emitBlocked(ctx, tenantID, userID, "totp-confirm")
			_ = s.store.DeleteTOTP(ctx, tenantID, userID)
			return nil, ErrTooManyAttempts
		}
		return nil, ErrInvalidCode
	}

	now := s.now()
	enrollment.ConfirmedAt = &now
	enrollment.LastUsedStep = step // the confirming code cannot be replayed for login
	// Clear the attempt budget on successful confirmation (mirroring MarkTOTPUsed on a
	// successful verify): the enrollment snapshot was read before reserveAttempt incremented
	// the counter, so persisting it as-is would carry failed-confirm attempts into the user's
	// first-login budget — leaving a freshly enrolled user one wrong code away from a lockout.
	enrollment.FailedAttempts = 0
	enrollment.LastAttemptAt = time.Time{}
	if err := s.store.SaveTOTP(ctx, tenantID, enrollment); err != nil {
		return nil, err
	}

	s.emit(ctx, event.Event{Type: event.MFAConfirmed, UserID: userID.String(), TenantID: tenantID})
	return s.mintRecoveryCodes(ctx, tenantID, userID)
}

func (s *service) VerifyTOTP(ctx context.Context, tenantID string, userID uuid.UUID, code string) error {
	enrollment, err := s.store.GetTOTP(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if !enrollment.Confirmed() {
		return ErrNotConfirmed
	}

	// Reserve an attempt slot atomically BEFORE the constant-time compare. Like otp, the
	// increment hands each concurrent caller a unique, monotonically increasing count, so at
	// most maxAttempts callers ever reach validateTOTP — concurrent guesses cannot run more
	// comparisons than the limit (the gate is the atomic counter, not the stale read above).
	n, err := s.reserveAttempt(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if s.overLimit(n) {
		s.emitBlocked(ctx, tenantID, userID, "totp")
		return ErrTooManyAttempts
	}

	step, ok := validateTOTP(enrollment.Secret, code, s.now(), s.digits, s.period, s.skew)
	if !ok {
		if s.atLimit(n) {
			// The last allowed guess was wrong: the factor is now locked.
			s.emitBlocked(ctx, tenantID, userID, "totp")
			return ErrTooManyAttempts
		}
		s.emit(ctx, event.Event{Type: event.MFAVerificationFailed, UserID: userID.String(), TenantID: tenantID, Reason: "invalid_code"})
		return ErrInvalidCode
	}

	// Replay protection: only accept a step strictly newer than the last one used. A successful
	// MarkTOTPUsed also resets the failed-attempt counter (see Store), clearing the budget.
	applied, err := s.store.MarkTOTPUsed(ctx, tenantID, userID, step)
	if err != nil {
		return err
	}
	if !applied {
		// A correct-but-replayed code is still a failed verification: it consumed the slot
		// reserved above (the counter was NOT reset since MarkTOTPUsed did not apply).
		s.emit(ctx, event.Event{Type: event.MFAVerificationFailed, UserID: userID.String(), TenantID: tenantID, Reason: "replay"})
		return ErrInvalidCode
	}
	return nil
}

func (s *service) VerifyRecoveryCode(ctx context.Context, tenantID string, userID uuid.UUID, code string) error {
	// Recovery codes are an alternate proof of the SAME second factor, so they share the TOTP
	// attempt budget when an enrollment exists. Reserve a slot before the lookup/compare so a
	// locked factor cannot be brute-forced through the recovery path either.
	_, err := s.store.GetTOTP(ctx, tenantID, userID)
	gated := err == nil // a TOTP enrollment exists → gate the recovery attempt against its budget
	var reserved int
	switch {
	case gated:
		// Reserve a slot before the lookup/compare so a locked factor cannot be brute-forced
		// through the recovery path either.
		n, rerr := s.reserveAttempt(ctx, tenantID, userID)
		if rerr != nil {
			return rerr
		}
		reserved = n
		if s.overLimit(n) {
			s.emitBlocked(ctx, tenantID, userID, "recovery")
			return ErrTooManyAttempts
		}
	case errors.Is(err, ErrNotEnrolled):
		// No TOTP factor to gate against (recovery codes can exist on their own); fall through
		// to the single-use consume, which is itself the only guard.
	default:
		return err
	}

	// A successful consume resets the TOTP failed-attempt counter (see Store).
	if err := s.store.ConsumeRecoveryCode(ctx, tenantID, userID, HashRecoveryCode(code)); err != nil {
		if errors.Is(err, ErrRecoveryCodeNotFound) {
			// When this wrong code was the last allowed attempt the factor is now locked; report
			// the lock-out so callers stop accepting further guesses.
			if gated && s.atLimit(reserved) {
				s.emitBlocked(ctx, tenantID, userID, "recovery")
				return ErrTooManyAttempts
			}
			s.emit(ctx, event.Event{Type: event.MFAVerificationFailed, UserID: userID.String(), TenantID: tenantID, Reason: "invalid_recovery_code"})
		}
		return err
	}
	return nil
}

// overLimit reports whether the reserved count n is beyond the configured ceiling (the slot was
// handed out only to reject it). When limiting is disabled (maxAttempts <= 0) it is always false.
func (s *service) overLimit(n int) bool { return s.maxAttempts > 0 && n > s.maxAttempts }

// atLimit reports whether n is exactly the last allowed attempt. When limiting is disabled it is
// always false.
func (s *service) atLimit(n int) bool { return s.maxAttempts > 0 && n >= s.maxAttempts }

// reserveAttempt atomically claims one slot of the attempt budget and returns the new count.
// When limiting is disabled it is a no-op that reports 0 (never locked).
// If a lockoutDuration is configured, the store handles time-based lockout decay atomically
// and prevents perpetual DoS if already locked.
func (s *service) reserveAttempt(ctx context.Context, tenantID string, userID uuid.UUID) (int, error) {
	if s.maxAttempts <= 0 {
		return 0, nil
	}
	return s.store.IncrementTOTPAttempts(ctx, tenantID, userID, s.now(), s.maxAttempts, s.lockoutDuration)
}

// emitBlocked reports that a second factor was locked after exhausting its attempt budget.
func (s *service) emitBlocked(ctx context.Context, tenantID string, userID uuid.UUID, factor string) {
	s.emit(ctx, event.Event{
		Type:     event.AccountBlocked,
		UserID:   userID.String(),
		TenantID: tenantID,
		Reason:   "mfa_too_many_attempts",
		Attrs:    map[string]any{"factor": factor},
	})
}

func (s *service) RegenerateRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID) ([]string, error) {
	enrollment, err := s.store.GetTOTP(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	if !enrollment.Confirmed() {
		return nil, ErrNotConfirmed
	}
	return s.mintRecoveryCodes(ctx, tenantID, userID)
}

func (s *service) DisableTOTP(ctx context.Context, tenantID string, userID uuid.UUID) error {
	if err := s.store.DeleteRecoveryCodes(ctx, tenantID, userID); err != nil {
		return err
	}
	if err := s.store.DeleteTOTP(ctx, tenantID, userID); err != nil {
		return err
	}
	s.emit(ctx, event.Event{Type: event.MFADisabled, UserID: userID.String(), TenantID: tenantID})
	return nil
}

func (s *service) IsEnrolled(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
	enrollment, err := s.store.GetTOTP(ctx, tenantID, userID)
	if err != nil {
		if errors.Is(err, ErrNotEnrolled) {
			return false, nil
		}
		return false, err
	}
	return enrollment.Confirmed(), nil
}

func (s *service) UnlockMFA(ctx context.Context, tenantID string, userID uuid.UUID) error {
	return s.store.ResetTOTPAttempts(ctx, tenantID, userID)
}

func (s *service) mintRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID) ([]string, error) {
	plaintext, hashes, err := generateRecoveryCodes(s.recoveryCodeCount)
	if err != nil {
		return nil, err
	}
	if err := s.store.ReplaceRecoveryCodes(ctx, tenantID, userID, hashes); err != nil {
		return nil, err
	}
	return plaintext, nil
}
