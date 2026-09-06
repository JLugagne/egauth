package otp

import (
	"context"
	"errors"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/google/uuid"
)

// Service issues and verifies one-time passcodes over a Store.
type Service interface {
	// Issue mints a fresh code for the subject+purpose (replacing any outstanding one) and
	// returns the Challenge — including the plaintext Code — for the application to deliver.
	// egauth does not send anything.
	Issue(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) (*Challenge, error)
	// Verify checks a presented code: single-use on success, attempt-limited on failure.
	// Returns ErrInvalidCode, ErrCodeNotFound or ErrTooManyAttempts.
	Verify(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose, code string) error
	// Invalidate discards any outstanding code for the subject+purpose. Idempotent.
	Invalidate(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) error
}

type service struct {
	store       Store
	digits      int
	ttl         time.Duration
	maxAttempts int
	cooldown    time.Duration
	now         func() time.Time
	events      event.Sink
}

// ServiceOption configures the OTP Service.
type ServiceOption func(*service)

// WithDigits sets the number of digits in generated codes (default 6).
// The value must be in the range [6, 10]: NewService panics if it falls outside
// this range. Values below 6 produce a trivially guessable code space (a 5-digit
// code has only 100 000 candidates); values above 10 cause big.Int allocations
// with no security benefit. Most authenticator apps support only 6 and 8 digits.
func WithDigits(n int) ServiceOption { return func(s *service) { s.digits = n } }

// WithTTL sets how long an issued code stays valid (default 10m).
func WithTTL(d time.Duration) ServiceOption { return func(s *service) { s.ttl = d } }

// WithMaxAttempts sets how many wrong guesses burn the code (default 5).
func WithMaxAttempts(n int) ServiceOption { return func(s *service) { s.maxAttempts = n } }

// WithCooldown sets the minimum duration required between OTP issues for the same subject+purpose (default 30s).
// Non-positive disables cooldown.
func WithCooldown(d time.Duration) ServiceOption { return func(s *service) { s.cooldown = d } }

// WithClock overrides the time source (primarily for tests).
func WithClock(now func() time.Time) ServiceOption { return func(s *service) { s.now = now } }

// NewService builds an OTP Service with sensible defaults. It panics on a nil store
// (always required) to fail fast at startup rather than with a nil-pointer panic deep
// in a request handler.
func NewService(store Store, opts ...ServiceOption) Service {
	if store == nil {
		panic("otp: NewService requires a non-nil Store")
	}
	s := &service{
		store:       store,
		digits:      DefaultDigits,
		ttl:         DefaultTTL,
		maxAttempts: DefaultMaxAttempts,
		cooldown:    DefaultCooldown,
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	// Enforce safe bounds on digits so a misconfiguration cannot produce
	// predictable codes (too few digits) or an allocation footgun (too many).
	// Minimum 6: a 6-digit code has 1,000,000 possible values, making brute
	// force impractical even with generous attempt limits.
	// Maximum 10: beyond this the big.Int arithmetic and zero-padded Sprintf
	// allocate proportionally with no security benefit.
	if s.digits < 6 || s.digits > 10 {
		panic("otp: NewService requires digits in the range [6, 10]")
	}
	if s.ttl <= 0 {
		s.ttl = DefaultTTL
	}
	if s.maxAttempts <= 0 {
		s.maxAttempts = DefaultMaxAttempts
	}
	if s.cooldown < 0 {
		s.cooldown = 0
	}
	return s
}

func (s *service) Issue(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) (*Challenge, error) {
	now := s.now()
	if s.cooldown > 0 {
		existing, err := s.store.GetOTP(ctx, tenantID, subjectID, purpose)
		if err == nil && existing != nil && !existing.CreatedAt.IsZero() {
			if now.Sub(existing.CreatedAt) < s.cooldown || existing.CreatedAt.After(now) {
				return nil, ErrCooldownActive
			}
		} else if err != nil && !errors.Is(err, ErrCodeNotFound) {
			return nil, err
		}
	}

	code, err := generateCode(s.digits)
	if err != nil {
		return nil, err
	}
	expiresAt := now.Add(s.ttl)

	record := &OTP{
		SubjectID: subjectID,
		TenantID:  tenantID,
		Purpose:   purpose,
		CodeHash:  HashCode(code),
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}
	if err := s.store.SaveOTP(ctx, tenantID, record); err != nil {
		return nil, err
	}

	return &Challenge{
		SubjectID: subjectID,
		TenantID:  tenantID,
		Purpose:   purpose,
		Code:      code,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *service) Verify(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose, code string) error {
	record, err := s.store.GetOTP(ctx, tenantID, subjectID, purpose)
	if err != nil {
		return err
	}

	if s.now().After(record.ExpiresAt) {
		_ = s.store.DeleteOTP(ctx, tenantID, subjectID, purpose)
		return ErrCodeNotFound
	}

	// Reserve an attempt slot atomically BEFORE comparing. IncrementOTPAttempts hands each
	// concurrent caller a unique, monotonically increasing count, so at most maxAttempts
	// callers ever reach compareCode — concurrent guesses cannot run more comparisons than the
	// limit (the gate is the atomic counter, not the stale read above).
	n, err := s.store.IncrementOTPAttempts(ctx, tenantID, subjectID, purpose)
	if err != nil {
		return err // ErrCodeNotFound if it was consumed/burned by a concurrent verify
	}
	if n > s.maxAttempts {
		_ = s.store.DeleteOTP(ctx, tenantID, subjectID, purpose)
		s.emit(ctx, event.Event{Type: event.AccountBlocked, UserID: subjectID.String(), TenantID: tenantID, Reason: "otp_too_many_attempts", Attrs: map[string]any{"purpose": purpose}})
		return ErrTooManyAttempts
	}

	if !compareCode(record.CodeHash, code) {
		if n >= s.maxAttempts {
			// Last allowed guess was wrong: burn the code.
			_ = s.store.DeleteOTP(ctx, tenantID, subjectID, purpose)
			s.emit(ctx, event.Event{Type: event.AccountBlocked, UserID: subjectID.String(), TenantID: tenantID, Reason: "otp_too_many_attempts", Attrs: map[string]any{"purpose": purpose}})
			return ErrTooManyAttempts
		}
		return ErrInvalidCode
	}

	// Correct code: consume atomically, guarded on the exact hash we just compared against. Only
	// the caller that removes THAT row wins, so a single code can never authorize more than one
	// verification (single-use under concurrency). The hash guard also closes the TOCTOU window:
	// if the code was reissued between the GetOTP read above and here, the row now carries a
	// different hash, ConsumeOTP removes nothing, and this stale verification fails instead of
	// burning the fresh replacement.
	consumed, err := s.store.ConsumeOTP(ctx, tenantID, subjectID, purpose, record.CodeHash)
	if err != nil {
		return err
	}
	if !consumed {
		return ErrCodeNotFound
	}
	return nil
}

func (s *service) Invalidate(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) error {
	return s.store.DeleteOTP(ctx, tenantID, subjectID, purpose)
}

// WithEventSink registers a security-event sink (see the event package) that receives an
// AccountBlocked event when a subject exhausts its verification attempts for a purpose (the
// code is burned). Optional; without it no events are emitted.
func WithEventSink(sink event.Sink) ServiceOption { return func(s *service) { s.events = sink } }

// emit sends a security event to the configured sink (a no-op when none is set).
func (s *service) emit(ctx context.Context, e event.Event) { event.Emit(ctx, s.events, e) }
