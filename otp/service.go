package otp

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Service issues and verifies one-time passcodes over a Store.
type Service interface {
	// Issue mints a fresh code for the subject+purpose (replacing any outstanding one) and
	// returns the Challenge — including the plaintext Code — for the application to deliver.
	// egauth does not send anything.
	Issue(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...Option) (*Challenge, error)
	// Verify checks a presented code: single-use on success, attempt-limited on failure.
	// Returns ErrInvalidCode, ErrCodeNotFound or ErrTooManyAttempts.
	Verify(ctx context.Context, subjectID uuid.UUID, purpose, code string, opts ...Option) error
	// Invalidate discards any outstanding code for the subject+purpose. Idempotent.
	Invalidate(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...Option) error
}

type service struct {
	store       Store
	digits      int
	ttl         time.Duration
	maxAttempts int
	now         func() time.Time
}

// ServiceOption configures the OTP Service.
type ServiceOption func(*service)

// WithDigits sets the number of digits in generated codes (default 6).
func WithDigits(n int) ServiceOption { return func(s *service) { s.digits = n } }

// WithTTL sets how long an issued code stays valid (default 10m).
func WithTTL(d time.Duration) ServiceOption { return func(s *service) { s.ttl = d } }

// WithMaxAttempts sets how many wrong guesses burn the code (default 5).
func WithMaxAttempts(n int) ServiceOption { return func(s *service) { s.maxAttempts = n } }

// WithClock overrides the time source (primarily for tests).
func WithClock(now func() time.Time) ServiceOption { return func(s *service) { s.now = now } }

// NewService builds an OTP Service with sensible defaults.
func NewService(store Store, opts ...ServiceOption) Service {
	s := &service{
		store:       store,
		digits:      DefaultDigits,
		ttl:         DefaultTTL,
		maxAttempts: DefaultMaxAttempts,
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	// Clamp to safe minimums so a misconfiguration cannot produce predictable/never-expiring
	// codes or an unbounded attempt count.
	if s.digits <= 0 {
		s.digits = DefaultDigits
	}
	if s.ttl <= 0 {
		s.ttl = DefaultTTL
	}
	if s.maxAttempts <= 0 {
		s.maxAttempts = DefaultMaxAttempts
	}
	return s
}

func (s *service) Issue(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...Option) (*Challenge, error) {
	code, err := generateCode(s.digits)
	if err != nil {
		return nil, err
	}
	now := s.now()
	expiresAt := now.Add(s.ttl)

	tenant := ""
	if o := ApplyOptions(opts); o.TenantID != nil {
		tenant = *o.TenantID
	}

	record := &OTP{
		SubjectID: subjectID,
		TenantID:  tenant,
		Purpose:   purpose,
		CodeHash:  HashCode(code),
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}
	if err := s.store.SaveOTP(ctx, record, opts...); err != nil {
		return nil, err
	}

	return &Challenge{
		SubjectID: subjectID,
		TenantID:  tenant,
		Purpose:   purpose,
		Code:      code,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *service) Verify(ctx context.Context, subjectID uuid.UUID, purpose, code string, opts ...Option) error {
	record, err := s.store.GetOTP(ctx, subjectID, purpose, opts...)
	if err != nil {
		return err
	}

	if s.now().After(record.ExpiresAt) {
		_ = s.store.DeleteOTP(ctx, subjectID, purpose, opts...)
		return ErrCodeNotFound
	}

	// Reserve an attempt slot atomically BEFORE comparing. IncrementOTPAttempts hands each
	// concurrent caller a unique, monotonically increasing count, so at most maxAttempts
	// callers ever reach compareCode — concurrent guesses cannot run more comparisons than the
	// limit (the gate is the atomic counter, not the stale read above).
	n, err := s.store.IncrementOTPAttempts(ctx, subjectID, purpose, opts...)
	if err != nil {
		return err // ErrCodeNotFound if it was consumed/burned by a concurrent verify
	}
	if n > s.maxAttempts {
		_ = s.store.DeleteOTP(ctx, subjectID, purpose, opts...)
		return ErrTooManyAttempts
	}

	if !compareCode(record.CodeHash, code) {
		if n >= s.maxAttempts {
			// Last allowed guess was wrong: burn the code.
			_ = s.store.DeleteOTP(ctx, subjectID, purpose, opts...)
			return ErrTooManyAttempts
		}
		return ErrInvalidCode
	}

	// Correct code: consume atomically. Only the caller that actually removes the row wins, so
	// a single code can never authorize more than one verification (single-use under
	// concurrency).
	consumed, err := s.store.ConsumeOTP(ctx, subjectID, purpose, opts...)
	if err != nil {
		return err
	}
	if !consumed {
		return ErrCodeNotFound
	}
	return nil
}

func (s *service) Invalidate(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...Option) error {
	return s.store.DeleteOTP(ctx, subjectID, purpose, opts...)
}
