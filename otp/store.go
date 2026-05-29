package otp

import (
	"context"

	"github.com/google/uuid"
)

// Store persists outstanding one-time passcodes (one per subject+purpose). Implementations set
// TenantID on stored records from the operation's options (WithTenant).
type Store interface {
	// SaveOTP upserts the code for a subject+purpose, replacing (and resetting the attempt
	// count of) any previous outstanding code.
	SaveOTP(ctx context.Context, o *OTP, opts ...Option) error
	// GetOTP returns the outstanding code for the subject+purpose, or ErrCodeNotFound.
	GetOTP(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...Option) (*OTP, error)
	// IncrementOTPAttempts atomically increments and returns the new attempt count for the
	// subject+purpose. Returns ErrCodeNotFound if there is no outstanding code.
	IncrementOTPAttempts(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...Option) (int, error)
	// ConsumeOTP atomically removes the outstanding code and reports whether THIS call was the
	// one that removed it. It is the single-use guard: under concurrent verification only one
	// caller observes consumed=true, so a code cannot authorize more than one verification.
	ConsumeOTP(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...Option) (consumed bool, err error)
	// DeleteOTP removes the outstanding code for the subject+purpose. Idempotent (used for
	// expiry/burn/invalidate where the row may already be gone).
	DeleteOTP(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...Option) error
}
