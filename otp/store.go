package otp

import (
	"context"

	"github.com/google/uuid"
)

// Store persists outstanding one-time passcodes (one per subject+purpose).\n\nEvery operation is scoped to a tenant via a mandatory tenantID argument. An empty\nstring is a legal tenant key (the single-tenant default partition); it must still be\npassed explicitly.
type Store interface {
	// SaveOTP upserts the code for a subject+purpose, replacing (and resetting the attempt
	// count of) any previous outstanding code. If the record already carries a non-empty
	// TenantID that differs from tenantID, it returns ErrTenantMismatch.
	SaveOTP(ctx context.Context, tenantID string, o *OTP) error
	// GetOTP returns the outstanding code for the subject+purpose, or ErrCodeNotFound.
	GetOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) (*OTP, error)
	// IncrementOTPAttempts atomically increments and returns the new attempt count for the
	// subject+purpose. Returns ErrCodeNotFound if there is no outstanding code.
	IncrementOTPAttempts(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) (int, error)
	// ConsumeOTP atomically removes the outstanding code ONLY IF its CodeHash equals
	// expectedCodeHash, and reports whether THIS call was the one that removed it. It is both the
	// single-use guard (under concurrent verification only one caller observes consumed=true, so a
	// code cannot authorize more than one verification) AND the identity guard: a row whose hash
	// no longer matches expectedCodeHash — e.g. a code reissued between the verifier's read and
	// this consume — is left untouched and consumed=false is returned, so a superseded code can
	// never burn its replacement.
	ConsumeOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose, expectedCodeHash string) (consumed bool, err error)
	// DeleteOTP removes the outstanding code for the subject+purpose. Idempotent (used for
	// expiry/burn/invalidate where the row may already be gone).
	DeleteOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) error
	// DeleteExpired purges codes past their expiry within the given tenant, returning the number
	// deleted. It is the schedulable GC reaper. A background job sweeping every tenant must loop.
	DeleteExpired(ctx context.Context, tenantID string) (int64, error)
}
