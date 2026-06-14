package otp

import (
	"context"

	"github.com/google/uuid"
)

// Store persists outstanding one-time passcodes (one per subject+purpose).
//
// It is the composition of the stable-core OTPStore (the issue/look-up/attempt-count/consume
// operations the Service touches on every send and verify) and the optional OTPReaper (the
// schedulable expired-code sweep that only a background job calls). Segmenting the contract this
// way means a future v1.x capability can ship as a NEW optional interface rather than a method on
// this one, which would break every external Store. Both the in-memory and pgx stores implement
// the whole Store.
//
// Every operation is scoped to a tenant via a mandatory tenantID argument. An empty
// string is a legal tenant key (the single-tenant default partition); it must still be
// passed explicitly.
type Store interface {
	OTPStore
	OTPReaper
}

// OTPStore is the stable-core capability of an OTP backend: issue, look up, attempt-count and
// consume the outstanding one-time codes the Service touches on every send/verify. It is the part
// of the contract frozen for v1; new optional behaviour is added as a separate capability
// interface, never as a method here.
type OTPStore interface {
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
}

// OTPReaper is the optional GC capability of an OTP backend: the schedulable sweep that purges
// expired codes. It is separated from the core OTPStore because the request path never calls it —
// only a background job does. The full Store composes OTPStore + OTPReaper; both the in-memory and
// pgx stores implement the whole Store.
type OTPReaper interface {
	// DeleteExpired purges codes past their expiry within the given tenant, returning the number
	// deleted. It is the schedulable GC reaper. A background job sweeping every tenant must loop.
	DeleteExpired(ctx context.Context, tenantID string) (int64, error)
}
