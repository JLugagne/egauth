package mfa

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Store persists TOTP enrollments and recovery codes.
//
// It is the composition of two capability interfaces — TOTPStore (the authenticator-app factor)
// and RecoveryCodeStore (the single-use backup codes). Segmenting the contract this way means a
// future v1.x capability can ship as a NEW optional interface rather than a method on this one,
// which would break every external Store. Both the in-memory and pgx stores implement the whole
// Store.
//
// Every operation is scoped to a tenant via a mandatory tenantID argument. An empty
// string is a legal tenant key (the single-tenant default partition); it must still be
// passed explicitly.
type Store interface {
	TOTPStore
	RecoveryCodeStore
}

// TOTPStore is the TOTP-enrollment capability of an mfa backend: persisting, reading,
// replay-guarding and lockout-accounting a user's authenticator-app factor.
type TOTPStore interface {
	// SaveTOTP upserts the user's TOTP enrollment (one per user/tenant). If the enrollment
	// already carries a non-empty TenantID that differs from tenantID, it returns ErrTenantMismatch.
	SaveTOTP(ctx context.Context, tenantID string, e *TOTPEnrollment) error
	// GetTOTP returns the user's enrollment, or ErrNotEnrolled if none exists.
	GetTOTP(ctx context.Context, tenantID string, userID uuid.UUID) (*TOTPEnrollment, error)
	// DeleteTOTP removes the user's enrollment. It is idempotent (no error if absent).
	DeleteTOTP(ctx context.Context, tenantID string, userID uuid.UUID) error
	// MarkTOTPUsed records step as the last accepted time-step, but only if it is strictly
	// greater than the current value. It reports whether the update applied — false means the
	// step was already consumed (a replay), which the service rejects. On a successful update
	// it MUST also reset the failed-attempt counter and LastAttemptAt to zero (a fresh accepted
	// code clears the lock-out budget).
	MarkTOTPUsed(ctx context.Context, tenantID string, userID uuid.UUID, step int64) (bool, error)
	// IncrementTOTPAttempts atomically increments the failed-attempt count for the user's
	// factor, sets LastAttemptAt to now, and returns the new count. It is the lock-out gate:
	// the service reserves a slot here BEFORE the constant-time compare, so concurrent wrong
	// guesses cannot run more comparisons than the configured limit. The now parameter is the
	// caller's clock value and is stored as LastAttemptAt to enable time-based lockout decay.
	// Returns ErrNotEnrolled if there is no enrollment.
	IncrementTOTPAttempts(ctx context.Context, tenantID string, userID uuid.UUID, now time.Time) (int, error)
	// ResetTOTPAttempts sets the failed-attempt counter and LastAttemptAt back to their zero
	// values for the given enrollment. It is used by the service for time-based lockout decay
	// and by the admin UnlockMFA primitive. Returns ErrNotEnrolled if the enrollment is absent.
	ResetTOTPAttempts(ctx context.Context, tenantID string, userID uuid.UUID) error
}

// RecoveryCodeStore is the recovery-code capability of an mfa backend: the single-use backup
// codes a user falls back to when their authenticator is unavailable.
type RecoveryCodeStore interface {
	// ReplaceRecoveryCodes atomically discards any existing recovery codes for the user and
	// stores the given hashes (in any order).
	ReplaceRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID, codeHashes []string) error
	// ConsumeRecoveryCode marks the matching unused code as used (single-use). It returns
	// ErrRecoveryCodeNotFound when no unused code matches the hash. On a successful consume it
	// MUST also reset the user's TOTP failed-attempt counter and LastAttemptAt to zero (a
	// valid recovery code is a successful second-factor verification, so it clears the lock-out
	// budget).
	ConsumeRecoveryCode(ctx context.Context, tenantID string, userID uuid.UUID, codeHash string) error
	// DeleteRecoveryCodes removes all of the user's recovery codes. Idempotent.
	DeleteRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID) error
}
