package mfa

import (
	"context"

	"github.com/google/uuid"
)

// Store persists TOTP enrollments and recovery codes.
//
// Every operation is scoped to a tenant via a mandatory tenantID argument. An empty
// string is a legal tenant key (the single-tenant default partition); it must still be
// passed explicitly.
type Store interface {
	// SaveTOTP upserts the user's TOTP enrollment (one per user/tenant). If the enrollment
	// already carries a non-empty TenantID that differs from tenantID, it returns ErrTenantMismatch.
	SaveTOTP(ctx context.Context, tenantID string, e *TOTPEnrollment) error
	// GetTOTP returns the user's enrollment, or ErrNotEnrolled if none exists.
	GetTOTP(ctx context.Context, tenantID string, userID uuid.UUID) (*TOTPEnrollment, error)
	// DeleteTOTP removes the user's enrollment. It is idempotent (no error if absent).
	DeleteTOTP(ctx context.Context, tenantID string, userID uuid.UUID) error
	// MarkTOTPUsed records step as the last accepted time-step, but only if it is strictly
	// greater than the current value. It reports whether the update applied — false means the
	// step was already consumed (a replay), which the service rejects.
	MarkTOTPUsed(ctx context.Context, tenantID string, userID uuid.UUID, step int64) (bool, error)

	// ReplaceRecoveryCodes atomically discards any existing recovery codes for the user and
	// stores the given hashes (in any order).
	ReplaceRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID, codeHashes []string) error
	// ConsumeRecoveryCode marks the matching unused code as used (single-use). It returns
	// ErrRecoveryCodeNotFound when no unused code matches the hash.
	ConsumeRecoveryCode(ctx context.Context, tenantID string, userID uuid.UUID, codeHash string) error
	// DeleteRecoveryCodes removes all of the user's recovery codes. Idempotent.
	DeleteRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID) error
}
