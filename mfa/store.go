package mfa

import (
	"context"

	"github.com/google/uuid"
)

// Store persists TOTP enrollments and recovery codes. Implementations set TenantID on stored
// records from the operation's options (WithTenant), mirroring the identity store.
type Store interface {
	// SaveTOTP upserts the user's TOTP enrollment (one per user/tenant).
	SaveTOTP(ctx context.Context, e *TOTPEnrollment, opts ...Option) error
	// GetTOTP returns the user's enrollment, or ErrNotEnrolled if none exists.
	GetTOTP(ctx context.Context, userID uuid.UUID, opts ...Option) (*TOTPEnrollment, error)
	// DeleteTOTP removes the user's enrollment. It is idempotent (no error if absent).
	DeleteTOTP(ctx context.Context, userID uuid.UUID, opts ...Option) error
	// MarkTOTPUsed records step as the last accepted time-step, but only if it is strictly
	// greater than the current value. It reports whether the update applied — false means the
	// step was already consumed (a replay), which the service rejects.
	MarkTOTPUsed(ctx context.Context, userID uuid.UUID, step int64, opts ...Option) (bool, error)

	// ReplaceRecoveryCodes atomically discards any existing recovery codes for the user and
	// stores the given hashes (in any order).
	ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, codeHashes []string, opts ...Option) error
	// ConsumeRecoveryCode marks the matching unused code as used (single-use). It returns
	// ErrRecoveryCodeNotFound when no unused code matches the hash.
	ConsumeRecoveryCode(ctx context.Context, userID uuid.UUID, codeHash string, opts ...Option) error
	// DeleteRecoveryCodes removes all of the user's recovery codes. Idempotent.
	DeleteRecoveryCodes(ctx context.Context, userID uuid.UUID, opts ...Option) error
}
