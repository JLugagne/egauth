// Package mfa implements multi-factor authentication: time-based one-time passwords (TOTP,
// RFC 6238 / RFC 4226) for authenticator apps, and single-use recovery codes. It follows
// egauth's conventions — a stateful Store interface (memory + pgx implementations, a shared
// contract suite), a stateless-ish Service for orchestration, and à-la-carte HTTP handlers —
// and depends only on the standard library plus google/uuid.
//
// SMS / phone factors are intentionally NOT supported (authenticator apps only).
package mfa

import (
	"time"

	"github.com/google/uuid"
)

// TOTP defaults. Algorithm SHA1 / 6 digits / 30s period are the values universally supported
// by authenticator apps (Google Authenticator, Authy, 1Password, ...).
const (
	DefaultDigits = 6
	DefaultPeriod = 30 * time.Second
	// DefaultSkew is how many periods of clock drift are tolerated on each side when
	// verifying a code (±1 → accepts the previous, current and next 30s window).
	DefaultSkew = 1
	// DefaultRecoveryCodeCount is how many single-use recovery codes are minted per set.
	DefaultRecoveryCodeCount = 10
	// DefaultMaxAttempts is how many failed second-factor verifications (TOTP or recovery
	// code, combined) are tolerated before the factor is locked. The second factor is
	// online-brute-forceable without it (≈3 of 1,000,000 codes are valid per window), so
	// limiting is ON by default; disable it explicitly with WithNoAttemptLimit.
	DefaultMaxAttempts = 5
	// DefaultLockoutDuration is the time window after which a locked-out second factor
	// automatically resets its attempt counter, allowing the user to try again. The window
	// is measured from the last failed attempt. Override via WithLockoutDuration; 0 disables
	// time-based decay (the lockout is permanent until an admin calls UnlockMFA or the factor
	// is disabled and re-enrolled).
	DefaultLockoutDuration = 15 * time.Minute
)

// TOTPEnrollment is a user's TOTP factor. The shared Secret must be stored in a recoverable
// form (the server recomputes the expected code from it), so unlike passwords/opaque tokens
// it is NOT hashed — see SECURITY.md for the at-rest considerations.
type TOTPEnrollment struct {
	UserID   uuid.UUID
	TenantID string
	// Secret is the base32-encoded shared secret (no padding), as provisioned to the app.
	Secret string
	// ConfirmedAt is set once the user has proven possession by entering a valid code; an
	// unconfirmed enrollment must not satisfy a login second-factor check.
	ConfirmedAt *time.Time
	// LastUsedStep is the most recent accepted time-step counter, used to reject replay of a
	// code within its validity window.
	LastUsedStep int64
	// FailedAttempts counts consecutive failed second-factor verifications (TOTP or recovery
	// code) since the last success or (re-)enrollment. Once it exceeds the service's
	// MaxAttempts the factor is locked; a successful verification resets it to zero.
	FailedAttempts int
	// LastAttemptAt records when the most recent failed second-factor verification was made.
	// The service uses this to implement time-based lockout decay: if the elapsed time since
	// the last failed attempt exceeds LockoutDuration, the counter is automatically reset and
	// the attempt is treated as a fresh budget.
	LastAttemptAt time.Time
	CreatedAt     time.Time
}

// Confirmed reports whether the enrollment has been confirmed.
func (e *TOTPEnrollment) Confirmed() bool { return e != nil && e.ConfirmedAt != nil }

// RecoveryCode is a single-use backup code. Only the SHA-256 hash of the plaintext is stored.
type RecoveryCode struct {
	UserID    uuid.UUID
	TenantID  string
	CodeHash  string
	UsedAt    *time.Time
	CreatedAt time.Time
}
