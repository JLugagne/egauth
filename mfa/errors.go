package mfa

import "errors"

var (
	// ErrNotEnrolled is returned when no TOTP enrollment exists for the user.
	ErrNotEnrolled = errors.New("mfa: not enrolled")

	// ErrAlreadyEnrolled is returned when enrollment is attempted but a confirmed TOTP factor
	// already exists for the user.
	ErrAlreadyEnrolled = errors.New("mfa: already enrolled")

	// ErrNotConfirmed is returned when a second-factor check is attempted but the enrollment
	// has not been confirmed yet.
	ErrNotConfirmed = errors.New("mfa: enrollment not confirmed")

	// ErrInvalidCode is returned when a TOTP code does not match (or is a replay of an
	// already-used code within its window).
	ErrInvalidCode = errors.New("mfa: invalid code")

	// ErrRecoveryCodeNotFound is returned when a recovery code does not match an unused code.
	ErrRecoveryCodeNotFound = errors.New("mfa: recovery code not found")

	// ErrTooManyAttempts is returned when the second factor has been guessed wrong too many
	// times. The lockout automatically expires after LockoutDuration (default 15 min) from the
	// last failed attempt, at which point the next attempt is treated as a fresh budget.
	// Operators can also unblock a user immediately via Service.UnlockMFA. If LockoutDuration
	// is set to 0 the lockout is permanent until UnlockMFA is called or the factor is disabled.
	ErrTooManyAttempts = errors.New("mfa: too many attempts")

	// ErrTenantMismatch is returned when a Save* call is given a tenantID that conflicts with
	// a non-empty TenantID already set on the record being saved.
	ErrTenantMismatch = errors.New("mfa: tenant ID mismatch")

	// ErrWeakSecret is returned when a TOTP shared secret decodes to fewer than MinSecretBytes
	// bytes — including the empty secret, which would key the HMAC with zero bytes and make every
	// code it produces trivially computable. It is reported at enrollment AND at verification, so a
	// factor whose stored secret was truncated (bad import, corrupt row, hand-edited record) fails
	// closed instead of accepting an attacker-computable code.
	ErrWeakSecret = errors.New("mfa: TOTP shared secret is too short")
)
