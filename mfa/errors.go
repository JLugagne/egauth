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
	// times; the factor is locked and the user must re-authenticate / re-enroll (or an
	// operator must reset it) before further attempts are accepted.
	ErrTooManyAttempts = errors.New("mfa: too many attempts")

	// ErrTenantMismatch is returned when a Save* call is given a tenantID that conflicts with
	// a non-empty TenantID already set on the record being saved.
	ErrTenantMismatch = errors.New("mfa: tenant ID mismatch")
)
