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

	// ErrTenantRequired is returned when the store requires a tenant but none was provided.
	ErrTenantRequired = errors.New("mfa: tenant ID is required")
)
