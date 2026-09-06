package otp

import "errors"

var (
	// ErrCodeNotFound is returned when no outstanding code exists for the subject+purpose, or
	// it has expired. It is deliberately indistinguishable from a wrong code at the handler
	// layer to avoid leaking whether a challenge is in flight.
	ErrCodeNotFound = errors.New("otp: no matching code")

	// ErrInvalidCode is returned when the presented code does not match.
	ErrInvalidCode = errors.New("otp: invalid code")

	// ErrTooManyAttempts is returned when the code has been guessed wrong too many times; the
	// code is burned and the subject must request a new one.
	ErrTooManyAttempts = errors.New("otp: too many attempts")

	// ErrTenantMismatch is returned by a SaveOTP operation when the record already carries a
	// non-empty TenantID that differs from the tenantID argument passed to the call.
	ErrTenantMismatch = errors.New("otp: tenant ID mismatch")

	// ErrCooldownActive is returned by Issue when an OTP challenge was recently issued for the
	// subject+purpose and the cooldown window has not elapsed yet.
	ErrCooldownActive = errors.New("otp: cooldown active; please wait before requesting another code")
)
