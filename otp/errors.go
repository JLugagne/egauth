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

	// ErrTenantRequired is returned when the store requires a tenant but none was provided.
	ErrTenantRequired = errors.New("otp: tenant ID is required")
)
