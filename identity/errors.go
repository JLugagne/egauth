package identity

import (
	"errors"
)

var (
	// ErrUserNotFound is returned when a user cannot be found in the store.
	ErrUserNotFound = errors.New("identity: user not found")

	// ErrEmailAlreadyExists is returned when trying to create a user with an email
	// that already exists in the same tenant.
	ErrEmailAlreadyExists = errors.New("identity: email already exists")

	// ErrInvalidEmail is returned when an email fails RFC 5322 address parsing.
	ErrInvalidEmail = errors.New("identity: invalid email")

	// ErrIdentityNotFound is returned when an identity cannot be found.
	ErrIdentityNotFound = errors.New("identity: identity not found")

	// ErrIdentityAlreadyExists is returned when trying to create an identity
	// that already exists for a given provider and provider_id in a tenant.
	ErrIdentityAlreadyExists = errors.New("identity: identity already exists")

	// ErrTenantRequired is returned when the store requires a tenant but none was provided.
	ErrTenantRequired = errors.New("identity: tenant ID is required")

	// ErrInvalidCredentials is returned when authentication fails due to invalid credentials.
	ErrInvalidCredentials = errors.New("identity: invalid credentials")

	// ErrAccountLocked is returned when authentication is attempted on an account that is
	// currently locked due to too many failed attempts.
	ErrAccountLocked = errors.New("identity: account locked")

	// ErrVerificationTokenNotFound is returned when a verification token cannot be found,
	// is malformed, or its verifier does not match. The three cases are deliberately
	// merged so the caller cannot distinguish "unknown selector" from "wrong verifier".
	ErrVerificationTokenNotFound = errors.New("identity: verification token not found")

	// ErrVerificationTokenExpired is returned when a verification token is found and its
	// verifier matches, but it is past its expiry. It is only surfaced to a caller that
	// presented the genuine token.
	ErrVerificationTokenExpired = errors.New("identity: verification token expired")
)
