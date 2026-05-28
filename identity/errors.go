package identity

import (
	"errors"
)

var (
	// ErrUserNotFound is returned when a user cannot be found in the store.
	ErrUserNotFound = errors.New("user not found")

	// ErrEmailAlreadyExists is returned when trying to create a user with an email
	// that already exists in the same tenant.
	ErrEmailAlreadyExists = errors.New("email already exists")

	// ErrIdentityNotFound is returned when an identity cannot be found.
	ErrIdentityNotFound = errors.New("identity not found")

	// ErrIdentityAlreadyExists is returned when trying to create an identity
	// that already exists for a given provider and provider_id in a tenant.
	ErrIdentityAlreadyExists = errors.New("identity already exists")

	// ErrTenantRequired is returned when the store requires a tenant but none was provided.
	ErrTenantRequired = errors.New("tenant ID is required")

	// ErrInvalidCredentials is returned when authentication fails due to invalid credentials.
	ErrInvalidCredentials = errors.New("invalid credentials")
)
