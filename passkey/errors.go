package passkey

import "errors"

var (
	// ErrNoCredentials is returned when a login ceremony is started for a user that has no
	// registered passkeys.
	ErrNoCredentials = errors.New("passkey: no credentials registered")

	// ErrCredentialNotFound is returned when a specific credential cannot be found.
	ErrCredentialNotFound = errors.New("passkey: credential not found")

	// ErrCredentialExists is returned when saving a credential whose ID is already registered
	// within the tenant (credential IDs are globally unique per authenticator).
	ErrCredentialExists = errors.New("passkey: credential already exists")

	// ErrSessionInvalid is returned when the ceremony session cookie is missing, malformed, or
	// expired between the Begin and Finish steps.
	ErrSessionInvalid = errors.New("passkey: ceremony session is missing or invalid")

	// ErrTenantRequired is returned when the store requires a tenant but none was provided.
	ErrTenantRequired = errors.New("passkey: tenant ID is required")
)
