package passkey

import "errors"

var (
	// ErrNilStore is returned by NewService when the store argument is nil. The store is
	// always required; NewService fails fast at startup rather than nil-panicking on the first
	// request.
	ErrNilStore = errors.New("passkey: NewService requires a non-nil Store")

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

	// ErrTenantMismatch is returned when the record's TenantID does not match the tenantID
	// argument supplied to Save* operations.
	ErrTenantMismatch = errors.New("passkey: tenant ID mismatch")

	// ErrAttestationRejected is returned by FinishRegistration when the authenticator's attestation
	// is refused by the configured attestation policy (e.g. its AAGUID is outside the allow-list or
	// on the deny-list). No credential is stored when this is returned.
	ErrAttestationRejected = errors.New("passkey: attestation rejected by policy")
)
