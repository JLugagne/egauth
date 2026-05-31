// Package passkey implements WebAuthn / FIDO2 passkeys (registration and login ceremonies) on
// top of the go-webauthn library, following egauth's conventions: a credential Store
// (memory + pgx implementations with a shared contract), a Service that runs the ceremonies,
// and à-la-carte HTTP handlers. The ceremony challenge (SessionData) is carried between the
// Begin and Finish steps in a short-lived, HMAC-signed secure cookie (the signing key is
// supplied via WithCookieKey and verified before the data is trusted), so the server stays
// stateless between the two calls without letting the client tamper with the challenge or the
// user-verification requirement.
package passkey

import (
	"time"

	"github.com/google/uuid"
)

// Credential is a stored WebAuthn credential record for a user. Data holds the full
// go-webauthn Credential serialized as JSON (the source of truth used to rebuild the
// authenticator state); ID/PublicKey/SignCount are denormalized for indexing and display.
type Credential struct {
	UserID    uuid.UUID
	TenantID  string
	ID        []byte // credential ID (raw bytes); unique per user
	PublicKey []byte
	SignCount uint32
	Data      []byte // JSON of webauthn.Credential
	CreatedAt time.Time
}

// StoreOptions holds options for Store operations, such as multi-tenancy.
type StoreOptions struct {
	TenantID *string
}

// Option configures StoreOptions.
type Option func(*StoreOptions)

// WithTenant scopes a Store operation to a tenant.
func WithTenant(id string) Option {
	return func(o *StoreOptions) { o.TenantID = &id }
}

// ApplyOptions applies opts to a fresh StoreOptions.
func ApplyOptions(opts []Option) StoreOptions {
	var o StoreOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
