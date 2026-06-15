package passkey

import (
	"context"

	"github.com/google/uuid"
)

// Store persists WebAuthn credential records. Every operation is scoped to a tenant via a
// mandatory tenantID argument. An empty string is a legal tenant key (the single-tenant
// default partition); it must still be passed explicitly.
//
// Store is the composition of the single cohesive CredentialStore capability. Credential
// persistence has no background-only (reaper) or otherwise optional operation to split out today,
// so there is just one capability interface — but expressing Store as an embedding of named
// capability interfaces keeps it uniform with the other modules and means a future v1.x capability
// (e.g. a credential reaper) can ship as a NEW optional interface that implementers type-assert
// for, rather than as a method added to Store, which would break every external implementation.
type Store interface {
	CredentialStore
}

// CredentialStore is the credential-CRUD capability of a passkey backend: saving newly registered
// WebAuthn credentials, listing a user's credentials, persisting sign-count/metadata updates and
// deleting a credential. It is the part of the contract frozen for v1.
type CredentialStore interface {
	// SaveCredential persists a newly registered credential. If c.TenantID is non-empty and
	// differs from tenantID, it returns ErrTenantMismatch; otherwise it sets c.TenantID = tenantID.
	SaveCredential(ctx context.Context, tenantID string, c *Credential) error
	// GetCredentials returns all credentials registered by the user (empty slice if none).
	GetCredentials(ctx context.Context, tenantID string, userID uuid.UUID) ([]*Credential, error)
	// UpdateCredential persists changes to an existing credential (notably the signature
	// counter after a successful login). Returns ErrCredentialNotFound if absent.
	UpdateCredential(ctx context.Context, tenantID string, c *Credential) error
	// DeleteCredential removes one of the user's credentials by its credential ID. Returns
	// ErrCredentialNotFound if absent.
	DeleteCredential(ctx context.Context, tenantID string, userID uuid.UUID, credentialID []byte) error
}
