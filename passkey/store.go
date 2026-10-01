package passkey

import (
	"context"

	"github.com/google/uuid"
)

// Store persists WebAuthn credential records. Every operation is scoped to a tenant via a
// mandatory tenantID argument. An empty string is a legal tenant key (the single-tenant
// default partition); it must still be passed explicitly.
//
// Store is the composition of the cohesive credential-CRUD capability (CredentialStore) and the
// account-recovery capability (CredentialEraser). Expressing Store as an embedding of named
// capability interfaces keeps it uniform with the other modules and means a future v1.x
// capability (e.g. a credential reaper) can ship as a NEW interface rather than as a method
// added ad hoc to Store.
type Store interface {
	CredentialStore
	CredentialEraser
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

// CredentialEraser is the account-recovery capability of a passkey backend: deleting every
// credential a user has registered so a password reset / account recovery evicts passkeys an
// attacker may have enrolled. It backs Service.AccountEraser, which adapts it to the
// identity.AccountEraser hook the identity service runs on reset and deletion.
//
// Implementations MUST be idempotent (deleting for a user with no credentials returns nil),
// because account erasure may be retried after a partial failure, and MUST scope the deletion
// to the given tenant and user only.
type CredentialEraser interface {
	// DeleteCredentialsByUser removes every credential registered by userID in tenantID and
	// returns nil when the user has none.
	DeleteCredentialsByUser(ctx context.Context, tenantID string, userID uuid.UUID) error
}
