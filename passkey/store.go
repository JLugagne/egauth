package passkey

import (
	"context"

	"github.com/google/uuid"
)

// Store persists WebAuthn credential records. Every operation is scoped to a tenant via a
// mandatory tenantID argument. An empty string is a legal tenant key (the single-tenant
// default partition); it must still be passed explicitly.
type Store interface {
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
