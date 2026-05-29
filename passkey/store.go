package passkey

import (
	"context"

	"github.com/google/uuid"
)

// Store persists WebAuthn credential records. Implementations set TenantID on stored records
// from the operation's options (WithTenant).
type Store interface {
	// SaveCredential persists a newly registered credential.
	SaveCredential(ctx context.Context, c *Credential, opts ...Option) error
	// GetCredentials returns all credentials registered by the user (empty slice if none).
	GetCredentials(ctx context.Context, userID uuid.UUID, opts ...Option) ([]*Credential, error)
	// UpdateCredential persists changes to an existing credential (notably the signature
	// counter after a successful login). Returns ErrCredentialNotFound if absent.
	UpdateCredential(ctx context.Context, c *Credential, opts ...Option) error
	// DeleteCredential removes one of the user's credentials by its credential ID. Returns
	// ErrCredentialNotFound if absent.
	DeleteCredential(ctx context.Context, userID uuid.UUID, credentialID []byte, opts ...Option) error
}
