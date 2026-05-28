package tokens

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// StoreOptions holds options for Store operations, such as Multi-tenancy.
type StoreOptions struct {
	TenantID *string
}

// Option is a function that configures StoreOptions.
type Option func(*StoreOptions)

// WithTenant sets the TenantID for the operation.
func WithTenant(id string) Option {
	return func(o *StoreOptions) {
		o.TenantID = &id
	}
}

// ApplyOptions applies the given options to a new StoreOptions instance.
func ApplyOptions(opts []Option) StoreOptions {
	var o StoreOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// Store defines the persistence interface for Refresh Tokens and API Keys.
// It stores ONLY the hash of the tokens to ensure security at rest.
type Store[C any] interface {
	// SaveRefreshToken persists the hash of a refresh token.
	SaveRefreshToken(ctx context.Context, tokenHash string, userID uuid.UUID, expiresAt time.Time, opts ...Option) error

	// FindRefreshTokenByHash retrieves a refresh token hash information.
	FindRefreshTokenByHash(ctx context.Context, tokenHash string, opts ...Option) (userID uuid.UUID, expiresAt time.Time, err error)

	// RevokeRefreshToken marks a refresh token as revoked or deletes it.
	RevokeRefreshToken(ctx context.Context, tokenHash string, opts ...Option) error

	// SaveAPIKey persists an API key.
	SaveAPIKey(ctx context.Context, key *APIKey[C], opts ...Option) error

	// FindAPIKeyByHash retrieves an API key by its hash.
	FindAPIKeyByHash(ctx context.Context, tokenHash string, opts ...Option) (*APIKey[C], error)
}
