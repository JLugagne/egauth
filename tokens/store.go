package tokens

import (
	"context"

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
	// SaveRefreshToken persists a refresh token record (storing only its hash).
	SaveRefreshToken(ctx context.Context, rt *RefreshToken, opts ...Option) error

	// FindRefreshToken retrieves a refresh token by its hash, including its ConsumedAt state.
	FindRefreshToken(ctx context.Context, tokenHash string, opts ...Option) (*RefreshToken, error)

	// ConsumeRefreshToken atomically marks a refresh token as consumed (single-use).
	// It returns ErrRefreshTokenNotFound if the token does not exist (in the tenant),
	// and ErrRefreshTokenReused if it exists but was already consumed (replay detection).
	ConsumeRefreshToken(ctx context.Context, tokenHash string, opts ...Option) error

	// RevokeRefreshToken deletes/revokes a single refresh token by its hash.
	RevokeRefreshToken(ctx context.Context, tokenHash string, opts ...Option) error

	// RevokeFamily revokes ALL refresh tokens sharing the given family ID.
	RevokeFamily(ctx context.Context, familyID uuid.UUID, opts ...Option) error

	// SaveAPIKey persists an API key.
	SaveAPIKey(ctx context.Context, key *APIKey[C], opts ...Option) error

	// FindAPIKeyByHash retrieves an API key by its hash.
	FindAPIKeyByHash(ctx context.Context, tokenHash string, opts ...Option) (*APIKey[C], error)
}
