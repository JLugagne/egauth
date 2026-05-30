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

	// DeleteExpired purges expired records (refresh tokens and any API keys past their expiry),
	// returning the number deleted. It is the schedulable GC reaper: refresh-token rows are
	// retained past consumption for reuse/theft detection, so they accumulate and must be swept
	// once expired. API keys with no expiry are never touched. With WithTenant it sweeps a single
	// tenant; without it, all tenants. Run it periodically (e.g. hourly) from a background job.
	//
	// Reaping only removes rows past their expiry, so an expired token can no longer be validated
	// or rotated and a replay WITHIN a token's validity is still detected as reuse (the family is
	// revoked). The one thing given up is the late alarm: a replay of an ALREADY-EXPIRED consumed
	// token reports not-found rather than revoking the family — acceptable, since by then the
	// token grants no access. Keeping consumed rows until their whole family expired would defeat
	// the GC for long-lived, continuously-rotating sessions, so the reaper trades that late
	// signal for bounded growth.
	DeleteExpired(ctx context.Context, opts ...Option) (int64, error)
}
