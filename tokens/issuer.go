package tokens

import (
	"context"
)

// Issuer is responsible for generating tokens and API keys.
type Issuer[C any] interface {
	// IssueTokenPair generates a new Access and Refresh token pair for the given claims.
	IssueTokenPair(ctx context.Context, claims Claims[C]) (*TokenPair[C], error)

	// IssueAPIKey generates a new API Key with the specified prefix and claims.
	IssueAPIKey(ctx context.Context, prefix string, claims Claims[C]) (*APIKey[C], error)
}

// Verifier is responsible for validating tokens and extracting their claims.
type Verifier[C any] interface {
	// VerifyAccessToken parses and validates an access token, returning its claims.
	//
	// Deprecated: this entry point performs NO tenant binding. In a multi-tenant
	// deployment served by a single shared signing key it cannot tell tenant A's token
	// apart from tenant B's, and a Verifier configured for multi-tenancy fails it closed.
	// Use VerifyAccessTokenForTenant, which binds the token to an explicit tenant and
	// fails closed on a mismatch. It remains valid for genuinely single-tenant callers,
	// where every token is issued under the empty tenant.
	VerifyAccessToken(ctx context.Context, token string) (*Claims[C], error)

	// VerifyAccessTokenForTenant parses and validates an access token and binds it to
	// tenantID, failing closed with ErrTenantMismatch unless the token's signed tenant_id
	// claim equals tenantID. This is the tenant-aware entry point multi-tenant callers
	// (and the HTTP middleware, once a tenant resolver is configured) MUST use so a token
	// minted for one tenant cannot be replayed in another under a shared signing key.
	// Single-tenant callers pass "" (the default partition), which is equivalent to
	// VerifyAccessToken for tokens issued under the empty tenant.
	VerifyAccessTokenForTenant(ctx context.Context, tenantID string, token string) (*Claims[C], error)

	// VerifyRefreshToken validates a refresh token against the store and returns its claims.
	// tenantID scopes the store lookup: the token is resolved only within that tenant's
	// partition, so a token saved under a real tenant must be verified with the matching
	// tenantID. Single-tenant callers pass "" (the default partition).
	VerifyRefreshToken(ctx context.Context, tenantID string, token string) (*Claims[C], error)

	// VerifyAPIKey validates an API key against the store and returns its claims.
	// tenantID scopes the store lookup: the key is resolved only within that tenant's
	// partition, so a key saved under a real tenant must be verified with the matching
	// tenantID. Single-tenant callers pass "" (the default partition).
	VerifyAPIKey(ctx context.Context, tenantID string, key string) (*Claims[C], error)
}
