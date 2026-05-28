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
	VerifyAccessToken(ctx context.Context, token string) (*Claims[C], error)

	// VerifyRefreshToken validates a refresh token against the store and returns its claims.
	VerifyRefreshToken(ctx context.Context, token string) (*Claims[C], error)

	// VerifyAPIKey validates an API key against the store and returns its claims.
	VerifyAPIKey(ctx context.Context, key string) (*Claims[C], error)
}
