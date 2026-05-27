package issuertest

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/libauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockIssuer is a function-based mock implementation of the tokens.Issuer interface.
type MockIssuer[C any] struct {
	IssueTokenPairFunc func(ctx context.Context, claims tokens.Claims[C]) (*tokens.TokenPair[C], error)
	IssueAPIKeyFunc    func(ctx context.Context, prefix string, claims tokens.Claims[C]) (*tokens.APIKey[C], error)
}

func (m *MockIssuer[C]) IssueTokenPair(ctx context.Context, claims tokens.Claims[C]) (*tokens.TokenPair[C], error) {
	if m.IssueTokenPairFunc == nil {
		panic("called not defined IssueTokenPairFunc")
	}
	return m.IssueTokenPairFunc(ctx, claims)
}

func (m *MockIssuer[C]) IssueAPIKey(ctx context.Context, prefix string, claims tokens.Claims[C]) (*tokens.APIKey[C], error) {
	if m.IssueAPIKeyFunc == nil {
		panic("called not defined IssueAPIKeyFunc")
	}
	return m.IssueAPIKeyFunc(ctx, prefix, claims)
}

// MockVerifier is a function-based mock implementation of the tokens.Verifier interface.
type MockVerifier[C any] struct {
	VerifyAccessTokenFunc func(ctx context.Context, token string) (*tokens.Claims[C], error)
}

func (m *MockVerifier[C]) VerifyAccessToken(ctx context.Context, token string) (*tokens.Claims[C], error) {
	if m.VerifyAccessTokenFunc == nil {
		panic("called not defined VerifyAccessTokenFunc")
	}
	return m.VerifyAccessTokenFunc(ctx, token)
}

// IssuerVerifierContractTesting runs all contract tests for tokens.Issuer and tokens.Verifier implementations.
func IssuerVerifierContractTesting[C any](t *testing.T, issuer tokens.Issuer[C], verifier tokens.Verifier[C], customClaim C) {
	ctx := context.Background()

	t.Run("Contract: Issue and Verify TokenPair", func(t *testing.T) {
		claims := tokens.Claims[C]{
			Subject:   uuid.New(),
			TenantID:  "tenant-123",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			Custom:    customClaim,
		}

		pair, err := issuer.IssueTokenPair(ctx, claims)
		require.NoError(t, err, "IssueTokenPair should succeed")
		require.NotNil(t, pair, "TokenPair must not be nil")
		require.NotEmpty(t, pair.AccessToken, "AccessToken must not be empty")

		verifiedClaims, err := verifier.VerifyAccessToken(ctx, pair.AccessToken)
		require.NoError(t, err, "VerifyAccessToken should succeed for a valid token")
		require.NotNil(t, verifiedClaims, "Verified claims must not be nil")
		assert.Equal(t, claims.Subject, verifiedClaims.Subject, "Subject should match")
		assert.Equal(t, claims.TenantID, verifiedClaims.TenantID, "TenantID should match")
	})

	t.Run("Contract: Issue API Key", func(t *testing.T) {
		claims := tokens.Claims[C]{
			Subject:  uuid.New(),
			TenantID: "tenant-123",
			Custom:   customClaim,
		}

		apiKey, err := issuer.IssueAPIKey(ctx, "sk_test_", claims)
		require.NoError(t, err, "IssueAPIKey should succeed")
		require.NotNil(t, apiKey, "APIKey must not be nil")
		assert.True(t, len(apiKey.Token) > len("sk_test_"), "Token should be longer than the prefix")
		assert.NotEmpty(t, apiKey.Hash, "Hash must not be empty")
	})
}
