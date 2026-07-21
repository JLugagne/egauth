package issuertest

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockIssuer is a function-based mock implementation of the tokens.Issuer interface.
type MockIssuer[C any] struct {
	IssueTokenPairFunc func(ctx context.Context, claims tokens.Claims[C]) (*tokens.TokenPair[C], error)
	IssueAPIKeyFunc    func(ctx context.Context, prefix string, keyType tokens.KeyType, createdBy uuid.UUID, claims tokens.Claims[C]) (*tokens.APIKey[C], error)
}

func (m *MockIssuer[C]) IssueTokenPair(ctx context.Context, claims tokens.Claims[C]) (*tokens.TokenPair[C], error) {
	if m.IssueTokenPairFunc == nil {
		panic("called not defined IssueTokenPairFunc")
	}
	return m.IssueTokenPairFunc(ctx, claims)
}

func (m *MockIssuer[C]) IssueAPIKey(ctx context.Context, prefix string, keyType tokens.KeyType, createdBy uuid.UUID, claims tokens.Claims[C]) (*tokens.APIKey[C], error) {
	if m.IssueAPIKeyFunc == nil {
		panic("called not defined IssueAPIKeyFunc")
	}
	return m.IssueAPIKeyFunc(ctx, prefix, keyType, createdBy, claims)
}

// MockRotator is a function-based mock implementation of the tokens.Rotator interface.
type MockRotator[C any] struct {
	RotateFunc func(ctx context.Context, tenantID string, refreshToken string) (*tokens.TokenPair[C], error)
}

func (m *MockRotator[C]) Rotate(ctx context.Context, tenantID string, refreshToken string) (*tokens.TokenPair[C], error) {
	if m.RotateFunc == nil {
		panic("called not defined RotateFunc")
	}
	return m.RotateFunc(ctx, tenantID, refreshToken)
}

// MockVerifier is a function-based mock implementation of the tokens.Verifier interface.
type MockVerifier[C any] struct {
	VerifyAccessTokenForTenantFunc func(ctx context.Context, tenantID string, token string) (*tokens.Claims[C], error)
	VerifyRefreshTokenFunc         func(ctx context.Context, tenantID string, token string) (*tokens.Claims[C], error)
	VerifyAPIKeyFunc               func(ctx context.Context, tenantID string, key string) (*tokens.Claims[C], error)
}

func (m *MockVerifier[C]) VerifyRefreshToken(ctx context.Context, tenantID string, token string) (*tokens.Claims[C], error) {
	if m.VerifyRefreshTokenFunc == nil {
		panic("called not defined VerifyRefreshTokenFunc")
	}
	return m.VerifyRefreshTokenFunc(ctx, tenantID, token)
}

func (m *MockVerifier[C]) VerifyAPIKey(ctx context.Context, tenantID string, key string, _ ...event.RequestContext) (*tokens.Claims[C], error) {
	if m.VerifyAPIKeyFunc == nil {
		panic("called not defined VerifyAPIKeyFunc")
	}
	return m.VerifyAPIKeyFunc(ctx, tenantID, key)
}

// IssuerVerifierContractTesting runs all contract tests for tokens.Issuer and tokens.Verifier implementations.
func IssuerVerifierContractTesting[C any](t *testing.T, issuer tokens.Issuer[C], verifier tokens.Verifier[C], customClaim C) {
	ctx := context.Background()

	t.Run("Contract: Issue and Verify TokenPair", func(t *testing.T) {
		claims := tokens.Claims[C]{
			Subject:   uuid.Must(uuid.NewV7()),
			TenantID:  "tenant-123",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			Custom:    customClaim,
		}

		pair, err := issuer.IssueTokenPair(ctx, claims)
		require.NoError(t, err, "IssueTokenPair should succeed")
		require.NotNil(t, pair, "TokenPair must not be nil")
		require.NotEmpty(t, pair.AccessToken, "AccessToken must not be empty")

		verifiedClaims, err := verifier.VerifyAccessTokenForTenant(ctx, "tenant-123", pair.AccessToken)
		require.NoError(t, err, "VerifyAccessTokenForTenant should succeed for a valid token")
		require.NotNil(t, verifiedClaims, "Verified claims must not be nil")
		assert.Equal(t, claims.Subject, verifiedClaims.Subject, "Subject should match")
		assert.Equal(t, claims.TenantID, verifiedClaims.TenantID, "TenantID should match")

		// Verify Refresh Token under the SAME (non-empty) tenant it was saved with: the
		// store lookup is tenant-scoped, so the matching tenantID is what resolves it. (The
		// cross-tenant fail-closed guarantee is proven separately against a tenant-
		// partitioning store; a non-partitioning test double cannot exhibit it.)
		refClaims, err := verifier.VerifyRefreshToken(ctx, claims.TenantID, pair.RefreshToken)
		require.NoError(t, err)
		assert.Equal(t, claims.Subject, refClaims.Subject)
	})

	t.Run("Contract: Issue and Verify API Key", func(t *testing.T) {
		userID := uuid.Must(uuid.NewV7())
		claims := tokens.Claims[C]{
			Subject:  userID,
			TenantID: "tenant-123",
			Custom:   customClaim,
		}

		// Issue a PAT: it acts as its creator, so createdBy and Subject are the same user.
		apiKey, err := issuer.IssueAPIKey(ctx, "sk_test_", tokens.KeyTypePAT, userID, claims)
		require.NoError(t, err, "IssueAPIKey should succeed")
		require.NotNil(t, apiKey, "APIKey must not be nil")
		assert.True(t, len(apiKey.Token) > len("sk_test_"), "Token should be longer than the prefix")
		assert.NotEmpty(t, apiKey.Hash, "Hash must not be empty")
		assert.Equal(t, tokens.KeyTypePAT, apiKey.Type, "PAT type should be recorded on the key")
		assert.Equal(t, userID, apiKey.CreatedBy, "creator should be recorded on the key")
		assert.Equal(t, userID, apiKey.Claims.Subject, "a PAT's subject is the creating user")

		// Verify API Key under the SAME (non-empty) tenant it was saved with: the store
		// lookup is tenant-scoped, so the matching tenantID is what resolves it. (The
		// cross-tenant fail-closed guarantee is proven separately against a tenant-
		// partitioning store; a non-partitioning test double cannot exhibit it.)
		verifiedClaims, err := verifier.VerifyAPIKey(ctx, claims.TenantID, apiKey.Token)
		require.NoError(t, err)
		assert.Equal(t, claims.Subject, verifiedClaims.Subject)
		// For API Keys, if the store is tenant-aware, it should return the tenant
		if claims.TenantID != "" {
			assert.Equal(t, claims.TenantID, verifiedClaims.TenantID)
		}
	})
}

func (m *MockVerifier[C]) VerifyAccessTokenForTenant(ctx context.Context, tenantID string, token string) (*tokens.Claims[C], error) {
	if m.VerifyAccessTokenForTenantFunc == nil {
		panic("called not defined VerifyAccessTokenForTenantFunc")
	}
	return m.VerifyAccessTokenForTenantFunc(ctx, tenantID, token)
}
