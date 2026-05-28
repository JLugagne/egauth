package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/libauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockStore is a functional mock of the tokens.Store interface.
type MockStore[C any] struct {
	SaveRefreshTokenFunc       func(ctx context.Context, tokenHash string, userID uuid.UUID, expiresAt time.Time, opts ...tokens.Option) error
	FindRefreshTokenByHashFunc func(ctx context.Context, tokenHash string, opts ...tokens.Option) (uuid.UUID, time.Time, error)
	RevokeRefreshTokenFunc     func(ctx context.Context, tokenHash string, opts ...tokens.Option) error
	SaveAPIKeyFunc             func(ctx context.Context, key *tokens.APIKey[C], opts ...tokens.Option) error
	FindAPIKeyByHashFunc       func(ctx context.Context, tokenHash string, opts ...tokens.Option) (*tokens.APIKey[C], error)
}

func (m *MockStore[C]) SaveRefreshToken(ctx context.Context, tokenHash string, userID uuid.UUID, expiresAt time.Time, opts ...tokens.Option) error {
	if m.SaveRefreshTokenFunc == nil {
		panic("called not defined SaveRefreshTokenFunc")
	}
	return m.SaveRefreshTokenFunc(ctx, tokenHash, userID, expiresAt, opts...)
}

func (m *MockStore[C]) FindRefreshTokenByHash(ctx context.Context, tokenHash string, opts ...tokens.Option) (uuid.UUID, time.Time, error) {
	if m.FindRefreshTokenByHashFunc == nil {
		panic("called not defined FindRefreshTokenByHashFunc")
	}
	return m.FindRefreshTokenByHashFunc(ctx, tokenHash, opts...)
}

func (m *MockStore[C]) RevokeRefreshToken(ctx context.Context, tokenHash string, opts ...tokens.Option) error {
	if m.RevokeRefreshTokenFunc == nil {
		panic("called not defined RevokeRefreshTokenFunc")
	}
	return m.RevokeRefreshTokenFunc(ctx, tokenHash, opts...)
}

func (m *MockStore[C]) SaveAPIKey(ctx context.Context, key *tokens.APIKey[C], opts ...tokens.Option) error {
	if m.SaveAPIKeyFunc == nil {
		panic("called not defined SaveAPIKeyFunc")
	}
	return m.SaveAPIKeyFunc(ctx, key, opts...)
}

func (m *MockStore[C]) FindAPIKeyByHash(ctx context.Context, tokenHash string, opts ...tokens.Option) (*tokens.APIKey[C], error) {
	if m.FindAPIKeyByHashFunc == nil {
		panic("called not defined FindAPIKeyByHashFunc")
	}
	return m.FindAPIKeyByHashFunc(ctx, tokenHash, opts...)
}

// StoreContractTesting runs a comprehensive suite of tests against any tokens.Store implementation.
func StoreContractTesting[C any](t *testing.T, store tokens.Store[C], useMultiTenant bool, customClaim C) {
	ctx := context.Background()

	var tenantA, tenantB string
	if useMultiTenant {
		tenantA = "tenant-A"
		tenantB = "tenant-B"
	}

	t.Run("Contract: Refresh Tokens", func(t *testing.T) {
		tokenHash := "refresh_token_hash"
		userID := uuid.New()
		expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)

		err := store.SaveRefreshToken(ctx, tokenHash, userID, expiresAt, tokens.WithTenant(tenantA))
		require.NoError(t, err)

		// Find
		fUserID, fExpiresAt, err := store.FindRefreshTokenByHash(ctx, tokenHash, tokens.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, userID, fUserID)
		assert.WithinDuration(t, expiresAt, fExpiresAt, time.Second)

		// Revoke
		err = store.RevokeRefreshToken(ctx, tokenHash, tokens.WithTenant(tenantA))
		require.NoError(t, err)

		_, _, err = store.FindRefreshTokenByHash(ctx, tokenHash, tokens.WithTenant(tenantA))
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)
	})

	t.Run("Contract: API Keys", func(t *testing.T) {
		tokenHash := "api_key_hash"
		key := &tokens.APIKey[C]{
			ID:       uuid.New(),
			TenantID: tenantA,
			Prefix:   "pk_",
			Hash:     tokenHash,
			Claims: tokens.Claims[C]{
				Subject: uuid.New(),
				Custom:  customClaim,
			},
		}

		err := store.SaveAPIKey(ctx, key, tokens.WithTenant(tenantA))
		require.NoError(t, err)

		// Find By Hash
		found, err := store.FindAPIKeyByHash(ctx, tokenHash, tokens.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, key.ID, found.ID)
		assert.Equal(t, key.Claims.Subject, found.Claims.Subject)
		assert.Empty(t, found.Token, "SECURITY: Clear-text token should never be persisted")

		// Find non-existent
		_, err = store.FindAPIKeyByHash(ctx, "non_existent", tokens.WithTenant(tenantA))
		assert.ErrorIs(t, err, tokens.ErrAPIKeyNotFound)
	})

	if useMultiTenant {
		t.Run("Contract: Multi-Tenant Isolation", func(t *testing.T) {
			sharedHash := "shared_hash"
			userID := uuid.New()
			expiresAt := time.Now().Add(time.Hour)

			// Save Refresh Token in Tenant A
			err := store.SaveRefreshToken(ctx, sharedHash, userID, expiresAt, tokens.WithTenant(tenantA))
			require.NoError(t, err)

			// Try to find from Tenant B
			_, _, err = store.FindRefreshTokenByHash(ctx, sharedHash, tokens.WithTenant(tenantB))
			assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

			// Try to revoke from Tenant B
			err = store.RevokeRefreshToken(ctx, sharedHash, tokens.WithTenant(tenantB))
			assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

			// Save API Key in Tenant A
			keyA := &tokens.APIKey[C]{
				ID:       uuid.New(),
				TenantID: tenantA,
				Hash:     "api_shared",
			}
			err = store.SaveAPIKey(ctx, keyA, tokens.WithTenant(tenantA))
			require.NoError(t, err)

			// Try to find from Tenant B
			_, err = store.FindAPIKeyByHash(ctx, "api_shared", tokens.WithTenant(tenantB))
			assert.ErrorIs(t, err, tokens.ErrAPIKeyNotFound)
		})
	}
}
