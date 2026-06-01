package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockStore is a functional mock of the tokens.Store interface.
type MockStore[C any] struct {
	SaveRefreshTokenFunc    func(ctx context.Context, tenantID string, rt *tokens.RefreshToken) error
	FindRefreshTokenFunc    func(ctx context.Context, tenantID string, tokenHash string) (*tokens.RefreshToken, error)
	ConsumeRefreshTokenFunc func(ctx context.Context, tenantID string, tokenHash string) error
	RevokeRefreshTokenFunc  func(ctx context.Context, tenantID string, tokenHash string) error
	RevokeFamilyFunc        func(ctx context.Context, tenantID string, familyID uuid.UUID) error
	SaveAPIKeyFunc          func(ctx context.Context, tenantID string, key *tokens.APIKey[C]) error
	FindAPIKeyByHashFunc    func(ctx context.Context, tenantID string, tokenHash string) (*tokens.APIKey[C], error)
	DeleteExpiredFunc       func(ctx context.Context, tenantID string) (int64, error)
}

func (m *MockStore[C]) SaveRefreshToken(ctx context.Context, tenantID string, rt *tokens.RefreshToken) error {
	if m.SaveRefreshTokenFunc == nil {
		panic("called not defined SaveRefreshTokenFunc")
	}
	return m.SaveRefreshTokenFunc(ctx, tenantID, rt)
}

func (m *MockStore[C]) FindRefreshToken(ctx context.Context, tenantID string, tokenHash string) (*tokens.RefreshToken, error) {
	if m.FindRefreshTokenFunc == nil {
		panic("called not defined FindRefreshTokenFunc")
	}
	return m.FindRefreshTokenFunc(ctx, tenantID, tokenHash)
}

func (m *MockStore[C]) ConsumeRefreshToken(ctx context.Context, tenantID string, tokenHash string) error {
	if m.ConsumeRefreshTokenFunc == nil {
		panic("called not defined ConsumeRefreshTokenFunc")
	}
	return m.ConsumeRefreshTokenFunc(ctx, tenantID, tokenHash)
}

func (m *MockStore[C]) RevokeRefreshToken(ctx context.Context, tenantID string, tokenHash string) error {
	if m.RevokeRefreshTokenFunc == nil {
		panic("called not defined RevokeRefreshTokenFunc")
	}
	return m.RevokeRefreshTokenFunc(ctx, tenantID, tokenHash)
}

func (m *MockStore[C]) RevokeFamily(ctx context.Context, tenantID string, familyID uuid.UUID) error {
	if m.RevokeFamilyFunc == nil {
		panic("called not defined RevokeFamilyFunc")
	}
	return m.RevokeFamilyFunc(ctx, tenantID, familyID)
}

func (m *MockStore[C]) SaveAPIKey(ctx context.Context, tenantID string, key *tokens.APIKey[C]) error {
	if m.SaveAPIKeyFunc == nil {
		panic("called not defined SaveAPIKeyFunc")
	}
	return m.SaveAPIKeyFunc(ctx, tenantID, key)
}

func (m *MockStore[C]) FindAPIKeyByHash(ctx context.Context, tenantID string, tokenHash string) (*tokens.APIKey[C], error) {
	if m.FindAPIKeyByHashFunc == nil {
		panic("called not defined FindAPIKeyByHashFunc")
	}
	return m.FindAPIKeyByHashFunc(ctx, tenantID, tokenHash)
}

func (m *MockStore[C]) DeleteExpired(ctx context.Context, tenantID string) (int64, error) {
	if m.DeleteExpiredFunc == nil {
		panic("called not defined DeleteExpiredFunc")
	}
	return m.DeleteExpiredFunc(ctx, tenantID)
}

var _ tokens.Store[any] = (*MockStore[any])(nil)

// StoreContractTesting runs a comprehensive suite of tests against any tokens.Store implementation.
func StoreContractTesting[C any](t *testing.T, store tokens.Store[C], useMultiTenant bool, customClaim C) {
	ctx := context.Background()

	var tenantA, tenantB string
	if useMultiTenant {
		tenantA = "tenant-A"
		tenantB = "tenant-B"
	}

	t.Run("Contract: DeleteExpired purges only expired records", func(t *testing.T) {
		userID := uuid.New()
		// An expired refresh token and a live one.
		expired := &tokens.RefreshToken{
			Hash: "reaper-expired", FamilyID: uuid.New(), UserID: userID, TenantID: tenantA,
			ExpiresAt: time.Now().Add(-time.Hour), CreatedAt: time.Now().Add(-2 * time.Hour),
		}
		live := &tokens.RefreshToken{
			Hash: "reaper-live", FamilyID: uuid.New(), UserID: userID, TenantID: tenantA,
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}
		// A consumed-but-not-yet-expired token must be KEPT (needed for reuse detection).
		consumedAt := time.Now().Add(-time.Minute)
		consumedLive := &tokens.RefreshToken{
			Hash: "reaper-consumed-live", FamilyID: uuid.New(), UserID: userID, TenantID: tenantA,
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now().Add(-time.Hour), ConsumedAt: &consumedAt,
		}
		require.NoError(t, store.SaveRefreshToken(ctx, tenantA, expired))
		require.NoError(t, store.SaveRefreshToken(ctx, tenantA, live))
		require.NoError(t, store.SaveRefreshToken(ctx, tenantA, consumedLive))

		n, err := store.DeleteExpired(ctx, tenantA)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, n, int64(1), "the expired token must be counted")

		_, err = store.FindRefreshToken(ctx, tenantA, "reaper-expired")
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound, "expired token must be gone")

		_, err = store.FindRefreshToken(ctx, tenantA, "reaper-live")
		assert.NoError(t, err, "live token must be kept")

		got, err := store.FindRefreshToken(ctx, tenantA, "reaper-consumed-live")
		require.NoError(t, err, "consumed-but-not-expired token must be kept for reuse detection")
		assert.NotNil(t, got.ConsumedAt)

		// Documented behavior: a consumed token that is ALSO past its expiry IS reaped (it can no
		// longer be rotated, so only the late post-expiry replay alarm is given up — see the
		// DeleteExpired doc). This keeps the GC bounded for long-lived rotating sessions.
		consumedExpiredAt := time.Now().Add(-30 * time.Minute)
		consumedExpired := &tokens.RefreshToken{
			Hash: "reaper-consumed-expired", FamilyID: uuid.New(), UserID: userID, TenantID: tenantA,
			ExpiresAt: time.Now().Add(-time.Hour), CreatedAt: time.Now().Add(-2 * time.Hour), ConsumedAt: &consumedExpiredAt,
		}
		require.NoError(t, store.SaveRefreshToken(ctx, tenantA, consumedExpired))
		_, err = store.DeleteExpired(ctx, tenantA)
		require.NoError(t, err)
		_, err = store.FindRefreshToken(ctx, tenantA, "reaper-consumed-expired")
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound, "a consumed-AND-expired token is reaped")
	})

	t.Run("Contract: Refresh Tokens save/find/consume/revoke", func(t *testing.T) {
		tokenHash := "refresh_token_hash"
		userID := uuid.New()
		familyID := uuid.New()
		expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
		authTime := time.Now().Add(-10 * time.Minute).Truncate(time.Second)

		rt := &tokens.RefreshToken{
			Hash:      tokenHash,
			FamilyID:  familyID,
			UserID:    userID,
			TenantID:  tenantA,
			AuthTime:  authTime,
			ExpiresAt: expiresAt,
			CreatedAt: time.Now().Truncate(time.Second),
		}
		err := store.SaveRefreshToken(ctx, tenantA, rt)
		require.NoError(t, err)

		// Find returns the full record, not yet consumed.
		found, err := store.FindRefreshToken(ctx, tenantA, tokenHash)
		require.NoError(t, err)
		assert.Equal(t, userID, found.UserID)
		assert.Equal(t, familyID, found.FamilyID)
		assert.WithinDuration(t, expiresAt, found.ExpiresAt, time.Second)
		assert.WithinDuration(t, authTime, found.AuthTime, time.Second, "auth_time must round-trip (step-up freshness)")
		assert.Nil(t, found.ConsumedAt, "freshly saved token must not be consumed")

		// Consume once succeeds.
		err = store.ConsumeRefreshToken(ctx, tenantA, tokenHash)
		require.NoError(t, err)

		// Find after consume still returns the record, now with ConsumedAt set.
		found, err = store.FindRefreshToken(ctx, tenantA, tokenHash)
		require.NoError(t, err)
		require.NotNil(t, found.ConsumedAt, "consumed token must report ConsumedAt")

		// Consuming again is a replay -> ErrRefreshTokenReused.
		err = store.ConsumeRefreshToken(ctx, tenantA, tokenHash)
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenReused)

		// Consuming a non-existent token -> ErrRefreshTokenNotFound.
		err = store.ConsumeRefreshToken(ctx, tenantA, "does_not_exist")
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

		// Revoke single token.
		err = store.RevokeRefreshToken(ctx, tenantA, tokenHash)
		require.NoError(t, err)

		_, err = store.FindRefreshToken(ctx, tenantA, tokenHash)
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

		// Revoking a missing token -> ErrRefreshTokenNotFound.
		err = store.RevokeRefreshToken(ctx, tenantA, tokenHash)
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)
	})

	t.Run("Contract: SaveRefreshToken rejects a record whose tenant differs from the argument", func(t *testing.T) {
		rt := &tokens.RefreshToken{
			Hash: "mismatch-rt", FamilyID: uuid.New(), UserID: uuid.New(), TenantID: "tenant-on-record",
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}
		err := store.SaveRefreshToken(ctx, "different-tenant", rt)
		assert.ErrorIs(t, err, tokens.ErrTenantMismatch, "record tenant != argument must be rejected")

		key := &tokens.APIKey[C]{
			ID: uuid.New(), TenantID: "tenant-on-record", Hash: "mismatch-key",
			Claims: tokens.Claims[C]{Subject: uuid.New(), Custom: customClaim},
		}
		err = store.SaveAPIKey(ctx, "different-tenant", key)
		assert.ErrorIs(t, err, tokens.ErrTenantMismatch, "API key record tenant != argument must be rejected")
	})

	t.Run("Contract: RevokeFamily", func(t *testing.T) {
		familyID := uuid.New()
		otherFamilyID := uuid.New()
		userID := uuid.New()
		expiresAt := time.Now().Add(time.Hour)

		// Two tokens in the target family.
		for i, h := range []string{"fam_a_1", "fam_a_2"} {
			rt := &tokens.RefreshToken{
				Hash:      h,
				FamilyID:  familyID,
				UserID:    userID,
				TenantID:  tenantA,
				ExpiresAt: expiresAt.Add(time.Duration(i) * time.Minute),
				CreatedAt: time.Now(),
			}
			require.NoError(t, store.SaveRefreshToken(ctx, tenantA, rt))
		}

		// One token in another family that must survive.
		survivor := &tokens.RefreshToken{
			Hash:      "fam_b_1",
			FamilyID:  otherFamilyID,
			UserID:    userID,
			TenantID:  tenantA,
			ExpiresAt: expiresAt,
			CreatedAt: time.Now(),
		}
		require.NoError(t, store.SaveRefreshToken(ctx, tenantA, survivor))

		// Revoke the whole family.
		err := store.RevokeFamily(ctx, tenantA, familyID)
		require.NoError(t, err)

		_, err = store.FindRefreshToken(ctx, tenantA, "fam_a_1")
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)
		_, err = store.FindRefreshToken(ctx, tenantA, "fam_a_2")
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

		// Other family untouched.
		_, err = store.FindRefreshToken(ctx, tenantA, "fam_b_1")
		assert.NoError(t, err)

		// Revoking an empty family is not an error.
		err = store.RevokeFamily(ctx, tenantA, uuid.New())
		assert.NoError(t, err)
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

		err := store.SaveAPIKey(ctx, tenantA, key)
		require.NoError(t, err)

		// Find By Hash
		found, err := store.FindAPIKeyByHash(ctx, tenantA, tokenHash)
		require.NoError(t, err)
		assert.Equal(t, key.ID, found.ID)
		assert.Equal(t, key.Claims.Subject, found.Claims.Subject)
		assert.Empty(t, found.Token, "SECURITY: Clear-text token should never be persisted")

		// Find non-existent
		_, err = store.FindAPIKeyByHash(ctx, tenantA, "non_existent")
		assert.ErrorIs(t, err, tokens.ErrAPIKeyNotFound)
	})

	if useMultiTenant {
		t.Run("Contract: Multi-Tenant Isolation", func(t *testing.T) {
			sharedHash := "shared_hash"
			userID := uuid.New()
			familyID := uuid.New()
			expiresAt := time.Now().Add(time.Hour)

			rt := &tokens.RefreshToken{
				Hash:      sharedHash,
				FamilyID:  familyID,
				UserID:    userID,
				TenantID:  tenantA,
				ExpiresAt: expiresAt,
				CreatedAt: time.Now(),
			}
			require.NoError(t, store.SaveRefreshToken(ctx, tenantA, rt))

			// Tenant B cannot find it.
			_, err := store.FindRefreshToken(ctx, tenantB, sharedHash)
			assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

			// Tenant B cannot consume it (treated as not found).
			err = store.ConsumeRefreshToken(ctx, tenantB, sharedHash)
			assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

			// Tenant B cannot revoke it.
			err = store.RevokeRefreshToken(ctx, tenantB, sharedHash)
			assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

			// Tenant B revoking the family does not remove Tenant A's token.
			err = store.RevokeFamily(ctx, tenantB, familyID)
			require.NoError(t, err)
			_, err = store.FindRefreshToken(ctx, tenantA, sharedHash)
			assert.NoError(t, err, "Tenant A's token must survive Tenant B's family revoke")

			// API key isolation.
			keyA := &tokens.APIKey[C]{
				ID:       uuid.New(),
				TenantID: tenantA,
				Hash:     "api_shared",
			}
			err = store.SaveAPIKey(ctx, tenantA, keyA)
			require.NoError(t, err)

			_, err = store.FindAPIKeyByHash(ctx, tenantB, "api_shared")
			assert.ErrorIs(t, err, tokens.ErrAPIKeyNotFound)
		})
	}
}
