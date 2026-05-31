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
	SaveRefreshTokenFunc    func(ctx context.Context, rt *tokens.RefreshToken, opts ...tokens.Option) error
	FindRefreshTokenFunc    func(ctx context.Context, tokenHash string, opts ...tokens.Option) (*tokens.RefreshToken, error)
	ConsumeRefreshTokenFunc func(ctx context.Context, tokenHash string, opts ...tokens.Option) error
	RevokeRefreshTokenFunc  func(ctx context.Context, tokenHash string, opts ...tokens.Option) error
	RevokeFamilyFunc        func(ctx context.Context, familyID uuid.UUID, opts ...tokens.Option) error
	SaveAPIKeyFunc          func(ctx context.Context, key *tokens.APIKey[C], opts ...tokens.Option) error
	FindAPIKeyByHashFunc    func(ctx context.Context, tokenHash string, opts ...tokens.Option) (*tokens.APIKey[C], error)
	DeleteExpiredFunc       func(ctx context.Context, opts ...tokens.Option) (int64, error)
}

func (m *MockStore[C]) SaveRefreshToken(ctx context.Context, rt *tokens.RefreshToken, opts ...tokens.Option) error {
	if m.SaveRefreshTokenFunc == nil {
		panic("called not defined SaveRefreshTokenFunc")
	}
	return m.SaveRefreshTokenFunc(ctx, rt, opts...)
}

func (m *MockStore[C]) FindRefreshToken(ctx context.Context, tokenHash string, opts ...tokens.Option) (*tokens.RefreshToken, error) {
	if m.FindRefreshTokenFunc == nil {
		panic("called not defined FindRefreshTokenFunc")
	}
	return m.FindRefreshTokenFunc(ctx, tokenHash, opts...)
}

func (m *MockStore[C]) ConsumeRefreshToken(ctx context.Context, tokenHash string, opts ...tokens.Option) error {
	if m.ConsumeRefreshTokenFunc == nil {
		panic("called not defined ConsumeRefreshTokenFunc")
	}
	return m.ConsumeRefreshTokenFunc(ctx, tokenHash, opts...)
}

func (m *MockStore[C]) RevokeRefreshToken(ctx context.Context, tokenHash string, opts ...tokens.Option) error {
	if m.RevokeRefreshTokenFunc == nil {
		panic("called not defined RevokeRefreshTokenFunc")
	}
	return m.RevokeRefreshTokenFunc(ctx, tokenHash, opts...)
}

func (m *MockStore[C]) RevokeFamily(ctx context.Context, familyID uuid.UUID, opts ...tokens.Option) error {
	if m.RevokeFamilyFunc == nil {
		panic("called not defined RevokeFamilyFunc")
	}
	return m.RevokeFamilyFunc(ctx, familyID, opts...)
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

func (m *MockStore[C]) DeleteExpired(ctx context.Context, opts ...tokens.Option) (int64, error) {
	if m.DeleteExpiredFunc == nil {
		panic("called not defined DeleteExpiredFunc")
	}
	return m.DeleteExpiredFunc(ctx, opts...)
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
		require.NoError(t, store.SaveRefreshToken(ctx, expired, tokens.WithTenant(tenantA)))
		require.NoError(t, store.SaveRefreshToken(ctx, live, tokens.WithTenant(tenantA)))
		require.NoError(t, store.SaveRefreshToken(ctx, consumedLive, tokens.WithTenant(tenantA)))

		n, err := store.DeleteExpired(ctx, tokens.WithTenant(tenantA))
		require.NoError(t, err)
		assert.GreaterOrEqual(t, n, int64(1), "the expired token must be counted")

		_, err = store.FindRefreshToken(ctx, "reaper-expired", tokens.WithTenant(tenantA))
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound, "expired token must be gone")

		_, err = store.FindRefreshToken(ctx, "reaper-live", tokens.WithTenant(tenantA))
		assert.NoError(t, err, "live token must be kept")

		got, err := store.FindRefreshToken(ctx, "reaper-consumed-live", tokens.WithTenant(tenantA))
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
		require.NoError(t, store.SaveRefreshToken(ctx, consumedExpired, tokens.WithTenant(tenantA)))
		_, err = store.DeleteExpired(ctx, tokens.WithTenant(tenantA))
		require.NoError(t, err)
		_, err = store.FindRefreshToken(ctx, "reaper-consumed-expired", tokens.WithTenant(tenantA))
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
		err := store.SaveRefreshToken(ctx, rt, tokens.WithTenant(tenantA))
		require.NoError(t, err)

		// Find returns the full record, not yet consumed.
		found, err := store.FindRefreshToken(ctx, tokenHash, tokens.WithTenant(tenantA))
		require.NoError(t, err)
		assert.Equal(t, userID, found.UserID)
		assert.Equal(t, familyID, found.FamilyID)
		assert.WithinDuration(t, expiresAt, found.ExpiresAt, time.Second)
		assert.WithinDuration(t, authTime, found.AuthTime, time.Second, "auth_time must round-trip (step-up freshness)")
		assert.Nil(t, found.ConsumedAt, "freshly saved token must not be consumed")

		// Consume once succeeds.
		err = store.ConsumeRefreshToken(ctx, tokenHash, tokens.WithTenant(tenantA))
		require.NoError(t, err)

		// Find after consume still returns the record, now with ConsumedAt set.
		found, err = store.FindRefreshToken(ctx, tokenHash, tokens.WithTenant(tenantA))
		require.NoError(t, err)
		require.NotNil(t, found.ConsumedAt, "consumed token must report ConsumedAt")

		// Consuming again is a replay -> ErrRefreshTokenReused.
		err = store.ConsumeRefreshToken(ctx, tokenHash, tokens.WithTenant(tenantA))
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenReused)

		// Consuming a non-existent token -> ErrRefreshTokenNotFound.
		err = store.ConsumeRefreshToken(ctx, "does_not_exist", tokens.WithTenant(tenantA))
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

		// Revoke single token.
		err = store.RevokeRefreshToken(ctx, tokenHash, tokens.WithTenant(tenantA))
		require.NoError(t, err)

		_, err = store.FindRefreshToken(ctx, tokenHash, tokens.WithTenant(tenantA))
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

		// Revoking a missing token -> ErrRefreshTokenNotFound.
		err = store.RevokeRefreshToken(ctx, tokenHash, tokens.WithTenant(tenantA))
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)
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
			require.NoError(t, store.SaveRefreshToken(ctx, rt, tokens.WithTenant(tenantA)))
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
		require.NoError(t, store.SaveRefreshToken(ctx, survivor, tokens.WithTenant(tenantA)))

		// Revoke the whole family.
		err := store.RevokeFamily(ctx, familyID, tokens.WithTenant(tenantA))
		require.NoError(t, err)

		_, err = store.FindRefreshToken(ctx, "fam_a_1", tokens.WithTenant(tenantA))
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)
		_, err = store.FindRefreshToken(ctx, "fam_a_2", tokens.WithTenant(tenantA))
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

		// Other family untouched.
		_, err = store.FindRefreshToken(ctx, "fam_b_1", tokens.WithTenant(tenantA))
		assert.NoError(t, err)

		// Revoking an empty family is not an error.
		err = store.RevokeFamily(ctx, uuid.New(), tokens.WithTenant(tenantA))
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
			require.NoError(t, store.SaveRefreshToken(ctx, rt, tokens.WithTenant(tenantA)))

			// Tenant B cannot find it.
			_, err := store.FindRefreshToken(ctx, sharedHash, tokens.WithTenant(tenantB))
			assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

			// Tenant B cannot consume it (treated as not found).
			err = store.ConsumeRefreshToken(ctx, sharedHash, tokens.WithTenant(tenantB))
			assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

			// Tenant B cannot revoke it.
			err = store.RevokeRefreshToken(ctx, sharedHash, tokens.WithTenant(tenantB))
			assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

			// Tenant B revoking the family does not remove Tenant A's token.
			err = store.RevokeFamily(ctx, familyID, tokens.WithTenant(tenantB))
			require.NoError(t, err)
			_, err = store.FindRefreshToken(ctx, sharedHash, tokens.WithTenant(tenantA))
			assert.NoError(t, err, "Tenant A's token must survive Tenant B's family revoke")

			// API key isolation.
			keyA := &tokens.APIKey[C]{
				ID:       uuid.New(),
				TenantID: tenantA,
				Hash:     "api_shared",
			}
			err = store.SaveAPIKey(ctx, keyA, tokens.WithTenant(tenantA))
			require.NoError(t, err)

			_, err = store.FindAPIKeyByHash(ctx, "api_shared", tokens.WithTenant(tenantB))
			assert.ErrorIs(t, err, tokens.ErrAPIKeyNotFound)
		})
	}
}

// StrictTenancyTesting asserts that a store built WithStrictTenancy rejects every tenant-scoped
// operation whose effective tenant is empty (no WithTenant and no tenant carried on the record)
// via tokens.ErrTenantRequired, and that the same operations succeed once a tenant is supplied.
// DeleteExpired is intentionally NOT asserted: it is an exempt maintenance sweep that spans all
// tenants when no tenant is given. Pass a store constructed WithStrictTenancy.
func StrictTenancyTesting[C any](t *testing.T, strict tokens.Store[C], customClaim C) {
	ctx := context.Background()
	fam := uuid.New()

	t.Run("strict: every tenant-scoped op rejects an empty tenant", func(t *testing.T) {
		// No WithTenant AND the record carries no tenant of its own -> rejected.
		rt := &tokens.RefreshToken{Hash: "strict-rt", FamilyID: fam, UserID: uuid.New(), ExpiresAt: time.Now().Add(time.Hour)}
		assert.ErrorIs(t, strict.SaveRefreshToken(ctx, rt), tokens.ErrTenantRequired, "SaveRefreshToken without a tenant must be rejected in strict mode")

		_, err := strict.FindRefreshToken(ctx, "strict-rt")
		assert.ErrorIs(t, err, tokens.ErrTenantRequired)

		assert.ErrorIs(t, strict.ConsumeRefreshToken(ctx, "strict-rt"), tokens.ErrTenantRequired)
		assert.ErrorIs(t, strict.RevokeRefreshToken(ctx, "strict-rt"), tokens.ErrTenantRequired)
		assert.ErrorIs(t, strict.RevokeFamily(ctx, fam), tokens.ErrTenantRequired)

		key := &tokens.APIKey[C]{ID: uuid.New(), Hash: "strict-key", Claims: tokens.Claims[C]{Subject: uuid.New(), Custom: customClaim}}
		assert.ErrorIs(t, strict.SaveAPIKey(ctx, key), tokens.ErrTenantRequired, "SaveAPIKey without a tenant must be rejected in strict mode")

		_, err = strict.FindAPIKeyByHash(ctx, "strict-key")
		assert.ErrorIs(t, err, tokens.ErrTenantRequired)
	})

	t.Run("strict: the same ops succeed once a tenant is supplied", func(t *testing.T) {
		const tenant = "strict-tenant"
		rt := &tokens.RefreshToken{
			Hash: "ok-rt", FamilyID: uuid.New(), UserID: uuid.New(), TenantID: tenant,
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}
		require.NoError(t, strict.SaveRefreshToken(ctx, rt, tokens.WithTenant(tenant)))
		got, err := strict.FindRefreshToken(ctx, "ok-rt", tokens.WithTenant(tenant))
		require.NoError(t, err)
		assert.Equal(t, rt.UserID, got.UserID)

		key := &tokens.APIKey[C]{
			ID: uuid.New(), TenantID: tenant, Hash: "ok-key",
			Claims: tokens.Claims[C]{Subject: uuid.New(), Custom: customClaim},
		}
		require.NoError(t, strict.SaveAPIKey(ctx, key, tokens.WithTenant(tenant)))
		foundKey, err := strict.FindAPIKeyByHash(ctx, "ok-key", tokens.WithTenant(tenant))
		require.NoError(t, err)
		assert.Equal(t, key.ID, foundKey.ID)
	})
}
