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
	SaveRefreshTokenFunc              func(ctx context.Context, tenantID string, rt *tokens.RefreshToken) error
	FindRefreshTokenFunc              func(ctx context.Context, tenantID string, tokenHash string) (*tokens.RefreshToken, error)
	ConsumeRefreshTokenFunc           func(ctx context.Context, tenantID string, tokenHash string) error
	RevokeRefreshTokenFunc            func(ctx context.Context, tenantID string, tokenHash string) error
	RevokeFamilyFunc                  func(ctx context.Context, tenantID string, familyID uuid.UUID) error
	RevokeAllRefreshTokensForUserFunc func(ctx context.Context, tenantID string, userID uuid.UUID) error
	SaveAPIKeyFunc                    func(ctx context.Context, tenantID string, key *tokens.APIKey[C]) error
	FindAPIKeyByHashFunc              func(ctx context.Context, tenantID string, tokenHash string) (*tokens.APIKey[C], error)
	DeleteExpiredFunc                 func(ctx context.Context, tenantID string) (int64, error)
	RevokeAPIKeyFunc                  func(ctx context.Context, tenantID string, keyID uuid.UUID) error
	ListAPIKeysByCreatorFunc          func(ctx context.Context, tenantID string, createdBy uuid.UUID) ([]*tokens.APIKey[C], error)
	RevokeAllAPIKeysForUserFunc       func(ctx context.Context, tenantID string, userID uuid.UUID) error
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

func (m *MockStore[C]) RevokeAllRefreshTokensForUser(ctx context.Context, tenantID string, userID uuid.UUID) error {
	if m.RevokeAllRefreshTokensForUserFunc == nil {
		panic("called not defined RevokeAllRefreshTokensForUserFunc")
	}
	return m.RevokeAllRefreshTokensForUserFunc(ctx, tenantID, userID)
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
		userID := uuid.Must(uuid.NewV7())
		// An expired refresh token and a live one.
		expired := &tokens.RefreshToken{
			Hash: "reaper-expired", FamilyID: uuid.Must(uuid.NewV7()), UserID: userID, TenantID: tenantA,
			ExpiresAt: time.Now().Add(-time.Hour), CreatedAt: time.Now().Add(-2 * time.Hour),
		}
		live := &tokens.RefreshToken{
			Hash: "reaper-live", FamilyID: uuid.Must(uuid.NewV7()), UserID: userID, TenantID: tenantA,
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}
		// A consumed-but-not-yet-expired token must be KEPT (needed for reuse detection).
		consumedAt := time.Now().Add(-time.Minute)
		consumedLive := &tokens.RefreshToken{
			Hash: "reaper-consumed-live", FamilyID: uuid.Must(uuid.NewV7()), UserID: userID, TenantID: tenantA,
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
			Hash: "reaper-consumed-expired", FamilyID: uuid.Must(uuid.NewV7()), UserID: userID, TenantID: tenantA,
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
		userID := uuid.Must(uuid.NewV7())
		familyID := uuid.Must(uuid.NewV7())
		expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
		authTime := time.Now().Add(-10 * time.Minute).Truncate(time.Second)

		rt := &tokens.RefreshToken{
			Hash:               tokenHash,
			FamilyID:           familyID,
			UserID:             userID,
			TenantID:           tenantA,
			AuthTime:           authTime,
			MustChangePassword: true,
			ExpiresAt:          expiresAt,
			CreatedAt:          time.Now().Truncate(time.Second),
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
		assert.True(t, found.MustChangePassword, "must_change_password must round-trip (forced-change gate carried across refresh)")
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
			Hash: "mismatch-rt", FamilyID: uuid.Must(uuid.NewV7()), UserID: uuid.Must(uuid.NewV7()), TenantID: "tenant-on-record",
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}
		err := store.SaveRefreshToken(ctx, "different-tenant", rt)
		assert.ErrorIs(t, err, tokens.ErrTenantMismatch, "record tenant != argument must be rejected")

		key := &tokens.APIKey[C]{
			ID: uuid.Must(uuid.NewV7()), TenantID: "tenant-on-record", Hash: "mismatch-key",
			Claims: tokens.Claims[C]{Subject: uuid.Must(uuid.NewV7()), Custom: customClaim},
		}
		err = store.SaveAPIKey(ctx, "different-tenant", key)
		assert.ErrorIs(t, err, tokens.ErrTenantMismatch, "API key record tenant != argument must be rejected")
	})

	t.Run("Contract: RevokeFamily", func(t *testing.T) {
		familyID := uuid.Must(uuid.NewV7())
		otherFamilyID := uuid.Must(uuid.NewV7())
		userID := uuid.Must(uuid.NewV7())
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
		err = store.RevokeFamily(ctx, tenantA, uuid.Must(uuid.NewV7()))
		assert.NoError(t, err)
	})

	t.Run("Contract: RevokeAllRefreshTokensForUser", func(t *testing.T) {
		expiresAt := time.Now().Add(time.Hour)
		victim := uuid.Must(uuid.NewV7())
		bystander := uuid.Must(uuid.NewV7())

		// The victim holds two refresh tokens in two different families.
		for i, h := range []string{"ru_victim_1", "ru_victim_2"} {
			require.NoError(t, store.SaveRefreshToken(ctx, tenantA, &tokens.RefreshToken{
				Hash:      h,
				FamilyID:  uuid.Must(uuid.NewV7()),
				UserID:    victim,
				TenantID:  tenantA,
				ExpiresAt: expiresAt.Add(time.Duration(i) * time.Minute),
				CreatedAt: time.Now(),
			}))
		}
		// A bystander's token must survive.
		require.NoError(t, store.SaveRefreshToken(ctx, tenantA, &tokens.RefreshToken{
			Hash:      "ru_bystander",
			FamilyID:  uuid.Must(uuid.NewV7()),
			UserID:    bystander,
			TenantID:  tenantA,
			ExpiresAt: expiresAt,
			CreatedAt: time.Now(),
		}))

		// Revoke every refresh token the victim holds.
		require.NoError(t, store.RevokeAllRefreshTokensForUser(ctx, tenantA, victim))

		_, err := store.FindRefreshToken(ctx, tenantA, "ru_victim_1")
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)
		_, err = store.FindRefreshToken(ctx, tenantA, "ru_victim_2")
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

		// The bystander is untouched.
		_, err = store.FindRefreshToken(ctx, tenantA, "ru_bystander")
		assert.NoError(t, err, "another user's refresh token must survive")

		// A user with no live tokens is a no-op, never an error.
		assert.NoError(t, store.RevokeAllRefreshTokensForUser(ctx, tenantA, uuid.Must(uuid.NewV7())))
	})

	t.Run("Contract: API Keys", func(t *testing.T) {
		tokenHash := "api_key_hash"
		key := &tokens.APIKey[C]{
			ID:       uuid.Must(uuid.NewV7()),
			TenantID: tenantA,
			Prefix:   "pk_",
			Hash:     tokenHash,
			Claims: tokens.Claims[C]{
				Subject: uuid.Must(uuid.NewV7()),
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

	t.Run("Contract: API key revoke", func(t *testing.T) {
		creator := uuid.Must(uuid.NewV7())
		key := &tokens.APIKey[C]{
			ID:        uuid.Must(uuid.NewV7()),
			TenantID:  tenantA,
			Prefix:    "pk_",
			Hash:      "revoke_me_hash",
			CreatedBy: creator,
			Claims: tokens.Claims[C]{
				Subject: uuid.Must(uuid.NewV7()),
				Custom:  customClaim,
			},
		}
		require.NoError(t, store.SaveAPIKey(ctx, tenantA, key))

		// Freshly saved key is active (RevokedAt nil).
		found, err := store.FindAPIKeyByHash(ctx, tenantA, "revoke_me_hash")
		require.NoError(t, err)
		assert.Nil(t, found.RevokedAt, "a freshly saved key must be active")

		// Revoke by ID.
		err = store.RevokeAPIKey(ctx, tenantA, key.ID)
		require.NoError(t, err)

		// FindAPIKeyByHash STILL returns the key, now with RevokedAt set (NOT filtered out): the
		// store stays policy-free and the verify layer is the one that rejects revoked keys.
		found, err = store.FindAPIKeyByHash(ctx, tenantA, "revoke_me_hash")
		require.NoError(t, err, "a revoked key must still be returned by FindAPIKeyByHash")
		require.NotNil(t, found.RevokedAt, "a revoked key must report RevokedAt")

		// Revoking a missing id -> ErrAPIKeyNotFound.
		err = store.RevokeAPIKey(ctx, tenantA, uuid.Must(uuid.NewV7()))
		assert.ErrorIs(t, err, tokens.ErrAPIKeyNotFound, "revoking an unknown key id must report not found")

		// Revoking an already-revoked key is a no-op success (RevokedAt is not advanced).
		firstRevokedAt := *found.RevokedAt
		err = store.RevokeAPIKey(ctx, tenantA, key.ID)
		require.NoError(t, err, "re-revoking an already-revoked key must be a no-op success")
		found, err = store.FindAPIKeyByHash(ctx, tenantA, "revoke_me_hash")
		require.NoError(t, err)
		require.NotNil(t, found.RevokedAt)
		assert.WithinDuration(t, firstRevokedAt, *found.RevokedAt, time.Second, "re-revoking must not advance RevokedAt")
	})

	t.Run("Contract: API key list by creator", func(t *testing.T) {
		creatorX := uuid.Must(uuid.NewV7())
		creatorY := uuid.Must(uuid.NewV7())

		x1 := &tokens.APIKey[C]{
			ID: uuid.Must(uuid.NewV7()), TenantID: tenantA, Prefix: "pk_", Hash: "list_x1",
			CreatedBy: creatorX, Token: "should-not-be-persisted-x1",
			Claims: tokens.Claims[C]{Subject: uuid.Must(uuid.NewV7()), Custom: customClaim},
		}
		x2 := &tokens.APIKey[C]{
			ID: uuid.Must(uuid.NewV7()), TenantID: tenantA, Prefix: "pk_", Hash: "list_x2",
			CreatedBy: creatorX, Token: "should-not-be-persisted-x2",
			Claims: tokens.Claims[C]{Subject: uuid.Must(uuid.NewV7()), Custom: customClaim},
		}
		y1 := &tokens.APIKey[C]{
			ID: uuid.Must(uuid.NewV7()), TenantID: tenantA, Prefix: "pk_", Hash: "list_y1",
			CreatedBy: creatorY, Token: "should-not-be-persisted-y1",
			Claims: tokens.Claims[C]{Subject: uuid.Must(uuid.NewV7()), Custom: customClaim},
		}
		require.NoError(t, store.SaveAPIKey(ctx, tenantA, x1))
		require.NoError(t, store.SaveAPIKey(ctx, tenantA, x2))
		require.NoError(t, store.SaveAPIKey(ctx, tenantA, y1))

		// ListAPIKeysByCreator(X) returns exactly X's keys, never Y's.
		listX, err := store.ListAPIKeysByCreator(ctx, tenantA, creatorX)
		require.NoError(t, err)
		gotIDs := make(map[uuid.UUID]bool, len(listX))
		for _, k := range listX {
			gotIDs[k.ID] = true
			// SECURITY: the clear-text token must never be returned by a list operation.
			assert.Empty(t, k.Token, "SECURITY: listed key must not carry a clear-text Token")
		}
		assert.True(t, gotIDs[x1.ID], "creator X's first key must be listed")
		assert.True(t, gotIDs[x2.ID], "creator X's second key must be listed")
		assert.False(t, gotIDs[y1.ID], "creator Y's key must not appear in creator X's listing")
		assert.Len(t, listX, 2, "creator X has exactly two keys")

		// Revoked keys are still listed, with RevokedAt set.
		require.NoError(t, store.RevokeAPIKey(ctx, tenantA, x1.ID))
		listX, err = store.ListAPIKeysByCreator(ctx, tenantA, creatorX)
		require.NoError(t, err)
		assert.Len(t, listX, 2, "revoking a key must not drop it from the listing")
		var sawRevoked bool
		for _, k := range listX {
			if k.ID == x1.ID {
				sawRevoked = true
				assert.NotNil(t, k.RevokedAt, "the revoked key must be listed with RevokedAt set")
			}
			assert.Empty(t, k.Token, "SECURITY: listed key must not carry a clear-text Token")
		}
		assert.True(t, sawRevoked, "the revoked key must still appear in the listing")

		// Unknown creator -> empty, non-nil slice, no error.
		listUnknown, err := store.ListAPIKeysByCreator(ctx, tenantA, uuid.Must(uuid.NewV7()))
		require.NoError(t, err, "an unknown creator must not be an error")
		assert.Empty(t, listUnknown, "an unknown creator must yield an empty slice")
	})

	t.Run("Contract: RevokeAllAPIKeysForUser", func(t *testing.T) {
		victim := uuid.Must(uuid.NewV7())
		bystander := uuid.Must(uuid.NewV7())

		// The victim issued two keys; one is already revoked beforehand.
		v1 := &tokens.APIKey[C]{
			ID: uuid.Must(uuid.NewV7()), TenantID: tenantA, Prefix: "pk_", Hash: "rau_v1",
			CreatedBy: victim,
			Claims:    tokens.Claims[C]{Subject: uuid.Must(uuid.NewV7()), Custom: customClaim},
		}
		v2 := &tokens.APIKey[C]{
			ID: uuid.Must(uuid.NewV7()), TenantID: tenantA, Prefix: "pk_", Hash: "rau_v2",
			CreatedBy: victim,
			Claims:    tokens.Claims[C]{Subject: uuid.Must(uuid.NewV7()), Custom: customClaim},
		}
		// A bystander's key must stay active.
		b1 := &tokens.APIKey[C]{
			ID: uuid.Must(uuid.NewV7()), TenantID: tenantA, Prefix: "pk_", Hash: "rau_b1",
			CreatedBy: bystander,
			Claims:    tokens.Claims[C]{Subject: uuid.Must(uuid.NewV7()), Custom: customClaim},
		}
		require.NoError(t, store.SaveAPIKey(ctx, tenantA, v1))
		require.NoError(t, store.SaveAPIKey(ctx, tenantA, v2))
		require.NoError(t, store.SaveAPIKey(ctx, tenantA, b1))

		// Pre-revoke v1 so we can prove its RevokedAt is preserved (not advanced).
		require.NoError(t, store.RevokeAPIKey(ctx, tenantA, v1.ID))
		preRevoked, err := store.FindAPIKeyByHash(ctx, tenantA, "rau_v1")
		require.NoError(t, err)
		require.NotNil(t, preRevoked.RevokedAt)
		firstRevokedAt := *preRevoked.RevokedAt

		// Revoke every key the victim issued.
		require.NoError(t, store.RevokeAllAPIKeysForUser(ctx, tenantA, victim))

		// v2 (was active) is now revoked.
		got, err := store.FindAPIKeyByHash(ctx, tenantA, "rau_v2")
		require.NoError(t, err)
		assert.NotNil(t, got.RevokedAt, "a previously active key must be revoked")

		// v1's original RevokedAt is preserved, not advanced.
		got, err = store.FindAPIKeyByHash(ctx, tenantA, "rau_v1")
		require.NoError(t, err)
		require.NotNil(t, got.RevokedAt)
		assert.WithinDuration(t, firstRevokedAt, *got.RevokedAt, time.Second,
			"an already-revoked key must keep its original RevokedAt")

		// The bystander's key stays active.
		got, err = store.FindAPIKeyByHash(ctx, tenantA, "rau_b1")
		require.NoError(t, err)
		assert.Nil(t, got.RevokedAt, "another user's key must stay active")

		// A user with no keys is a no-op, never an error.
		assert.NoError(t, store.RevokeAllAPIKeysForUser(ctx, tenantA, uuid.Must(uuid.NewV7())))
	})

	if useMultiTenant {
		t.Run("Contract: Multi-Tenant Isolation", func(t *testing.T) {
			sharedHash := "shared_hash"
			userID := uuid.Must(uuid.NewV7())
			familyID := uuid.Must(uuid.NewV7())
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
			creatorA := uuid.Must(uuid.NewV7())
			keyA := &tokens.APIKey[C]{
				ID:        uuid.Must(uuid.NewV7()),
				TenantID:  tenantA,
				Hash:      "api_shared",
				CreatedBy: creatorA,
			}
			err = store.SaveAPIKey(ctx, tenantA, keyA)
			require.NoError(t, err)

			_, err = store.FindAPIKeyByHash(ctx, tenantB, "api_shared")
			assert.ErrorIs(t, err, tokens.ErrAPIKeyNotFound)

			// Tenant B cannot revoke Tenant A's key: cross-tenant is treated as not found.
			err = store.RevokeAPIKey(ctx, tenantB, keyA.ID)
			assert.ErrorIs(t, err, tokens.ErrAPIKeyNotFound, "Tenant B must not be able to revoke Tenant A's key")

			// Tenant A's key must remain active after Tenant B's failed revoke.
			foundA, err := store.FindAPIKeyByHash(ctx, tenantA, "api_shared")
			require.NoError(t, err)
			assert.Nil(t, foundA.RevokedAt, "Tenant A's key must stay active after Tenant B's failed revoke")

			// ListAPIKeysByCreator under Tenant B for a creator whose keys live in Tenant A is empty.
			listB, err := store.ListAPIKeysByCreator(ctx, tenantB, creatorA)
			require.NoError(t, err)
			assert.Empty(t, listB, "Tenant B must not see Tenant A's keys via ListAPIKeysByCreator")

			// And Tenant A still sees its own key.
			listA, err := store.ListAPIKeysByCreator(ctx, tenantA, creatorA)
			require.NoError(t, err)
			assert.Len(t, listA, 1, "Tenant A must see its own creator's key")
		})
	}
}

func (m *MockStore[C]) RevokeAPIKey(ctx context.Context, tenantID string, keyID uuid.UUID) error {
	if m.RevokeAPIKeyFunc == nil {
		panic("called not defined RevokeAPIKeyFunc")
	}
	return m.RevokeAPIKeyFunc(ctx, tenantID, keyID)
}

func (m *MockStore[C]) ListAPIKeysByCreator(ctx context.Context, tenantID string, createdBy uuid.UUID) ([]*tokens.APIKey[C], error) {
	if m.ListAPIKeysByCreatorFunc == nil {
		panic("called not defined ListAPIKeysByCreatorFunc")
	}
	return m.ListAPIKeysByCreatorFunc(ctx, tenantID, createdBy)
}

func (m *MockStore[C]) RevokeAllAPIKeysForUser(ctx context.Context, tenantID string, userID uuid.UUID) error {
	if m.RevokeAllAPIKeysForUserFunc == nil {
		panic("called not defined RevokeAllAPIKeysForUserFunc")
	}
	return m.RevokeAllAPIKeysForUserFunc(ctx, tenantID, userID)
}
