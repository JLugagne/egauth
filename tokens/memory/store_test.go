package memory

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type CustomClaims struct {
	Foo string `json:"foo"`
}

func TestStore(t *testing.T) {
	store := NewStore[CustomClaims]()
	storetest.StoreContractTesting(t, store, true, CustomClaims{Foo: "bar"})
}

func TestRotateRefreshToken(t *testing.T) {
	ctx := context.Background()
	tenantID := "tenant-1"
	userID := uuid.Must(uuid.NewV7())
	familyID := uuid.Must(uuid.NewV7())

	t.Run("successful atomic rotation", func(t *testing.T) {
		store := NewStore[CustomClaims]()
		oldRT := &tokens.RefreshToken{
			Hash:      "old-hash",
			TenantID:  tenantID,
			UserID:    userID,
			FamilyID:  familyID,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		require.NoError(t, store.SaveRefreshToken(ctx, tenantID, oldRT))

		newRT := &tokens.RefreshToken{
			Hash:      "new-hash",
			TenantID:  tenantID,
			UserID:    userID,
			FamilyID:  familyID,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		err := store.RotateRefreshToken(ctx, tenantID, "old-hash", newRT)
		require.NoError(t, err)

		// Old token must be consumed
		oldFound, err := store.FindRefreshToken(ctx, tenantID, "old-hash")
		require.NoError(t, err)
		assert.NotNil(t, oldFound.ConsumedAt)

		// New token must be saved and unconsumed
		newFound, err := store.FindRefreshToken(ctx, tenantID, "new-hash")
		require.NoError(t, err)
		assert.Nil(t, newFound.ConsumedAt)
	})

	t.Run("returns ErrRefreshTokenNotFound if old token does not exist", func(t *testing.T) {
		store := NewStore[CustomClaims]()
		newRT := &tokens.RefreshToken{
			Hash:      "new-hash",
			TenantID:  tenantID,
			UserID:    userID,
			FamilyID:  familyID,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		err := store.RotateRefreshToken(ctx, tenantID, "nonexistent-hash", newRT)
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

		// New token should not be saved
		_, err = store.FindRefreshToken(ctx, tenantID, "new-hash")
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)
	})

	t.Run("returns ErrRefreshTokenReused if old token already consumed", func(t *testing.T) {
		store := NewStore[CustomClaims]()
		now := time.Now().UTC()
		oldRT := &tokens.RefreshToken{
			Hash:       "old-hash",
			TenantID:   tenantID,
			UserID:     userID,
			FamilyID:   familyID,
			ExpiresAt:  time.Now().Add(time.Hour),
			ConsumedAt: &now,
		}
		require.NoError(t, store.SaveRefreshToken(ctx, tenantID, oldRT))

		newRT := &tokens.RefreshToken{
			Hash:      "new-hash",
			TenantID:  tenantID,
			UserID:    userID,
			FamilyID:  familyID,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		err := store.RotateRefreshToken(ctx, tenantID, "old-hash", newRT)
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenReused)

		// New token should not be saved
		_, err = store.FindRefreshToken(ctx, tenantID, "new-hash")
		assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)
	})

	t.Run("returns ErrTenantMismatch and does not consume old token if new token has different tenant", func(t *testing.T) {
		store := NewStore[CustomClaims]()
		oldRT := &tokens.RefreshToken{
			Hash:      "old-hash",
			TenantID:  tenantID,
			UserID:    userID,
			FamilyID:  familyID,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		require.NoError(t, store.SaveRefreshToken(ctx, tenantID, oldRT))

		newRT := &tokens.RefreshToken{
			Hash:      "new-hash",
			TenantID:  "other-tenant",
			UserID:    userID,
			FamilyID:  familyID,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		err := store.RotateRefreshToken(ctx, tenantID, "old-hash", newRT)
		assert.ErrorIs(t, err, tokens.ErrTenantMismatch)

		// Old token must NOT be consumed
		oldFound, err := store.FindRefreshToken(ctx, tenantID, "old-hash")
		require.NoError(t, err)
		assert.Nil(t, oldFound.ConsumedAt)
	})
}

func TestStore_MultiTenantHashCollision(t *testing.T) {
	ctx := context.Background()
	store := NewStore[CustomClaims]()

	t.Run("refresh tokens with identical hash across tenants preserve both tokens without collision", func(t *testing.T) {
		const hashX = "shared-refresh-hash-x"
		userA := uuid.Must(uuid.NewV7())
		userB := uuid.Must(uuid.NewV7())
		familyA := uuid.Must(uuid.NewV7())
		familyB := uuid.Must(uuid.NewV7())

		rtA := &tokens.RefreshToken{
			Hash:      hashX,
			TenantID:  "tenantA",
			UserID:    userA,
			FamilyID:  familyA,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		require.NoError(t, store.SaveRefreshToken(ctx, "tenantA", rtA))

		rtB := &tokens.RefreshToken{
			Hash:      hashX,
			TenantID:  "tenantB",
			UserID:    userB,
			FamilyID:  familyB,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		require.NoError(t, store.SaveRefreshToken(ctx, "tenantB", rtB))

		// Both tokens must be preserved under their respective tenants
		foundA, err := store.FindRefreshToken(ctx, "tenantA", hashX)
		require.NoError(t, err)
		assert.Equal(t, "tenantA", foundA.TenantID)
		assert.Equal(t, userA, foundA.UserID)
		assert.Equal(t, familyA, foundA.FamilyID)

		foundB, err := store.FindRefreshToken(ctx, "tenantB", hashX)
		require.NoError(t, err)
		assert.Equal(t, "tenantB", foundB.TenantID)
		assert.Equal(t, userB, foundB.UserID)
		assert.Equal(t, familyB, foundB.FamilyID)
	})

	t.Run("API keys with identical hash across tenants preserve both keys without collision", func(t *testing.T) {
		const hashY = "shared-api-key-hash-y"
		userA := uuid.Must(uuid.NewV7())
		userB := uuid.Must(uuid.NewV7())
		keyIDA := uuid.Must(uuid.NewV7())
		keyIDB := uuid.Must(uuid.NewV7())

		keyA := &tokens.APIKey[CustomClaims]{
			ID:        keyIDA,
			Hash:      hashY,
			TenantID:  "tenantA",
			CreatedBy: userA,
			Type:      tokens.KeyTypePAT,
			Claims:    tokens.Claims[CustomClaims]{Custom: CustomClaims{Foo: "tenantA-data"}},
		}
		require.NoError(t, store.SaveAPIKey(ctx, "tenantA", keyA))

		keyB := &tokens.APIKey[CustomClaims]{
			ID:        keyIDB,
			Hash:      hashY,
			TenantID:  "tenantB",
			CreatedBy: userB,
			Type:      tokens.KeyTypePAT,
			Claims:    tokens.Claims[CustomClaims]{Custom: CustomClaims{Foo: "tenantB-data"}},
		}
		require.NoError(t, store.SaveAPIKey(ctx, "tenantB", keyB))

		// Both keys must be preserved under their respective tenants
		foundA, err := store.FindAPIKeyByHash(ctx, "tenantA", hashY)
		require.NoError(t, err)
		assert.Equal(t, "tenantA", foundA.TenantID)
		assert.Equal(t, keyIDA, foundA.ID)
		assert.Equal(t, userA, foundA.CreatedBy)
		assert.Equal(t, "tenantA-data", foundA.Claims.Custom.Foo)

		foundB, err := store.FindAPIKeyByHash(ctx, "tenantB", hashY)
		require.NoError(t, err)
		assert.Equal(t, "tenantB", foundB.TenantID)
		assert.Equal(t, keyIDB, foundB.ID)
		assert.Equal(t, userB, foundB.CreatedBy)
		assert.Equal(t, "tenantB-data", foundB.Claims.Custom.Foo)
	})
}
