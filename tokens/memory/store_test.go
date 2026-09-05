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
