package memory

import (
	"context"
	"errors"
	"strconv"
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

func TestStore_RevokeFamily_PreservesAuditTrail(t *testing.T) {
	ctx := context.Background()
	store := NewStore[CustomClaims]()
	tenantID := "tenant-audit"
	familyID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())

	rt := &tokens.RefreshToken{
		Hash:      "token-hash-1",
		TenantID:  tenantID,
		UserID:    userID,
		FamilyID:  familyID,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, store.SaveRefreshToken(ctx, tenantID, rt))

	// Revoke the family
	require.NoError(t, store.RevokeFamily(ctx, tenantID, familyID))

	// FindRefreshToken must return ErrTokenFamilyRevoked (not ErrRefreshTokenNotFound)
	_, err := store.FindRefreshToken(ctx, tenantID, "token-hash-1")
	require.Error(t, err)
	assert.ErrorIs(t, err, tokens.ErrTokenFamilyRevoked)
	assert.ErrorIs(t, err, tokens.ErrTokenRevoked)

	// In memory store, verify the entry was retained with RevokedAt set
	store.mu.RLock()
	entry, exists := store.refreshTokens[tokenKey{tenantID: tenantID, hash: "token-hash-1"}]
	store.mu.RUnlock()

	require.True(t, exists, "revoked token family must remain in memory storage for auditability")
	assert.NotNil(t, entry.RevokedAt, "RevokedAt timestamp must be stamped on revocation")
}

// TestNewStore_BoundedByDefault confirms NewStore caps refresh-token records by
// DefaultMaxEntries and that NewUnboundedStore is the explicitly named opt-out.
func TestNewStore_BoundedByDefault(t *testing.T) {
	if got := NewStore[CustomClaims]().MaxEntries(); got != DefaultMaxEntries {
		t.Fatalf("NewStore MaxEntries: got %d want %d (bounded default)", got, DefaultMaxEntries)
	}
	if got := NewUnboundedStore[CustomClaims]().MaxEntries(); got != 0 {
		t.Fatalf("NewUnboundedStore MaxEntries: got %d want 0 (unbounded)", got)
	}
}

// TestBoundedStore_NeverExceedsCap verifies a bounded store evicts the soonest-expiring
// refresh-token record when a new one is inserted at the cap.
func TestBoundedStore_NeverExceedsCap(t *testing.T) {
	ctx := context.Background()
	const tenantID = "tenant-1"
	const capN = 2
	store := NewBoundedStore[CustomClaims](capN)
	future := time.Now().Add(time.Hour)

	for i := range capN + 1 {
		rt := &tokens.RefreshToken{
			Hash:      "hash-" + strconv.Itoa(i),
			TenantID:  tenantID,
			UserID:    uuid.Must(uuid.NewV7()),
			FamilyID:  uuid.Must(uuid.NewV7()),
			ExpiresAt: future.Add(time.Duration(i) * time.Second),
			CreatedAt: time.Now(),
		}
		require.NoError(t, store.SaveRefreshToken(ctx, tenantID, rt))
	}
	require.Len(t, store.refreshTokens, capN)

	if _, err := store.FindRefreshToken(ctx, tenantID, "hash-0"); !errors.Is(err, tokens.ErrRefreshTokenNotFound) {
		t.Fatalf("soonest-expiring record must be evicted: got %v", err)
	}
	if _, err := store.FindRefreshToken(ctx, tenantID, "hash-2"); err != nil {
		t.Fatalf("newest record must be present: %v", err)
	}
}

// TestBoundedStore_EvictsExpiredFirst verifies already-expired records are evicted before live
// ones when the cap is reached.
func TestBoundedStore_EvictsExpiredFirst(t *testing.T) {
	ctx := context.Background()
	const tenantID = "tenant-1"
	const capN = 2
	store := NewBoundedStore[CustomClaims](capN)
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Minute)

	for i, exp := range []time.Time{past, future} {
		rt := &tokens.RefreshToken{
			Hash:      "hash-" + strconv.Itoa(i),
			TenantID:  tenantID,
			UserID:    uuid.Must(uuid.NewV7()),
			FamilyID:  uuid.Must(uuid.NewV7()),
			ExpiresAt: exp,
			CreatedAt: time.Now(),
		}
		require.NoError(t, store.SaveRefreshToken(ctx, tenantID, rt))
	}
	newRT := &tokens.RefreshToken{
		Hash:      "hash-new",
		TenantID:  tenantID,
		UserID:    uuid.Must(uuid.NewV7()),
		FamilyID:  uuid.Must(uuid.NewV7()),
		ExpiresAt: future.Add(time.Hour),
		CreatedAt: time.Now(),
	}
	require.NoError(t, store.SaveRefreshToken(ctx, tenantID, newRT))

	if _, err := store.FindRefreshToken(ctx, tenantID, "hash-0"); !errors.Is(err, tokens.ErrRefreshTokenNotFound) {
		t.Fatalf("expired record must be evicted first: got %v", err)
	}
	if _, err := store.FindRefreshToken(ctx, tenantID, "hash-1"); err != nil {
		t.Fatalf("live record must survive: %v", err)
	}
	if _, err := store.FindRefreshToken(ctx, tenantID, "hash-new"); err != nil {
		t.Fatalf("new record must be present: %v", err)
	}
}

// TestBoundedStore_RotateStaysAtCap verifies rotation at the cap does not grow the map beyond it.
func TestBoundedStore_RotateStaysAtCap(t *testing.T) {
	ctx := context.Background()
	const tenantID = "tenant-1"
	store := NewBoundedStore[CustomClaims](1)
	future := time.Now().Add(time.Hour)

	oldRT := &tokens.RefreshToken{
		Hash:      "old-hash",
		TenantID:  tenantID,
		UserID:    uuid.Must(uuid.NewV7()),
		FamilyID:  uuid.Must(uuid.NewV7()),
		ExpiresAt: future,
		CreatedAt: time.Now(),
	}
	require.NoError(t, store.SaveRefreshToken(ctx, tenantID, oldRT))

	newRT := &tokens.RefreshToken{
		Hash:      "new-hash",
		TenantID:  tenantID,
		UserID:    oldRT.UserID,
		FamilyID:  oldRT.FamilyID,
		ExpiresAt: future,
		CreatedAt: time.Now(),
	}
	require.NoError(t, store.RotateRefreshToken(ctx, tenantID, "old-hash", newRT))
	require.Len(t, store.refreshTokens, 1)
	if _, err := store.FindRefreshToken(ctx, tenantID, "new-hash"); err != nil {
		t.Fatalf("rotated record must be present: %v", err)
	}
}

// TestUnboundedStore_NotCapped proves an unbounded store keeps every refresh-token record,
// including more than the default cap.
func TestUnboundedStore_NotCapped(t *testing.T) {
	ctx := context.Background()
	const tenantID = "tenant-1"
	store := NewUnboundedStore[CustomClaims]()
	future := time.Now().Add(time.Hour)

	for i := range DefaultMaxEntries + 1 {
		rt := &tokens.RefreshToken{
			Hash:      "hash-" + strconv.Itoa(i),
			TenantID:  tenantID,
			UserID:    uuid.Must(uuid.NewV7()),
			FamilyID:  uuid.Must(uuid.NewV7()),
			ExpiresAt: future,
			CreatedAt: time.Now(),
		}
		require.NoError(t, store.SaveRefreshToken(ctx, tenantID, rt))
	}
	require.Len(t, store.refreshTokens, DefaultMaxEntries+1)
}
