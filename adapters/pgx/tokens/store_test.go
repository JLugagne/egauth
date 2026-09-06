package pgx_test

import (
	"context"
	"testing"
	"time"

	pgx "github.com/JLugagne/egauth/adapters/pgx/tokens"
	egauthtokens "github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/storetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

type customClaims struct {
	Foo string `json:"foo"`
}

// newTestPool spins up a throwaway Postgres container and returns a connected pool.
// The container is registered for cleanup on t.Cleanup.
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("requires Docker (testcontainers); run without -short")
	}
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("user"),
		postgres.WithPassword("pass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	require.NoError(t, pgx.Migrate(ctx, pool))
	return pool
}

func TestStoreContract(t *testing.T) {
	pool := newTestPool(t)
	store := pgx.NewStore[customClaims](pool)
	storetest.StoreContractTesting(t, store, true, customClaims{Foo: "bar"})
}

// TestStoreAPIKeyColumns verifies that type and created_by round-trip through SaveAPIKey /
// FindAPIKeyByHash, covering both PAT and Service key types and the nil-creator case.
func TestStoreAPIKeyColumns(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	store := pgx.NewStore[customClaims](pool)

	tenantID := "tenant-col-test"
	creatorID := uuid.Must(uuid.NewV7())

	t.Run("PAT key round-trips type and created_by", func(t *testing.T) {
		key := &egauthtokens.APIKey[customClaims]{
			ID:        uuid.Must(uuid.NewV7()),
			TenantID:  tenantID,
			Prefix:    "pat_",
			Hash:      "hash-pat-01",
			Type:      egauthtokens.KeyTypePAT,
			CreatedBy: creatorID,
			Claims: egauthtokens.Claims[customClaims]{
				Subject: creatorID,
				Custom:  customClaims{Foo: "pat-test"},
			},
		}
		require.NoError(t, store.SaveAPIKey(ctx, tenantID, key))

		got, err := store.FindAPIKeyByHash(ctx, tenantID, "hash-pat-01")
		require.NoError(t, err)
		assert.Equal(t, egauthtokens.KeyTypePAT, got.Type, "Type must round-trip as pat")
		assert.Equal(t, creatorID, got.CreatedBy, "CreatedBy must round-trip")
		assert.Empty(t, got.Token, "SECURITY: clear-text token must never be stored")
	})

	t.Run("Service key round-trips type and created_by", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV7())
		key := &egauthtokens.APIKey[customClaims]{
			ID:        keyID,
			TenantID:  tenantID,
			Prefix:    "svc_",
			Hash:      "hash-svc-01",
			Type:      egauthtokens.KeyTypeService,
			CreatedBy: creatorID,
			Claims: egauthtokens.Claims[customClaims]{
				Subject: keyID, // service token: subject is the key's own ID
				Custom:  customClaims{Foo: "svc-test"},
			},
		}
		require.NoError(t, store.SaveAPIKey(ctx, tenantID, key))

		got, err := store.FindAPIKeyByHash(ctx, tenantID, "hash-svc-01")
		require.NoError(t, err)
		assert.Equal(t, egauthtokens.KeyTypeService, got.Type, "Type must round-trip as service")
		assert.Equal(t, creatorID, got.CreatedBy, "CreatedBy must round-trip for service token")
	})

	t.Run("zero CreatedBy stored as NULL and returned as zero UUID", func(t *testing.T) {
		key := &egauthtokens.APIKey[customClaims]{
			ID:       uuid.Must(uuid.NewV7()),
			TenantID: tenantID,
			Hash:     "hash-nocreator-01",
			Type:     egauthtokens.KeyTypeService,
			// CreatedBy intentionally zero — should be stored as NULL
			Claims: egauthtokens.Claims[customClaims]{
				Subject: uuid.Must(uuid.NewV7()),
				Custom:  customClaims{Foo: "no-creator"},
			},
		}
		require.NoError(t, store.SaveAPIKey(ctx, tenantID, key))

		got, err := store.FindAPIKeyByHash(ctx, tenantID, "hash-nocreator-01")
		require.NoError(t, err)
		assert.Equal(t, uuid.Nil, got.CreatedBy, "zero CreatedBy must come back as uuid.Nil")
	})

	t.Run("default type applied when Type field is empty", func(t *testing.T) {
		key := &egauthtokens.APIKey[customClaims]{
			ID:       uuid.Must(uuid.NewV7()),
			TenantID: tenantID,
			Hash:     "hash-defaulttype-01",
			// Type intentionally empty — SaveAPIKey must default to service
			Claims: egauthtokens.Claims[customClaims]{
				Subject: uuid.Must(uuid.NewV7()),
				Custom:  customClaims{Foo: "default-type"},
			},
		}
		require.NoError(t, store.SaveAPIKey(ctx, tenantID, key))

		got, err := store.FindAPIKeyByHash(ctx, tenantID, "hash-defaulttype-01")
		require.NoError(t, err)
		assert.Equal(t, egauthtokens.KeyTypeService, got.Type, "empty Type must default to service")
	})

	t.Run("DeleteExpired is a hard DELETE with no soft-delete columns", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		key := &egauthtokens.APIKey[customClaims]{
			ID:        uuid.Must(uuid.NewV7()),
			TenantID:  tenantID,
			Hash:      "hash-expired-col-01",
			Type:      egauthtokens.KeyTypeService,
			ExpiresAt: &past,
			Claims: egauthtokens.Claims[customClaims]{
				Subject: uuid.Must(uuid.NewV7()),
				Custom:  customClaims{Foo: "expired"},
			},
		}
		require.NoError(t, store.SaveAPIKey(ctx, tenantID, key))

		n, err := store.DeleteExpired(ctx, tenantID)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, n, int64(1), "expired key must be counted")

		_, err = store.FindAPIKeyByHash(ctx, tenantID, "hash-expired-col-01")
		assert.ErrorIs(t, err, egauthtokens.ErrAPIKeyNotFound, "expired key must be hard-deleted")
	})
}

func TestRotateRefreshToken(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	store := pgx.NewStore[customClaims](pool)

	tenantID := "tenant-rotate-test"
	userID := uuid.Must(uuid.NewV7())
	familyID := uuid.Must(uuid.NewV7())

	t.Run("successful atomic rotation", func(t *testing.T) {
		oldRT := &egauthtokens.RefreshToken{
			Hash:      "pgx-old-hash-1",
			TenantID:  tenantID,
			UserID:    userID,
			FamilyID:  familyID,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		require.NoError(t, store.SaveRefreshToken(ctx, tenantID, oldRT))

		newRT := &egauthtokens.RefreshToken{
			Hash:      "pgx-new-hash-1",
			TenantID:  tenantID,
			UserID:    userID,
			FamilyID:  familyID,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		err := store.RotateRefreshToken(ctx, tenantID, "pgx-old-hash-1", newRT)
		require.NoError(t, err)

		oldFound, err := store.FindRefreshToken(ctx, tenantID, "pgx-old-hash-1")
		require.NoError(t, err)
		assert.NotNil(t, oldFound.ConsumedAt)

		newFound, err := store.FindRefreshToken(ctx, tenantID, "pgx-new-hash-1")
		require.NoError(t, err)
		assert.Nil(t, newFound.ConsumedAt)
	})

	t.Run("returns ErrRefreshTokenNotFound if old token does not exist", func(t *testing.T) {
		newRT := &egauthtokens.RefreshToken{
			Hash:      "pgx-new-hash-notfound",
			TenantID:  tenantID,
			UserID:    userID,
			FamilyID:  familyID,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		err := store.RotateRefreshToken(ctx, tenantID, "nonexistent-hash", newRT)
		assert.ErrorIs(t, err, egauthtokens.ErrRefreshTokenNotFound)

		_, err = store.FindRefreshToken(ctx, tenantID, "pgx-new-hash-notfound")
		assert.ErrorIs(t, err, egauthtokens.ErrRefreshTokenNotFound)
	})

	t.Run("returns ErrRefreshTokenReused if old token already consumed", func(t *testing.T) {
		now := time.Now().UTC()
		oldRT := &egauthtokens.RefreshToken{
			Hash:       "pgx-old-hash-consumed",
			TenantID:   tenantID,
			UserID:     userID,
			FamilyID:   familyID,
			ExpiresAt:  time.Now().Add(time.Hour),
			ConsumedAt: &now,
		}
		require.NoError(t, store.SaveRefreshToken(ctx, tenantID, oldRT))

		newRT := &egauthtokens.RefreshToken{
			Hash:      "pgx-new-hash-consumed-attempt",
			TenantID:  tenantID,
			UserID:    userID,
			FamilyID:  familyID,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		err := store.RotateRefreshToken(ctx, tenantID, "pgx-old-hash-consumed", newRT)
		assert.ErrorIs(t, err, egauthtokens.ErrRefreshTokenReused)

		_, err = store.FindRefreshToken(ctx, tenantID, "pgx-new-hash-consumed-attempt")
		assert.ErrorIs(t, err, egauthtokens.ErrRefreshTokenNotFound)
	})

	t.Run("rolls back on error and does not leave old token consumed", func(t *testing.T) {
		oldRT := &egauthtokens.RefreshToken{
			Hash:      "pgx-old-hash-rollback",
			TenantID:  tenantID,
			UserID:    userID,
			FamilyID:  familyID,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		require.NoError(t, store.SaveRefreshToken(ctx, tenantID, oldRT))

		// Tenant mismatch causes an error
		newRT := &egauthtokens.RefreshToken{
			Hash:      "pgx-new-hash-rollback",
			TenantID:  "different-tenant",
			UserID:    userID,
			FamilyID:  familyID,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		err := store.RotateRefreshToken(ctx, tenantID, "pgx-old-hash-rollback", newRT)
		assert.ErrorIs(t, err, egauthtokens.ErrTenantMismatch)

		// Old token must still NOT be consumed
		oldFound, err := store.FindRefreshToken(ctx, tenantID, "pgx-old-hash-rollback")
		require.NoError(t, err)
		assert.Nil(t, oldFound.ConsumedAt, "old token must remain unconsumed after rollback")

		// New token must NOT be saved
		_, err = store.FindRefreshToken(ctx, tenantID, "pgx-new-hash-rollback")
		assert.ErrorIs(t, err, egauthtokens.ErrRefreshTokenNotFound)
	})
}

func TestStore_RevokeFamily_PreservesAuditTrail(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	store := pgx.NewStore[customClaims](pool)

	tenantID := "tenant-audit-pgx"
	userID := uuid.Must(uuid.NewV7())
	familyID := uuid.Must(uuid.NewV7())

	rt := &egauthtokens.RefreshToken{
		Hash:      "pgx-audit-hash-1",
		TenantID:  tenantID,
		UserID:    userID,
		FamilyID:  familyID,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, store.SaveRefreshToken(ctx, tenantID, rt))

	// Revoke the family
	require.NoError(t, store.RevokeFamily(ctx, tenantID, familyID))

	// FindRefreshToken must return ErrTokenFamilyRevoked
	_, err := store.FindRefreshToken(ctx, tenantID, "pgx-audit-hash-1")
	require.Error(t, err)
	assert.ErrorIs(t, err, egauthtokens.ErrTokenFamilyRevoked)
	assert.ErrorIs(t, err, egauthtokens.ErrTokenRevoked)

	// Direct database query: row must NOT be deleted, revoked_at must be populated
	var revokedAt *time.Time
	query := `SELECT revoked_at FROM tokens WHERE tenant_id = $1 AND token_hash = $2 AND claims IS NULL`
	err = pool.QueryRow(ctx, query, tenantID, "pgx-audit-hash-1").Scan(&revokedAt)
	require.NoError(t, err, "row must remain in tokens table for audit trail")
	assert.NotNil(t, revokedAt, "revoked_at must be stamped in database")
}
