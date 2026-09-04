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
