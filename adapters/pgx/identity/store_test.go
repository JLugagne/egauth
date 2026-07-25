package pgx_test

import (
	"context"
	"testing"
	"time"

	pgxstore "github.com/JLugagne/egauth/adapters/pgx/identity"
	"github.com/JLugagne/egauth/identity/storetest"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestPgxStore_Contract(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker (testcontainers); run without -short")
	}
	ctx := context.Background()

	// 1. Setup Postgres Testcontainer
	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(15*time.Second),
		),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		if err := pgContainer.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate pgContainer: %s", err)
		}
	})

	connString, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	// 2. Connect with pgxpool
	pool, err := pgxpool.New(ctx, connString)
	require.NoError(t, err)
	t.Cleanup(func() {
		pool.Close()
	})

	// 3. Run Migrations
	err = pgxstore.Migrate(ctx, pool)
	require.NoError(t, err)

	// 4. Create Store
	store := pgxstore.NewStore(pool)

	// 5. Run Contract Tests
	storetest.StoreContractTesting(t, store, true)
	storetest.StoreDisableEnableContract(t, store, "tenant-A")
	storetest.StoreUpdateUserSoftDeleteContract(t, store, "tenant-A")
	storetest.StoreUpdateUserFieldScopeContract(t, store, "tenant-A")
	storetest.StoreDeleteAuthGateContract(t, store, "tenant-A")
}
