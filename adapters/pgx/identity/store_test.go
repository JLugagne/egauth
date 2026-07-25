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
	storetest.StorePasswordRotationLivenessContract(t, store, "tenant-A")
	storetest.StoreMarkEmailVerifiedContract(t, store, "tenant-A")
	storetest.StoreVerificationTokenPurgeContract(t, store, "tenant-A")
	storetest.StoreVerificationTokenPurgeTenantScopeContract(t, store, "tenant-A", "tenant-B")
}

// TestMigrate_SurvivesPriorPartialApply reproduces the exact scenario the runner's idempotency
// contract exists for (see internal/pgxmigrate's package doc: "if the process dies after a file
// applies but before its version row is durable, the file re-applies on the next run — which is
// harmless only because it is idempotent"): migration 001's DDL already committed against the
// database, but schema_migrations has no row for it yet (e.g. the client crashed after Postgres
// committed but before the version INSERT's result reached it). Migrate must survive re-issuing
// 001 from scratch. Before IF NOT EXISTS was added to idx_users_email_tenant and
// idx_identities_provider_tenant, this failed with "relation already exists".
func TestMigrate_SurvivesPriorPartialApply(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker (testcontainers); run without -short")
	}
	ctx := context.Background()

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
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	connString, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	pool, err := pgxpool.New(ctx, connString)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	raw, err := pgxstore.MigrationsFS.ReadFile("migrations/001_create_tables.sql")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, string(raw))
	require.NoError(t, err, "applying 001's DDL directly (simulating the pre-crash state)")

	require.NoError(t, pgxstore.Migrate(ctx, pool),
		"Migrate must tolerate 001's DDL already having run without a schema_migrations row for it")
}
