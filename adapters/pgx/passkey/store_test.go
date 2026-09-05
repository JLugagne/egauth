package pgx_test

import (
	"context"
	"testing"
	"time"

	passkeypgx "github.com/JLugagne/egauth/adapters/pgx/passkey"
	"github.com/JLugagne/egauth/passkey"
	"github.com/JLugagne/egauth/passkey/storetest"
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

	pool, err := pgxpool.New(ctx, connString)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	require.NoError(t, passkeypgx.Migrate(ctx, pool))

	storetest.StoreContractTesting(t, passkeypgx.NewStore(pool), true)
}

func TestPgxStore_ChallengeStore(t *testing.T) {
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
	t.Cleanup(func() {
		if err := pgContainer.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate pgContainer: %s", err)
		}
	})

	connString, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, connString)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	require.NoError(t, passkeypgx.Migrate(ctx, pool))

	var cs passkey.ChallengeStore = passkeypgx.NewChallengeStore(pool)

	t.Run("Put and Consume removes challenge", func(t *testing.T) {
		err := cs.Put(ctx, "t1", "chal-1", time.Now().Add(5*time.Minute))
		require.NoError(t, err)

		ok, err := cs.Consume(ctx, "t1", "chal-1")
		require.NoError(t, err)
		require.True(t, ok, "first consume must return true")

		// Ensure it was removed
		ok, err = cs.Consume(ctx, "t1", "chal-1")
		require.NoError(t, err)
		require.False(t, ok, "challenge should be removed after consume")
	})

	t.Run("Second Consume returns false", func(t *testing.T) {
		err := cs.Put(ctx, "t1", "chal-2", time.Now().Add(5*time.Minute))
		require.NoError(t, err)

		ok, err := cs.Consume(ctx, "t1", "chal-2")
		require.NoError(t, err)
		require.True(t, ok)

		ok, err = cs.Consume(ctx, "t1", "chal-2")
		require.NoError(t, err)
		require.False(t, ok, "second consume must return false")
	})

	t.Run("Consuming an expired challenge returns false", func(t *testing.T) {
		err := cs.Put(ctx, "t1", "chal-expired", time.Now().Add(-1*time.Minute))
		require.NoError(t, err)

		ok, err := cs.Consume(ctx, "t1", "chal-expired")
		require.NoError(t, err)
		require.False(t, ok, "consuming expired challenge must return false")
	})

	t.Run("Multi-tenant challenge isolation", func(t *testing.T) {
		err := cs.Put(ctx, "tenant-a", "shared-chal", time.Now().Add(5*time.Minute))
		require.NoError(t, err)

		ok, err := cs.Consume(ctx, "tenant-b", "shared-chal")
		require.NoError(t, err)
		require.False(t, ok, "tenant-b cannot consume tenant-a challenge")

		ok, err = cs.Consume(ctx, "tenant-a", "shared-chal")
		require.NoError(t, err)
		require.True(t, ok, "tenant-a can consume its own challenge")
	})

	t.Run("Put on conflict updates expires_at", func(t *testing.T) {
		err := cs.Put(ctx, "t1", "chal-overwrite", time.Now().Add(-1*time.Minute))
		require.NoError(t, err)

		err = cs.Put(ctx, "t1", "chal-overwrite", time.Now().Add(5*time.Minute))
		require.NoError(t, err)

		ok, err := cs.Consume(ctx, "t1", "chal-overwrite")
		require.NoError(t, err)
		require.True(t, ok, "overwritten unexpired challenge must be consumable")
	})
}
