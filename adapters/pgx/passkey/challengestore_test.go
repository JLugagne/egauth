package pgx_test

import (
	"context"
	"testing"
	"time"

	passkeypgx "github.com/JLugagne/egauth/adapters/pgx/passkey"
	"github.com/JLugagne/egauth/passkey"
	"github.com/JLugagne/egauth/passkey/storetest"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestPgxChallengeStore_ImplementsInterface pins mfa/SF-4: a shared, Postgres-backed
// ChallengeStore must exist, because the per-process in-memory one rejects roughly (N-1)/N of the
// ceremonies of an N-replica deployment as replays.
func TestPgxChallengeStore_ImplementsInterface(t *testing.T) {
	var cs passkey.ChallengeStore = passkeypgx.NewChallengeStore(nil)
	assert.NotNil(t, cs)
}

func TestPgxChallengeStore_Contract(t *testing.T) {
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

	require.NoError(t, passkeypgx.Migrate(ctx, pool))

	storetest.ChallengeStoreContractTesting(t, passkeypgx.NewChallengeStore(pool))
}

// TestPgxChallengeStore_DeleteExpired covers the pruning path, which no ceremony exercises: a
// challenge that is never finished is only reclaimed by it.
func TestPgxChallengeStore_DeleteExpired(t *testing.T) {
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

	require.NoError(t, passkeypgx.Migrate(ctx, pool))
	cs := passkeypgx.NewChallengeStore(pool)

	require.NoError(t, cs.Put(ctx, "t-prune", "stale-challenge", time.Now().Add(-time.Minute)))
	require.NoError(t, cs.Put(ctx, "t-prune", "live-challenge", time.Now().Add(time.Hour)))

	deleted, err := cs.DeleteExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted, "only the expired challenge must be pruned")

	ok, err := cs.Consume(ctx, "t-prune", "live-challenge")
	require.NoError(t, err)
	assert.True(t, ok, "pruning must not touch a live challenge")
}
