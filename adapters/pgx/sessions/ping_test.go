package pgx_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/adapters/pgx/sessions"
	"github.com/JLugagne/egauth/health"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Verifies the N11 health seam: the pgx Store implements health.Pinger and Ping surfaces
// backend connectivity (nil while the pool is up, error once it is closed).

func TestStore_Ping(t *testing.T) {
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
	defer func() { _ = pgContainer.Terminate(ctx) }()

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)

	store := pgx.NewStore(pool)

	// The store must expose the optional Pinger seam.
	pinger, ok := interface{}(store).(health.Pinger)
	require.True(t, ok, "pgx Store must implement health.Pinger")

	// Healthy while the pool is up.
	require.NoError(t, pinger.Ping(ctx))

	// Closing the pool makes Ping surface the connectivity failure.
	pool.Close()
	assert.Error(t, pinger.Ping(ctx), "Ping must error once the pool is closed")
}
