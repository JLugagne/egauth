package e2e_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("requires Docker (testcontainers); run without -short")
	}
	testcontainers.SkipIfProviderIsNotHealthy(t)
	image := os.Getenv("E2E_POSTGRES_IMAGE")
	if image == "" {
		image = "postgres:16-alpine"
	}
	ctx := context.Background()
	c, err := postgres.Run(ctx, image,
		postgres.WithDatabase("testdb"), postgres.WithUsername("user"), postgres.WithPassword("pass"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(90*time.Second)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}
