package keys_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	keysstore "github.com/JLugagne/egauth/adapters/pgx/store/keys"
)

var shared struct {
	once      sync.Once
	container *postgres.PostgresContainer
	pool      *pgxpool.Pool
	err       error
}

var databases atomic.Int32

func TestMain(m *testing.M) {
	code := m.Run()
	if shared.pool != nil {
		shared.pool.Close()
	}
	if shared.container != nil {
		_ = shared.container.Terminate(context.Background())
	}
	os.Exit(code)
}

func start(ctx context.Context) {
	c, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("testdb"), postgres.WithUsername("user"), postgres.WithPassword("pass"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(60*time.Second)))
	if err != nil {
		shared.err = err
		return
	}
	shared.container = c
	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		shared.err = err
		return
	}
	shared.pool, shared.err = pgxpool.New(ctx, dsn)
}

func boot(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("requires Docker (testcontainers); run without -short")
	}
	ctx := context.Background()
	shared.once.Do(func() {
		start(ctx)
		if shared.err == nil {
			shared.err = migrate.Run(ctx, shared.pool, []migrate.Module{{Name: "keys", FS: keysstore.Migrations}})
		}
	})
	require.NoError(t, shared.err)
}

func cleanPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	boot(t)
	_, err := shared.pool.Exec(context.Background(), "TRUNCATE keystore_keys, egauth_tenant_tombstones, egauth_key_changes, egauth_key_feed_horizon")
	require.NoError(t, err)
	return shared.pool
}

func emptyDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	boot(t)
	ctx := context.Background()
	name := fmt.Sprintf("keys_empty_%d", databases.Add(1))
	_, err := shared.pool.Exec(ctx, "CREATE DATABASE "+name)
	require.NoError(t, err)
	dsn, err := shared.container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}
