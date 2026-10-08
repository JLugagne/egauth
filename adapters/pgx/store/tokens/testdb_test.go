package tokens_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	tokensstore "github.com/JLugagne/egauth/adapters/pgx/store/tokens"
)

var shared struct {
	once      sync.Once
	container *postgres.PostgresContainer
	pool      *pgxpool.Pool
	err       error
}

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

func cleanPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("requires Docker (testcontainers); run without -short")
	}
	ctx := context.Background()
	shared.once.Do(func() {
		start(ctx)
		if shared.err == nil {
			shared.err = migrate.Run(ctx, shared.pool, []migrate.Module{{Name: "tokens", FS: tokensstore.Migrations}})
		}
	})
	require.NoError(t, shared.err)
	_, err := shared.pool.Exec(ctx, "TRUNCATE egauth_refresh_tokens, egauth_revocations, tokens")
	require.NoError(t, err)
	return shared.pool
}
