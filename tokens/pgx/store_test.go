package pgx_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens/pgx"
	"github.com/JLugagne/egauth/tokens/storetest"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

type customClaims struct {
	Foo string `json:"foo"`
}

func TestStoreContract(t *testing.T) {
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
	defer pgContainer.Terminate(ctx)

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	defer pool.Close()

	err = pgx.Migrate(ctx, pool)
	require.NoError(t, err)

	store := pgx.NewStore[customClaims](pool)
	storetest.StoreContractTesting(t, store, true, customClaims{Foo: "bar"})

	storetest.StrictTenancyTesting(t, pgx.NewStore[customClaims](pool, pgx.WithStrictTenancy()), customClaims{Foo: "bar"})
}
