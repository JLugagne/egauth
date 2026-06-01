package pgx_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/oauth"
	oauthpgx "github.com/JLugagne/egauth/oauth/pgx"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestStore(t *testing.T) {
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
		_ = pgContainer.Terminate(ctx)
	})

	connString, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	// 2. Connect with pgxpool
	pool, err := pgxpool.New(ctx, connString)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	require.NoError(t, oauthpgx.Migrate(ctx, pool))

	store := oauthpgx.NewStore(pool)
	const tenantID = "tenant-123"
	const providerName = "my-sso"

	config := oauthpgx.OIDCProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		AuthURL:      "https://sso.example.com/auth",
		TokenURL:     "https://sso.example.com/token",
		Issuer:       "https://sso.example.com",
		JWKSURL:      "https://sso.example.com/jwks",
		Scopes:       []string{"openid", "email", "profile"},
	}

	// 1. Not found initially
	_, err = store.GetProvider(ctx, tenantID, providerName)
	require.ErrorIs(t, err, oauth.ErrProviderNotFound)

	// 2. Upsert and verify
	require.NoError(t, store.UpsertProvider(ctx, tenantID, providerName, config))

	p, err := store.GetProvider(ctx, tenantID, providerName)
	require.NoError(t, err)
	require.Equal(t, providerName, p.Name())

	// 3. Upsert again to test update (ON CONFLICT DO UPDATE)
	config.ClientID = "new-client-id"
	require.NoError(t, store.UpsertProvider(ctx, tenantID, providerName, config))

	// 4. Delete
	require.NoError(t, store.DeleteProvider(ctx, tenantID, providerName))
	_, err = store.GetProvider(ctx, tenantID, providerName)
	require.ErrorIs(t, err, oauth.ErrProviderNotFound)
}
