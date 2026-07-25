package pgx_test

import (
	"context"
	"testing"
	"time"

	passkeypgx "github.com/JLugagne/egauth/adapters/pgx/passkey"
	"github.com/JLugagne/egauth/passkey"
	"github.com/JLugagne/egauth/passkey/storetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
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

// TestPgxStore_UpdateCredential_SignCountNeverRegresses is the regression test for pgx/PG-6: a
// stale write (a lower sign_count than what is already stored, as would happen if a slower
// concurrent request's write commits after a faster one already advanced the counter) must never
// roll sign_count back, since it is the cloned-credential detection signal.
func TestPgxStore_UpdateCredential_SignCountNeverRegresses(t *testing.T) {
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
	store := passkeypgx.NewStore(pool)

	const tenantID = "tenant-cas"
	userID := uuid.New()
	base := &passkey.Credential{
		UserID: userID, TenantID: tenantID, ID: []byte("cred-cas-1"),
		PublicKey: []byte("pk"), SignCount: 1, Data: []byte("{}"),
	}
	require.NoError(t, store.SaveCredential(ctx, tenantID, base))

	// A newer write advances sign_count to 10 (e.g. a fast, winning concurrent login).
	advanced := *base
	advanced.SignCount = 10
	require.NoError(t, store.UpdateCredential(ctx, tenantID, &advanced))

	// A stale write with a LOWER sign_count arrives after (e.g. a slower request that read the
	// credential before the advance committed). It must be a silent no-op, not an error, and must
	// not roll sign_count back.
	stale := *base
	stale.SignCount = 3
	require.NoError(t, store.UpdateCredential(ctx, tenantID, &stale),
		"a stale write must be a no-op success, not an error")

	got, err := store.GetCredentials(ctx, tenantID, userID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, uint32(10), got[0].SignCount, "sign_count must never regress even when a stale write arrives later")
}
