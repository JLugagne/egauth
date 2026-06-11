//go:build integration

// The integration build tag gates this file so the default `go test ./...` (and `go test
// -short ./...`) never requires Docker or a database: it is only compiled with `-tags=integration`.
//
// It runs the SHARED sessions.Store contract suite (storetest.StoreContractTesting) — the exact
// same suite the in-memory store runs in sessions/memory — against a REAL PostgreSQL backend, plus
// an explicit expiry-boundary check on FindSessionByHash.
//
// Backend selection (see newIntegrationPool):
//   - TEST_DATABASE_URL set -> run against that DSN (e.g. a CI Postgres service container).
//   - otherwise -> spin up an ephemeral Postgres via testcontainers-go.
//   - neither a DSN nor a working Docker daemon -> t.Skip (never fail), so the Docker-less
//     contributor path is not blocked.
package pgx_test

import (
	"context"
	"os"
	"testing"
	"time"

	pgxstore "github.com/JLugagne/egauth/adapters/pgx/sessions"
	"github.com/JLugagne/egauth/sessions"
	"github.com/JLugagne/egauth/sessions/storetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// newIntegrationPool returns a pgx pool connected to a real Postgres for the duration of the test,
// applies the sessions migrations, and registers all cleanup. It prefers TEST_DATABASE_URL and
// falls back to a testcontainers-managed Postgres; it t.Skip()s (never fails) when no database can
// be reached.
func newIntegrationPool(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()

	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" {
		t.Logf("using TEST_DATABASE_URL backend")
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Skipf("TEST_DATABASE_URL set but pool could not be created: %v", err)
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			t.Skipf("TEST_DATABASE_URL set but database is unreachable: %v", err)
		}
		t.Cleanup(pool.Close)

		if err := pgxstore.Migrate(ctx, pool); err != nil {
			t.Fatalf("migrate against TEST_DATABASE_URL: %v", err)
		}
		return pool
	}

	t.Logf("no TEST_DATABASE_URL; starting ephemeral Postgres via testcontainers")
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
	if err != nil {
		// No Docker daemon (or it is unreachable): skip rather than fail, matching the
		// Docker-less contributor path documented in CI.
		t.Skipf("Docker/testcontainers unavailable, skipping real-Postgres integration: %v", err)
	}
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	if err := pgxstore.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate against testcontainers Postgres: %v", err)
	}
	return pool
}

// TestStoreContract_Integration runs the SAME shared contract suite (storetest.StoreContractTesting)
// that the in-memory store runs, but against a real PostgreSQL backend. This proves the pgx store
// honours the sessions.Store contract at runtime, not just against the in-memory mock.
func TestStoreContract_Integration(t *testing.T) {
	ctx := context.Background()
	pool := newIntegrationPool(ctx, t)
	store := pgxstore.NewStore(pool)
	storetest.StoreContractTesting(t, store, true)
}

// TestFindSessionByHash_ExpiredExclusion_Integration pins the expired-row exclusion contract
// against the REAL database, exercising the expiry boundary explicitly.
//
// The store's FindSessionByHash filters with:
//
//	WHERE token_hash = $1 AND tenant_id = $2 AND expires_at >= NOW()
//
// so a row whose expires_at is in the past must NOT be returned, while a row whose expires_at is in
// the future MUST be returned. We seed rows around NOW() and assert the boundary: already-expired
// -> ErrSessionNotFound; clearly-live -> found. A row that expires shortly in the future is created
// live and then re-checked after it has lapsed, proving the predicate is evaluated against the
// database clock at query time, not at insert time.
func TestFindSessionByHash_ExpiredExclusion_Integration(t *testing.T) {
	ctx := context.Background()
	pool := newIntegrationPool(ctx, t)
	store := pgxstore.NewStore(pool)

	const tenant = "tenant-expiry"

	// Row 1: already expired one hour ago -> must be excluded.
	expired := &sessions.Session{
		ID:        uuid.New(),
		TenantID:  tenant,
		UserID:    uuid.New(),
		TokenHash: "expiry-already-gone",
		ExpiresAt: time.Now().Add(-time.Hour),
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	require.NoError(t, store.CreateSession(ctx, tenant, expired))

	// Row 2: clearly live -> must be returned.
	live := &sessions.Session{
		ID:        uuid.New(),
		TenantID:  tenant,
		UserID:    uuid.New(),
		TokenHash: "expiry-still-live",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	require.NoError(t, store.CreateSession(ctx, tenant, live))

	// The expired row is invisible to FindSessionByHash, evaluated against the DB clock.
	_, err := store.FindSessionByHash(ctx, tenant, "expiry-already-gone")
	require.ErrorIs(t, err, sessions.ErrSessionNotFound,
		"expired row must be excluded by the expires_at >= NOW() predicate")

	// The live row is returned.
	found, err := store.FindSessionByHash(ctx, tenant, "expiry-still-live")
	require.NoError(t, err)
	assert.Equal(t, live.ID, found.ID)

	// Row 3: expires very soon. It is found while live, then excluded once its expiry lapses,
	// proving the predicate uses the database clock at query time (not the insert-time value).
	soon := &sessions.Session{
		ID:        uuid.New(),
		TenantID:  tenant,
		UserID:    uuid.New(),
		TokenHash: "expiry-boundary",
		ExpiresAt: time.Now().Add(750 * time.Millisecond),
		CreatedAt: time.Now(),
	}
	require.NoError(t, store.CreateSession(ctx, tenant, soon))

	gotSoon, err := store.FindSessionByHash(ctx, tenant, "expiry-boundary")
	require.NoError(t, err, "row must be visible while still live")
	assert.Equal(t, soon.ID, gotSoon.ID)

	// Cross the boundary, then confirm exclusion. A margin past the expiry avoids flakiness.
	time.Sleep(1200 * time.Millisecond)
	_, err = store.FindSessionByHash(ctx, tenant, "expiry-boundary")
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound,
		"row must be excluded once its expires_at has lapsed at query time")
}
