package pgxmigrate_test

import (
	"context"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/JLugagne/egauth/adapters/pgx/internal/pgxmigrate"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Verifies the N5 no-op property: after a migration is applied and recorded, re-running Run
// skips it instead of re-executing. The migration here is deliberately NON-idempotent (CREATE
// TABLE without IF NOT EXISTS), so if Run were to re-execute it on the second call Postgres
// would error with "relation already exists" — making the no-op assertion airtight.

func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("requires Docker (testcontainers); run without -short")
	}
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
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	pool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func TestRun_RerunIsNoOp(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)

	fsys := fstest.MapFS{
		// Non-idempotent on purpose: a second execution would fail with "relation already exists".
		"migrations/001_create_widgets.sql": {Data: []byte(`CREATE TABLE widgets (id INT PRIMARY KEY);`)},
		"migrations/002_seed_widget.sql":    {Data: []byte(`INSERT INTO widgets (id) VALUES (1);`)},
	}

	// First run applies both files.
	require.NoError(t, pgxmigrate.Run(ctx, pool, fsys, "widgets"))

	assertCount := func(table string, want int) {
		t.Helper()
		var n int
		require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n))
		assert.Equal(t, want, n, "row count in %s", table)
	}
	assertCount("schema_migrations", 2)
	assertCount("widgets", 1) // the seed INSERT ran exactly once

	// Second run must be a no-op: neither file re-executes (the non-idempotent CREATE would
	// error, and the seed INSERT would push widgets to 2 rows). It must also not duplicate the
	// schema_migrations rows.
	require.NoError(t, pgxmigrate.Run(ctx, pool, fsys, "widgets"), "re-running Migrate must be a no-op")
	assertCount("schema_migrations", 2)
	assertCount("widgets", 1)
}

func TestRun_AppliesOnlyUnappliedFiles(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)

	// Apply the first file only.
	require.NoError(t, pgxmigrate.Run(ctx, pool, fstest.MapFS{
		"migrations/001_a.sql": {Data: []byte(`CREATE TABLE a (id INT);`)},
	}, "ab"))

	// Now run with an additional file. Re-presenting 001 (already recorded) must be skipped,
	// while the new 002 applies — proving incremental application, not all-or-nothing re-run.
	require.NoError(t, pgxmigrate.Run(ctx, pool, fstest.MapFS{
		"migrations/001_a.sql": {Data: []byte(`CREATE TABLE a (id INT);`)}, // non-idempotent; must be skipped
		"migrations/002_b.sql": {Data: []byte(`CREATE TABLE b (id INT);`)},
	}, "ab"))

	var versions []string
	rows, err := pool.Query(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var v string
		require.NoError(t, rows.Scan(&v))
		versions = append(versions, v)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{"ab:001_a.sql", "ab:002_b.sql"}, versions)
}

// TestRun_SameFilenameInTwoNamespacesBothApply is the Docker-gated regression test for the
// filename-collision bug: every store shares one schema_migrations table, and two stores may
// legitimately ship the same filename (sessions and otp both have 002_add_expires_at_index.sql).
// Keying the applied-set on the bare filename made the second store's file look already-applied,
// so it was silently skipped and that store's schema stayed incomplete. Both migrations here are
// non-idempotent, so a skip shows up as a missing table rather than merely a missing row.
func TestRun_SameFilenameInTwoNamespacesBothApply(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)

	const shared = "migrations/002_add_expires_at_index.sql"
	require.NoError(t, pgxmigrate.Run(ctx, pool, fstest.MapFS{
		shared: {Data: []byte(`CREATE TABLE ns_one_marker (id INT);`)},
	}, "ns-one"))
	require.NoError(t, pgxmigrate.Run(ctx, pool, fstest.MapFS{
		shared: {Data: []byte(`CREATE TABLE ns_two_marker (id INT);`)},
	}, "ns-two"))

	for _, table := range []string{"ns_one_marker", "ns_two_marker"} {
		var exists bool
		require.NoError(t, pool.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)", table,
		).Scan(&exists))
		assert.True(t, exists, "%s must exist: a filename shared with another namespace must not skip the migration", table)
	}

	var versions []string
	rows, err := pool.Query(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var v string
		require.NoError(t, rows.Scan(&v))
		versions = append(versions, v)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{"ns-one:002_add_expires_at_index.sql", "ns-two:002_add_expires_at_index.sql"}, versions)
}

// TestRun_ConcurrentCallersOnSameNamespaceAllSucceed is the Docker-gated regression test for the
// advisory lock (pgx/PG-1): it starts several concurrent Run callers — simulating N replicas of
// one service starting together during a rolling deploy — all targeting the SAME namespace and
// the SAME deliberately non-idempotent migration (no IF NOT EXISTS). Without the lock, two
// callers can both observe the file as "not yet applied" and race the CREATE TABLE, which
// Postgres is not guaranteed to survive even when serialized after the fact (duplicate-relation
// error, or the well-known concurrent-DDL catalog race) — reproducing "N-1 of N replicas fail
// startup". With the lock serializing every caller, every one of them must succeed.
func TestRun_ConcurrentCallersOnSameNamespaceAllSucceed(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker (testcontainers); run without -short")
	}
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
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	fsys := fstest.MapFS{
		// Non-idempotent on purpose: races here are not merely wasted work, they are errors.
		"migrations/001_create_race.sql": {Data: []byte(`CREATE TABLE race_winner (id INT PRIMARY KEY);`)},
	}

	const replicas = 8
	pools := make([]*pgxpool.Pool, replicas)
	for i := range pools {
		pool, err := pgxpool.New(ctx, connStr)
		require.NoError(t, err)
		t.Cleanup(pool.Close)
		pools[i] = pool
	}

	var wg sync.WaitGroup
	errs := make([]error, replicas)
	start := make(chan struct{})
	for i, pool := range pools {
		wg.Add(1)
		go func(i int, pool *pgxpool.Pool) {
			defer wg.Done()
			<-start
			errs[i] = pgxmigrate.Run(ctx, pool, fsys, "rolling-deploy-ns")
		}(i, pool)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "replica %d must not fail: every concurrent starter targeting the same namespace must serialise on the advisory lock", i)
	}

	var n int
	require.NoError(t, pools[0].QueryRow(ctx, "SELECT count(*) FROM schema_migrations WHERE version = 'rolling-deploy-ns:001_create_race.sql'").Scan(&n))
	assert.Equal(t, 1, n, "the migration must be recorded exactly once despite the concurrent race")
}
