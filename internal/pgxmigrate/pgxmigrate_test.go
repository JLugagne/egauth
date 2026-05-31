package pgxmigrate_test

import (
	"context"
	"testing"
	"testing/fstest"
	"time"

	"github.com/JLugagne/libauth/internal/pgxmigrate"
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
	require.NoError(t, pgxmigrate.Run(ctx, pool, fsys))

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
	require.NoError(t, pgxmigrate.Run(ctx, pool, fsys), "re-running Migrate must be a no-op")
	assertCount("schema_migrations", 2)
	assertCount("widgets", 1)
}

func TestRun_AppliesOnlyUnappliedFiles(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)

	// Apply the first file only.
	require.NoError(t, pgxmigrate.Run(ctx, pool, fstest.MapFS{
		"migrations/001_a.sql": {Data: []byte(`CREATE TABLE a (id INT);`)},
	}))

	// Now run with an additional file. Re-presenting 001 (already recorded) must be skipped,
	// while the new 002 applies — proving incremental application, not all-or-nothing re-run.
	require.NoError(t, pgxmigrate.Run(ctx, pool, fstest.MapFS{
		"migrations/001_a.sql": {Data: []byte(`CREATE TABLE a (id INT);`)}, // non-idempotent; must be skipped
		"migrations/002_b.sql": {Data: []byte(`CREATE TABLE b (id INT);`)},
	}))

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
	assert.Equal(t, []string{"001_a.sql", "002_b.sql"}, versions)
}
