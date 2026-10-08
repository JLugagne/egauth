package migrate_test

import (
	"context"
	"io/fs"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	identitypgx "github.com/JLugagne/egauth/adapters/pgx/identity"
	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	otppgx "github.com/JLugagne/egauth/adapters/pgx/otp"
	sessionspgx "github.com/JLugagne/egauth/adapters/pgx/sessions"
)

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("requires Docker (testcontainers); run without -short")
	}
	ctx := context.Background()
	c, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("testdb"), postgres.WithUsername("user"), postgres.WithPassword("pass"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(60*time.Second)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func count(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(), sql, args...).Scan(&n))
	return n
}

func embedded(t *testing.T, fsys fs.FS) []string {
	t.Helper()
	entries, err := fs.ReadDir(fsys, "migrations")
	require.NoError(t, err)
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestRunBootstrapsARealV016SchemaAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)
	require.NoError(t, identitypgx.Migrate(ctx, pool))
	legacy := count(t, pool, `SELECT count(*) FROM schema_migrations`)

	mods := []migrate.Module{{Name: "identity", FS: identitypgx.MigrationsFS}}
	require.NoError(t, migrate.Run(ctx, pool, mods), "v0.16 files are bootstrapped, never re-run")
	require.NoError(t, migrate.Run(ctx, pool, mods))
	require.NoError(t, migrate.Check(ctx, pool, "identity", identitypgx.MigrationsFS))
	require.Equal(t, len(embedded(t, identitypgx.MigrationsFS)),
		count(t, pool, `SELECT count(*) FROM egauth_schema_migrations WHERE module = 'identity'`))
	require.Equal(t, legacy, count(t, pool, `SELECT count(*) FROM schema_migrations`), "the legacy table is never written")
}

func TestRunRerunsTheCollidingBasenameOwnedByAnUnregisteredModuleAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)
	require.NoError(t, otppgx.Migrate(ctx, pool))
	require.Equal(t, 1, count(t, pool, `SELECT count(*) FROM schema_migrations WHERE version = '002_add_expires_at_index.sql'`))

	require.NoError(t, migrate.Run(ctx, pool, []migrate.Module{{Name: "sessions", FS: sessionspgx.MigrationsFS}}))
	require.Equal(t, 1, count(t, pool, `SELECT count(*) FROM pg_indexes WHERE indexname = 'idx_sessions_tenant_expires'`),
		"a v0.16 row of 002_add_expires_at_index.sql may come from otp, so sessions re-runs it")
}

func TestRunNeverCopiesARowIntoAnotherModuleAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)
	require.NoError(t, identitypgx.Migrate(ctx, pool))
	mods := []migrate.Module{{Name: "sessions", FS: fstest.MapFS{
		"migrations/001_create_tables.sql": {Data: []byte(`CREATE TABLE IF NOT EXISTS foreign_probe (id INT);`)},
	}}}
	require.NoError(t, migrate.Run(ctx, pool, mods))
	require.Equal(t, 1, count(t, pool, `SELECT count(*) FROM pg_tables WHERE tablename = 'foreign_probe'`),
		"a basename v0.16 recorded for identity never marks another module applied")
}

func TestRunIgnoresForeignSchemaMigrationsAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)
	_, err := pool.Exec(ctx, `CREATE TABLE schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL); INSERT INTO schema_migrations VALUES (1, false)`)
	require.NoError(t, err)
	mods := []migrate.Module{{Name: "identity", FS: identitypgx.MigrationsFS}}
	require.NoError(t, migrate.Run(ctx, pool, mods))
	require.Equal(t, 1, count(t, pool, `SELECT count(*) FROM pg_tables WHERE tablename = 'users'`))
	var dirty bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT dirty FROM schema_migrations`).Scan(&dirty))
	require.False(t, dirty)
}

func TestRunIsAtomicAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)
	mods := []migrate.Module{{Name: "a", FS: fstest.MapFS{
		"migrations/001_t.sql":   {Data: []byte(`CREATE TABLE a_t (id INT PRIMARY KEY);`)},
		"migrations/002_bad.sql": {Data: []byte(`SELECT * FROM missing_relation;`)},
	}}}
	require.Error(t, migrate.Run(ctx, pool, mods))
	require.Zero(t, count(t, pool, `SELECT count(*) FROM pg_tables WHERE tablename = 'a_t'`))
	mods[0].FS.(fstest.MapFS)["migrations/002_bad.sql"] = &fstest.MapFile{Data: []byte(`SELECT 1;`)}
	require.NoError(t, migrate.Run(ctx, pool, mods), "a failed run left nothing behind, so the non-idempotent file applies")
	require.NoError(t, migrate.Run(ctx, pool, mods))
}

func TestRunConcurrentCallsAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)
	mods := []migrate.Module{{Name: "a", FS: fstest.MapFS{
		"migrations/001_t.sql": {Data: []byte(`CREATE TABLE a_t (id INT PRIMARY KEY);`)},
	}}}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() { errs <- migrate.Run(ctx, pool, mods) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, 1, count(t, pool, `SELECT count(*) FROM egauth_schema_migrations`))
}
