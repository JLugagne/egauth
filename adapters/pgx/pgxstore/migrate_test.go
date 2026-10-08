package pgxstore_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/JLugagne/egauth/adapters/pgx/pgxstore"
)

type recorder struct {
	applied  map[string][]string
	executed []string
	begun    int
	commits  int
}

type recorderTx struct {
	pgx.Tx
	r *recorder
}

func (tx recorderTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return tx.r.Exec(ctx, sql, args...)
}

func (tx recorderTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return tx.r.QueryRow(ctx, sql, args...)
}

func (tx recorderTx) Commit(context.Context) error {
	tx.r.commits++
	return nil
}

func (tx recorderTx) Rollback(context.Context) error { return nil }

type listRow struct{ vals [][]string }

func (r listRow) Scan(dest ...any) error {
	for i, d := range dest {
		*(d.(*[]string)) = r.vals[i]
	}
	return nil
}

func (r *recorder) Begin(context.Context) (pgx.Tx, error) {
	r.begun++
	return recorderTx{r: r}, nil
}

func (r *recorder) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.HasPrefix(sql, "INSERT INTO egauth_schema_migrations") && len(args) == 2 {
		return pgconn.CommandTag{}, nil
	}
	if strings.Contains(sql, "-- ") || strings.Contains(sql, "CREATE ") {
		r.executed = append(r.executed, sql)
		for _, m := range []string{"ceremony", "deployment", "limiter"} {
			if strings.Contains(sql, "VALUES ('"+m+"', '001_create.sql')") {
				r.applied[m] = append(r.applied[m], "001_create.sql")
			}
		}
	}
	return pgconn.CommandTag{}, nil
}

func (r *recorder) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "information_schema.columns"):
		return listRow{[][]string{nil, nil}}
	case strings.Contains(sql, "FROM egauth_schema_migrations"):
		return listRow{[][]string{r.applied[args[0].(string)]}}
	}
	panic("unexpected query: " + sql)
}

func TestMigrateAppliesEveryRegisteredModuleOnce(t *testing.T) {
	db := &recorder{applied: map[string][]string{}}
	for range 2 {
		if err := pgxstore.Migrate(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	var created int
	for _, sql := range db.executed {
		if strings.Contains(sql, "CREATE") && strings.Contains(sql, "INSERT INTO egauth_schema_migrations") {
			created++
		}
	}
	if created != 3 {
		t.Fatalf("applied %d migration files, want 3 (ceremony, deployment, limiter) exactly once", created)
	}
	if db.begun != 2 || db.commits != 2 {
		t.Fatalf("each run must hold one transaction: begun %d, committed %d", db.begun, db.commits)
	}
	for _, sql := range db.executed {
		if strings.Contains(strings.ToUpper(sql), "DROP ") {
			t.Fatalf("a v0.17 migration drops something: %s", sql)
		}
	}
}

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

func TestMigrateConcurrentCallsAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() { errs <- pgxstore.Migrate(ctx, pool) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM egauth_schema_migrations`).Scan(&n))
	require.Equal(t, 3, n)
}
