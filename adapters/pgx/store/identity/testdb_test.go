package identity_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	identitystore "github.com/JLugagne/egauth/adapters/pgx/store/identity"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/identity/storetest"
)

var shared struct {
	once      sync.Once
	container *postgres.PostgresContainer
	dsn       string
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
	if shared.dsn, err = c.ConnectionString(ctx, "sslmode=disable"); err != nil {
		shared.err = err
		return
	}
	shared.pool, shared.err = pgxpool.New(ctx, shared.dsn)
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
			shared.err = migrate.Run(ctx, shared.pool, []migrate.Module{{Name: "identity", FS: identitystore.Migrations}})
		}
	})
	require.NoError(t, shared.err)
}

func cleanPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	boot(t)
	_, err := shared.pool.Exec(context.Background(),
		"TRUNCATE users, identities, verification_tokens, egauth_epoch_log, egauth_lifecycle_outbox RESTART IDENTITY")
	require.NoError(t, err)
	return shared.pool
}

func emptyDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	boot(t)
	ctx := context.Background()
	name := fmt.Sprintf("identity_%d", databases.Add(1))
	_, err := shared.pool.Exec(ctx, "CREATE DATABASE "+name)
	require.NoError(t, err)
	u, err := url.Parse(shared.dsn)
	require.NoError(t, err)
	u.Path = "/" + name
	pool, err := pgxpool.New(ctx, u.String())
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

type faultyDB struct {
	*pgxpool.Pool
	mu    sync.Mutex
	armed int
}

func (f *faultyDB) arm(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.armed = n
}

func (f *faultyDB) Begin(ctx context.Context) (pgx.Tx, error) {
	f.mu.Lock()
	n := f.armed
	f.armed = -1
	f.mu.Unlock()
	tx, err := f.Pool.Begin(ctx)
	if err != nil || n < 0 {
		return tx, err
	}
	return &faultyTx{Tx: tx, left: n}, nil
}

type faultyTx struct {
	pgx.Tx
	left int
}

func (t *faultyTx) step() error {
	t.left--
	if t.left < 0 {
		return storetest.ErrInjected
	}
	return nil
}

func (t *faultyTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if err := t.step(); err != nil {
		return pgconn.CommandTag{}, err
	}
	return t.Tx.Exec(ctx, sql, args...)
}

func (t *faultyTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if err := t.step(); err != nil {
		return nil, err
	}
	return t.Tx.Query(ctx, sql, args...)
}

type failedRow struct{ err error }

func (r failedRow) Scan(...any) error { return r.err }

func (t *faultyTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if err := t.step(); err != nil {
		return failedRow{err: err}
	}
	return t.Tx.QueryRow(ctx, sql, args...)
}

func (t *faultyTx) Commit(ctx context.Context) error {
	if err := t.step(); err != nil {
		_ = t.Tx.Rollback(ctx)
		return err
	}
	return t.Tx.Commit(ctx)
}

var faults sync.Map

func newStore(t *testing.T) *identitystore.Store {
	db := &faultyDB{Pool: cleanPool(t), armed: -1}
	st := identitystore.New(db)
	faults.Store(st, db)
	t.Cleanup(func() { faults.Delete(st) })
	return st
}

const micros = `$3::bigint * interval '1 microsecond'`

func hooks(pool func() *pgxpool.Pool) storetest.Hooks {
	return storetest.Hooks{
		Age: func(t *testing.T, _ identity.Store, s principal.Subject, d time.Duration) {
			ctx := context.Background()
			for _, q := range []string{
				`UPDATE egauth_epoch_log SET created_at = created_at - ` + micros + ` WHERE tenant_id = $1 AND user_id = $2`,
				`UPDATE egauth_lifecycle_outbox SET created_at = created_at - ` + micros + `,
    next_attempt_at = next_attempt_at - ` + micros + `, done_at = done_at - ` + micros + `
WHERE tenant_id = $1 AND user_id = $2`,
				`UPDATE identities SET updated_at = updated_at - ` + micros + `, locked_until = locked_until - ` + micros + `
WHERE tenant_id = $1 AND user_id = $2 AND provider = 'password'`,
			} {
				_, err := pool().Exec(ctx, q, s.Tenant.String(), s.User, d.Microseconds())
				require.NoError(t, err)
			}
		},
		Fail: func(t *testing.T, ctx context.Context, st identity.Store, n int) context.Context {
			db, ok := faults.Load(st)
			require.True(t, ok, "the store was not built by newStore")
			db.(*faultyDB).arm(n)
			return ctx
		},
		Unverified: func(t *testing.T, _ identity.Store, s principal.Subject, email identity.Identifier) {
			_, err := pool().Exec(context.Background(), `INSERT INTO users (id, tenant_id, email, created_at, updated_at)
VALUES ($1, $2, $3, now(), now())`, s.User, s.Tenant.String(), email.Value())
			require.NoError(t, err)
		},
	}
}
