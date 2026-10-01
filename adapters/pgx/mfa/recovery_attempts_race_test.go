// Regression coverage for F-PGX-001: IncrementRecoveryAttempts used to be a Go-side
// read-modify-write (SELECT ... FOR UPDATE then a stale upsert). When the mfa_recovery_attempts
// row is absent — the first failed recovery-code attempt after enrollment or after
// ReplaceRecoveryCodes/ConfirmEnrollment, both of which DELETE the row — SELECT ... FOR UPDATE
// locks nothing, so every concurrent caller reads 0, computes 1, and the upsert overwrites the
// counter with that same stale 1. N concurrent wrong recovery codes therefore all pass the
// service's reserve-before-compare gate instead of at most maxAttempts.
//
// The test reproduces the PoC's deterministic interleaving: a barrier lines every caller up on the
// vulnerable read, and a test-only trigger slows every write to mfa_recovery_attempts so all reads
// finish before the first insert commits. The fixed store is a single atomic upsert (no
// read-modify-write), so the barrier simply is not reached; it exists to keep the test failing
// deterministically if the race is ever reintroduced.

package pgx_test

import (
	"context"
	"crypto/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mfapgx "github.com/JLugagne/egauth/adapters/pgx/mfa"
	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/mfa"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// randomKEKKey returns fresh 32-byte key material so tests never depend on a published fixture.
func randomKEKKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

// racePool starts a dedicated Postgres container with a pool wide enough for the concurrent burst.
func racePool(t *testing.T, maxConns int32) *pgxpool.Pool {
	t.Helper()
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
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, mfapgx.Migrate(ctx, pool))
	return pool
}

// installSlowRecoveryWriteTrigger slows every write to mfa_recovery_attempts so the concurrent
// reads (issued as soon as the barrier releases) complete before the first insert commits.
func installSlowRecoveryWriteTrigger(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION test_slow_recovery_write() RETURNS trigger AS $$
		BEGIN
			PERFORM pg_sleep(0.25);
			RETURN NEW;
		END $$ LANGUAGE plpgsql;
		DROP TRIGGER IF EXISTS test_slow_recovery_write ON mfa_recovery_attempts;
		CREATE TRIGGER test_slow_recovery_write
			BEFORE INSERT OR UPDATE ON mfa_recovery_attempts
			FOR EACH ROW EXECUTE FUNCTION test_slow_recovery_write();
	`)
	require.NoError(t, err)
}

// syncingDB wraps a pool so every transaction's SELECT ... FOR UPDATE blocks until n parties have
// arrived, lining up the concurrent burst on the vulnerable read. A timeout on the release path
// keeps the harness from leaking a goroutine when the store no longer performs that read.
type syncingDB struct {
	*pgxpool.Pool
	arrived chan struct{}
	release chan struct{}
}

func newSyncingDB(pool *pgxpool.Pool, n int) *syncingDB {
	d := &syncingDB{Pool: pool, arrived: make(chan struct{}, n), release: make(chan struct{})}
	go func() {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for i := 0; i < n; i++ {
			select {
			case <-d.arrived:
			case <-timer.C:
				close(d.release)
				return
			}
		}
		close(d.release)
	}()
	return d
}

func (d *syncingDB) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &syncingTx{Tx: tx, arrived: d.arrived, release: d.release}, nil
}

type syncingTx struct {
	pgx.Tx
	arrived chan struct{}
	release chan struct{}
}

func (t *syncingTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if strings.Contains(sql, "FOR UPDATE") {
		t.arrived <- struct{}{}
		<-t.release
	}
	return t.Tx.QueryRow(ctx, sql, args...)
}

// TestPgxStore_RecoveryAttemptsAbsentRowNoLostUpdate proves the store-level contract: a burst of
// concurrent increments on an absent row must yield unique, monotonically increasing counts and
// persist every increment (no lost update).
func TestPgxStore_RecoveryAttemptsAbsentRowNoLostUpdate(t *testing.T) {
	ctx := context.Background()
	const burst = 10
	pool := racePool(t, 4*burst)
	installSlowRecoveryWriteTrigger(t, pool)

	db := newSyncingDB(pool, burst)
	kek, err := keystore.NewKEK(randomKEKKey(t))
	require.NoError(t, err)
	store := mfapgx.NewStore(db, kek)

	tenant := "tenant-race"
	uid := uuid.Must(uuid.NewV7())
	now := time.Now()

	results := make([]int, burst)
	errs := make([]error, burst)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = store.IncrementRecoveryAttempts(ctx, tenant, uid, now, 0, 0)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d", i)
	}
	var persisted int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT failed_attempts FROM mfa_recovery_attempts WHERE tenant_id = $1 AND user_id = $2`,
		tenant, uid).Scan(&persisted))
	t.Logf("returned counts=%v persisted failed_attempts=%d", results, persisted)

	seen := map[int]int{}
	for _, n := range results {
		seen[n]++
	}
	assert.Len(t, seen, burst,
		"each concurrent caller must receive a unique, monotonically increasing count; got %v", results)
	assert.Equal(t, burst, persisted,
		"every concurrent increment must be persisted exactly once (no lost update)")
}

// countingStore counts how many wrong guesses actually reached the recovery-code comparison.
type countingStore struct {
	mfa.Store
	consumeCalls atomic.Int64
}

func (c *countingStore) ConsumeRecoveryCode(ctx context.Context, tenantID string, userID uuid.UUID, codeHash string) error {
	c.consumeCalls.Add(1)
	return c.Store.ConsumeRecoveryCode(ctx, tenantID, userID, codeHash)
}

// TestPgxStore_RecoveryLockoutConcurrentBurstEnforced is the service-level proof: with
// maxAttempts=3, a burst of 10 concurrent wrong recovery codes must reach the comparison at most 3
// times, and the persisted counter must reflect the whole burst.
func TestPgxStore_RecoveryLockoutConcurrentBurstEnforced(t *testing.T) {
	ctx := context.Background()
	const (
		maxAttempts = 3
		burst       = 10
	)
	pool := racePool(t, 4*burst)
	installSlowRecoveryWriteTrigger(t, pool)

	db := newSyncingDB(pool, burst)
	kek, err := keystore.NewKEK(randomKEKKey(t))
	require.NoError(t, err)
	counting := &countingStore{Store: mfapgx.NewStore(db, kek)}
	svc := mfa.NewService(counting, mfa.WithMaxAttempts(maxAttempts))

	tenant := "tenant-lockout"
	uid := uuid.Must(uuid.NewV7())

	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, burst)
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = svc.VerifyRecoveryCode(ctx, tenant, uid, "wrong-code")
		}(i)
	}
	close(start)
	wg.Wait()

	var persisted int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT failed_attempts FROM mfa_recovery_attempts WHERE tenant_id = $1 AND user_id = $2`,
		tenant, uid).Scan(&persisted))
	t.Logf("comparisons=%d persisted=%d errors=%v", counting.consumeCalls.Load(), persisted, errs)

	assert.LessOrEqual(t, counting.consumeCalls.Load(), int64(maxAttempts),
		"a concurrent burst must not let more than maxAttempts guesses reach the recovery-code comparison")
	assert.Greater(t, persisted, maxAttempts,
		"the persisted recovery-attempt counter must exceed maxAttempts after an over-limit burst")
}
