package keystore_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	pgxkeystore "github.com/JLugagne/egauth/adapters/pgx/keystore"
	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/keystore/keystoretest"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// startPostgres spins up a throwaway Postgres via testcontainers and applies the keystore
// migrations. It skips under -short (no Docker).
func startPostgres(t *testing.T) *pgxpool.Pool {
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

	require.NoError(t, pgxkeystore.Migrate(ctx, pool))
	return pool
}

// newManager builds a keystore.Manager over the pgx Store with a test KEK.
func newManager(t *testing.T, pool *pgxpool.Pool) *keystore.Manager {
	t.Helper()
	kek, err := keystore.NewKEK(bytes.Repeat([]byte("k"), keystore.KEKKeyLength))
	require.NoError(t, err)
	mgr, err := keystore.NewManager(pgxkeystore.NewStore(pool), kek)
	require.NoError(t, err)
	return mgr
}

// TestPgxKeystore_StoreContract runs the SHARED cross-backend conformance suite
// (keystoretest.StoreContractTesting) against the real Postgres backend, so the pgx store is held
// to exactly the same contract as the in-memory one — including the sentinel rules that make an
// emergency revocation stick. Each subtest gets a truncated (fresh, empty) store bound to the
// suite's clock.
func TestPgxKeystore_StoreContract(t *testing.T) {
	pool := startPostgres(t)
	keystoretest.StoreContractTesting(t, func(now func() time.Time) keystore.Store {
		if _, err := pool.Exec(context.Background(), `TRUNCATE keystore_keys, keystore_tenants`); err != nil {
			panic(errors.Join(errors.New("truncate keystore tables between contract subtests"), err))
		}
		return pgxkeystore.NewStore(pool, pgxkeystore.WithClock(now))
	})
}

// TestPgxKeystore_Lifecycle exercises provision / active+verify / rotate / revoke / delete and
// cross-tenant isolation end-to-end against a real Postgres with the default (wall-clock) time
// source, complementing the fixed-clock contract suite above.
func TestPgxKeystore_Lifecycle(t *testing.T) {
	pool := startPostgres(t)
	ctx := context.Background()
	mgr := newManager(t, pool)

	// Provision is idempotent.
	require.NoError(t, mgr.ProvisionTenant(ctx, "a"))
	require.NoError(t, mgr.ProvisionTenant(ctx, "a"))
	require.NoError(t, mgr.ProvisionTenant(ctx, "b"))

	aKey, err := mgr.ActiveSigningKey(ctx, "a")
	require.NoError(t, err)
	bKey, err := mgr.ActiveSigningKey(ctx, "b")
	require.NoError(t, err)

	// Cross-tenant isolation: distinct ids and secrets; no leakage across verification sets.
	require.NotEqual(t, aKey.KeyID, bKey.KeyID)
	require.False(t, bytes.Equal(aKey.Secret, bKey.Secret))
	require.Len(t, aKey.Secret, 32, "secret must be decrypted to 32 bytes")

	bVerify, err := mgr.VerificationKeys(ctx, "b")
	require.NoError(t, err)
	_, leaked := bVerify[aKey.KeyID]
	require.False(t, leaked, "A's key must not appear in B's verification set")

	// Sealed at rest: the raw store row must hold the sealed (longer) secret, not plaintext.
	rawStore := pgxkeystore.NewStore(pool)
	raw, err := rawStore.ActiveSigningKey(ctx, "a")
	require.NoError(t, err)
	require.False(t, bytes.Equal(raw.Secret, aKey.Secret), "DB must store the sealed secret")
	require.Greater(t, len(raw.Secret), len(aKey.Secret))

	// Rotate A: new active key, old key kept verify-only; B untouched.
	require.NoError(t, mgr.RenewSigningKey(ctx, "a", func(o *keystore.RenewOptions) {
		o.OverlapTTL = time.Hour
	}))
	aKey2, err := mgr.ActiveSigningKey(ctx, "a")
	require.NoError(t, err)
	require.NotEqual(t, aKey.KeyID, aKey2.KeyID)
	aVerify, err := mgr.VerificationKeys(ctx, "a")
	require.NoError(t, err)
	require.Contains(t, aVerify, aKey.KeyID, "old key stays verify-only during overlap")
	require.Contains(t, aVerify, aKey2.KeyID)
	bKeyAfter, err := mgr.ActiveSigningKey(ctx, "b")
	require.NoError(t, err)
	require.Equal(t, bKey.KeyID, bKeyAfter.KeyID, "rotating A must not affect B")

	// Revoke A's keys: no active key remains; B intact.
	require.NoError(t, mgr.RevokeTenantKeys(ctx, "a"))
	_, err = mgr.ActiveSigningKey(ctx, "a")
	require.Error(t, err)
	_, err = mgr.ActiveSigningKey(ctx, "b")
	require.NoError(t, err)

	// Delete A: fully purged; B untouched.
	require.NoError(t, mgr.DeleteTenant(ctx, "a"))
	existsA, err := rawStore.TenantExists(ctx, "a")
	require.NoError(t, err)
	require.False(t, existsA)
	existsB, err := rawStore.TenantExists(ctx, "b")
	require.NoError(t, err)
	require.True(t, existsB)

	// Delete is idempotent.
	require.NoError(t, mgr.DeleteTenant(ctx, "a"))
}

// TestPgxKeystore_TenantMismatchGuard: the store fails closed on a contradictory tenant id.
func TestPgxKeystore_TenantMismatchGuard(t *testing.T) {
	pool := startPostgres(t)
	ctx := context.Background()
	store := pgxkeystore.NewStore(pool)
	err := store.PutSigningKey(ctx, "acme", keystore.SigningKey{KeyID: "k1", TenantID: "other", Secret: []byte("x")})
	require.True(t, errors.Is(err, keystore.ErrTenantMismatch))
}

// TestPgxKeystore_AlgRoundTrip asserts a non-default Alg survives the insert/scan cycle on both
// the active and verification read paths (migration 002 + alg column wiring).
func TestPgxKeystore_AlgRoundTrip(t *testing.T) {
	pool := startPostgres(t)
	ctx := context.Background()
	store := pgxkeystore.NewStore(pool)
	key := keystore.SigningKey{
		KeyID:     "rsa-1",
		TenantID:  "acme",
		Secret:    []byte("sealed-pkcs8-der-stand-in"),
		CreatedAt: time.Now(),
		Alg:       "RS256",
	}
	require.NoError(t, store.PutSigningKey(ctx, "acme", key))

	active, err := store.ActiveSigningKey(ctx, "acme")
	require.NoError(t, err)
	require.Equal(t, "RS256", active.Alg)

	verify, err := store.VerificationKeys(ctx, "acme")
	require.NoError(t, err)
	require.Contains(t, verify, "rsa-1")
	require.Equal(t, "RS256", verify["rsa-1"].Alg)
}

// TestPgxKeystore_DefaultAlgForLegacyRow asserts a row inserted without an explicit alg relies on
// the column default and scans back as HS256 (backward compat for pre-migration rows).
func TestPgxKeystore_DefaultAlgForLegacyRow(t *testing.T) {
	pool := startPostgres(t)
	ctx := context.Background()
	// Insert directly without the alg column so the DEFAULT 'HS256' applies, simulating a row
	// written before migration 002. The tenant record is inserted first because migration 003 makes
	// keystore_keys.tenant_id a foreign key onto keystore_tenants.
	_, err := pool.Exec(ctx,
		`INSERT INTO keystore_tenants (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING`, "legacy")
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`INSERT INTO keystore_keys (tenant_id, key_id, secret, created_at) VALUES ($1, $2, $3, now())`,
		"legacy", "k1", []byte("sealed"))
	require.NoError(t, err)

	store := pgxkeystore.NewStore(pool)
	active, err := store.ActiveSigningKey(ctx, "legacy")
	require.NoError(t, err)
	require.Equal(t, "HS256", active.Alg)
}

// TestPgxKeystore_Migrate_Idempotent asserts re-running the migrations, and re-applying the
// tenant-table migration body on its own (the case the runner tolerates when a crash loses the
// version row), is a no-op that keeps existing tenant records.
func TestPgxKeystore_Migrate_Idempotent(t *testing.T) {
	pool := startPostgres(t)
	ctx := context.Background()
	store := pgxkeystore.NewStore(pool)
	require.NoError(t, store.CreateTenant(ctx, "acme", keystore.SigningKey{
		KeyID: "k1", Secret: []byte("sealed"), CreatedAt: time.Now(),
	}))

	require.NoError(t, pgxkeystore.Migrate(ctx, pool))

	body, err := pgxkeystore.MigrationsFS.ReadFile("migrations/003_create_keystore_tenants_table.sql")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, string(body))
	require.NoError(t, err)

	exists, err := store.TenantExists(ctx, "acme")
	require.NoError(t, err)
	require.True(t, exists, "re-applying the migration must not drop tenant records")
	active, err := store.ActiveSigningKey(ctx, "acme")
	require.NoError(t, err)
	require.Equal(t, "k1", active.KeyID)
}

// TestPgxKeystore_RevokeKeepsTenantRecord pins the durable-revocation invariant at the SQL level:
// revoking deletes key rows but keeps the tenant row, so the sentinels stay ErrNoActiveKey.
func TestPgxKeystore_RevokeKeepsTenantRecord(t *testing.T) {
	pool := startPostgres(t)
	ctx := context.Background()
	store := pgxkeystore.NewStore(pool)
	require.NoError(t, store.CreateTenant(ctx, "acme", keystore.SigningKey{
		KeyID: "k1", Secret: []byte("sealed"), CreatedAt: time.Now(),
	}))
	require.NoError(t, store.RevokeTenantKeys(ctx, "acme"))

	exists, err := store.TenantExists(ctx, "acme")
	require.NoError(t, err)
	require.True(t, exists, "a revoked tenant must still exist")

	_, err = store.ActiveSigningKey(ctx, "acme")
	require.True(t, errors.Is(err, keystore.ErrNoActiveKey), "got %v", err)

	verify, err := store.VerificationKeys(ctx, "acme")
	require.NoError(t, err, "VerificationKeys must publish an empty set after a revoke")
	require.Empty(t, verify)

	var keyRows, tenantRows int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM keystore_keys WHERE tenant_id = $1`, "acme").Scan(&keyRows))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM keystore_tenants WHERE tenant_id = $1`, "acme").Scan(&tenantRows))
	require.Zero(t, keyRows)
	require.Equal(t, 1, tenantRows)

	require.NoError(t, store.DeleteTenant(ctx, "acme"))
	exists, err = store.TenantExists(ctx, "acme")
	require.NoError(t, err)
	require.False(t, exists, "DeleteTenant must remove the tenant record")
}

// TestPgxKeystore_CreateTenant_ConcurrentRace fires N concurrent CreateTenant calls for the SAME
// new tenant id (distinct key ids) and asserts the check-then-insert is atomic: exactly one call
// wins with nil, and every other call observes the tenant already exists (ErrTenantExists) rather
// than both racing past TenantExists and inserting two active signing keys for one tenant.
func TestPgxKeystore_CreateTenant_ConcurrentRace(t *testing.T) {
	pool := startPostgres(t)
	ctx := context.Background()
	store := pgxkeystore.NewStore(pool)

	const tenantID = "race-tenant"
	const n = 6

	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			key := keystore.SigningKey{
				KeyID:     fmt.Sprintf("k%d", i),
				Secret:    []byte("sealed-secret-material-stand-in"),
				CreatedAt: time.Now(),
			}
			results[i] = store.CreateTenant(ctx, tenantID, key)
		}(i)
	}
	close(start)
	wg.Wait()

	var successes, conflicts int
	for _, err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, keystore.ErrTenantExists):
			conflicts++
		default:
			t.Fatalf("unexpected error from concurrent CreateTenant: %v", err)
		}
	}
	require.Equal(t, 1, successes, "exactly one concurrent CreateTenant must win")
	require.Equal(t, n-1, conflicts, "every other concurrent CreateTenant must see ErrTenantExists")

	// The tenant must end up with a single, deterministic active signing key (no duplicate
	// active keys from a lost race).
	key1, err := store.ActiveSigningKey(ctx, tenantID)
	require.NoError(t, err)
	key2, err := store.ActiveSigningKey(ctx, tenantID)
	require.NoError(t, err)
	require.Equal(t, key1.KeyID, key2.KeyID, "ActiveSigningKey must be deterministic")
}
