package keys_test

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	keysstore "github.com/JLugagne/egauth/adapters/pgx/store/keys"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/keys"
	"github.com/JLugagne/egauth/store/keys/storetest"
)

func seedV016(t *testing.T, _ keys.Store, k keys.Key) {
	t.Helper()
	var created, notAfter, retired *time.Time
	if !k.CreatedAt.IsZero() {
		created = &k.CreatedAt
	}
	if !k.NotAfter.IsZero() {
		notAfter = &k.NotAfter
	}
	retired = k.RetiredAt
	_, err := shared.pool.Exec(context.Background(), `INSERT INTO keystore_keys
    (tenant_id, key_id, secret, alg, aad_version, created_at, not_after, retired_at)
VALUES ($1, $2, $3, $4, 0, COALESCE($5::timestamptz, now()), $6, $7)`,
		k.Tenant.String(), k.KeyID, k.Sealed, k.Alg, created, notAfter, retired)
	require.NoError(t, err)
}

func ageFeed(t *testing.T, _ keys.Store, d time.Duration) {
	t.Helper()
	_, err := shared.pool.Exec(context.Background(), `UPDATE egauth_key_changes SET created_at = created_at - $1::bigint * interval '1 microsecond'`,
		d.Microseconds())
	require.NoError(t, err)
}

func TestStoreConformance(t *testing.T) {
	storetest.Seed(t, storetest.Fixtures{SeedV016: seedV016, AgeFeed: ageFeed})
	storetest.Run(t, func(t *testing.T) keys.Store { return keysstore.New(cleanPool(t)) })
}

func TestStoreIsShared(t *testing.T) {
	s := keysstore.New(cleanPool(t))
	require.Equal(t, store.Shared, s.Durability())
	require.NoError(t, s.Ping(context.Background()))
}

func tenant(t *testing.T, name string) principal.TenantID {
	t.Helper()
	id, err := principal.ParseTenantID(name)
	require.NoError(t, err)
	return id
}

func current(t *testing.T, tn, id string) keys.Key {
	t.Helper()
	return keys.Key{Tenant: tenant(t, tn), KeyID: id, Alg: "EdDSA", Sealed: []byte("sealed-" + id), AADVersion: keys.AADVersionCurrent}
}

func TestTombstoneIsSharedAcrossInstances(t *testing.T) {
	ctx := context.Background()
	pool := cleanPool(t)
	first, second := keysstore.New(pool), keysstore.New(pool)
	require.NoError(t, first.CreateTenant(ctx, current(t, "tenant-a", "k1")))
	_, cur, err := second.ChangesSince(ctx, store.Cursor{})
	require.NoError(t, err)
	require.NoError(t, first.Tombstone(ctx, tenant(t, "tenant-a")))
	require.ErrorIs(t, second.PutKey(ctx, current(t, "tenant-a", "k2")), keys.ErrTenantTombstoned,
		"a tombstone written by one instance blocks provisioning on every instance (T-13)")
	list, _, err := second.ChangesSince(ctx, cur)
	require.NoError(t, err)
	require.Equal(t, []keys.Change{{Tenant: tenant(t, "tenant-a")}}, list)
}

func TestFeedFollowsCommitOrder(t *testing.T) {
	ctx := context.Background()
	pool := cleanPool(t)
	s := keysstore.New(pool)
	slow, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = slow.Rollback(ctx) }()
	_, err = slow.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('egauth/keys/changes', 0))`)
	require.NoError(t, err)
	_, err = slow.Exec(ctx, `INSERT INTO egauth_key_changes (tenant_id, created_at) VALUES ('tenant-slow', now())`)
	require.NoError(t, err)

	fast := current(t, "tenant-fast", "k1")
	done := make(chan error, 1)
	go func() { done <- s.CreateTenant(ctx, fast) }()
	select {
	case err := <-done:
		t.Fatalf("a feed write must wait for an earlier uncommitted one, got %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	list, cur, err := s.ChangesSince(ctx, store.Cursor{})
	require.NoError(t, err)
	require.Empty(t, list, "no later position is visible while an earlier one is uncommitted (T-15)")
	require.NoError(t, slow.Commit(ctx))
	require.NoError(t, <-done)
	list, _, err = s.ChangesSince(ctx, cur)
	require.NoError(t, err)
	require.Len(t, list, 2, "the late commit is not skipped")
}

func TestReapPrunesOldFeedRows(t *testing.T) {
	ctx := context.Background()
	pool := cleanPool(t)
	s := keysstore.New(pool)
	require.NoError(t, s.CreateTenant(ctx, current(t, "tenant-a", "k1")))
	_, err := pool.Exec(ctx, `UPDATE egauth_key_changes SET created_at = created_at - interval '48 hours'`)
	require.NoError(t, err)
	n, err := s.ReapExpired(ctx)
	require.NoError(t, err)
	require.Zero(t, n, "pruned feed rows are not reaped keys")
	var left int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM egauth_key_changes`).Scan(&left))
	require.Zero(t, left)
}

func legacyOnly(t *testing.T) fs.FS {
	t.Helper()
	out := fstest.MapFS{}
	for _, name := range []string{"001_create_keystore_keys_table.sql", "002_add_key_algorithm.sql"} {
		raw, err := fs.ReadFile(keysstore.Migrations, "migrations/"+name)
		require.NoError(t, err)
		out["migrations/"+name] = &fstest.MapFile{Data: raw}
	}
	return out
}

func TestMigrationKeepsV016Rows(t *testing.T) {
	ctx := context.Background()
	pool := emptyDatabase(t)
	require.NoError(t, migrate.Run(ctx, pool, []migrate.Module{{Name: "keys", FS: legacyOnly(t)}}))
	_, err := pool.Exec(ctx, `INSERT INTO keystore_keys (tenant_id, key_id, secret, created_at, not_after, retired_at, alg)
VALUES ('tenant-a', 'legacy', '\x0102', now() - interval '1 hour', NULL, NULL, 'HS256')`)
	require.NoError(t, err)
	require.NoError(t, migrate.Run(ctx, pool, []migrate.Module{{Name: "keys", FS: keysstore.Migrations}}))
	require.NoError(t, migrate.Run(ctx, pool, []migrate.Module{{Name: "keys", FS: keysstore.Migrations}}), "a re-run is a no-op")

	s := keysstore.New(pool)
	require.NoError(t, s.Ping(ctx))
	n, err := s.CountLegacySealed(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "a v0.16 row is legacy-sealed")
	rows, cur, err := s.V016Sealed(ctx, store.Cursor{}, 10)
	require.NoError(t, err)
	require.Equal(t, []keys.V016Row{{Ref: keys.SealedRef{Tenant: tenant(t, "tenant-a"), KeyID: "legacy"}, Sealed: []byte{1, 2}}}, rows)
	require.False(t, cur.IsZero(), "existing rows get a listing position")
	k, err := s.ActiveKey(ctx, tenant(t, "tenant-a"))
	require.NoError(t, err)
	require.Equal(t, "HS256", k.Alg)
	require.Equal(t, keys.AADVersionLegacy, k.AADVersion)
	dead, err := s.IsTombstoned(ctx, tenant(t, "tenant-a"))
	require.NoError(t, err)
	require.False(t, dead)
}
