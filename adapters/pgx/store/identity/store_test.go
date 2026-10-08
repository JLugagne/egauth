package identity_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	legacypgx "github.com/JLugagne/egauth/adapters/pgx/identity"
	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	identitystore "github.com/JLugagne/egauth/adapters/pgx/store/identity"
	legacycore "github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/identity/storetest"
)

func TestStoreConformance(t *testing.T) {
	storetest.Use(t, hooks(func() *pgxpool.Pool { return shared.pool }))
	storetest.Run(t, func(t *testing.T) identity.Store { return newStore(t) })
}

func TestStoreIsShared(t *testing.T) {
	s := identitystore.New(cleanPool(t))
	require.Equal(t, store.Shared, s.Durability())
	require.NoError(t, s.Ping(context.Background()))
}

func TestPingReportsAMissingMigration(t *testing.T) {
	pool := emptyDatabase(t)
	err := identitystore.New(pool).Ping(context.Background())
	require.Error(t, err)
}

func TestLegacyMigrationsAreTheV016Files(t *testing.T) {
	legacy, err := filepath.Glob(filepath.Join("..", "..", "identity", "migrations", "*.sql"))
	require.NoError(t, err)
	require.Len(t, legacy, 8)
	for _, path := range legacy {
		want, err := os.ReadFile(path)
		require.NoError(t, err)
		got, err := fs.ReadFile(identitystore.Migrations, "migrations/"+filepath.Base(path))
		require.NoError(t, err, "%s must keep its v0.16 name so the bootstrap carries it over", filepath.Base(path))
		idempotent := strings.ReplaceAll(string(want), "CREATE UNIQUE INDEX idx_", "CREATE UNIQUE INDEX IF NOT EXISTS idx_")
		require.Equal(t, idempotent, string(got), "%s must be the v0.16 file, made idempotent only (G16)", filepath.Base(path))
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	ctx := context.Background()
	pool := emptyDatabase(t)
	mods := []migrate.Module{{Name: "identity", FS: identitystore.Migrations}}
	require.NoError(t, migrate.Run(ctx, pool, mods))
	body, err := fs.ReadFile(identitystore.Migrations, "migrations/009_security_epoch.sql")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, string(body))
	require.NoError(t, err, "009 re-run on its own schema is a no-op")
	require.NoError(t, migrate.Run(ctx, pool, mods))
	require.NoError(t, identitystore.New(pool).Ping(ctx))
}

func legacyAccount(t *testing.T, old *legacypgx.Store, email, hash string) principal.Subject {
	t.Helper()
	ctx := context.Background()
	u, err := old.CreateUser(ctx, "acme", email)
	require.NoError(t, err)
	require.NoError(t, old.AddIdentity(ctx, "acme", &legacycore.Identity{
		UserID: u.ID, TenantID: "acme", Provider: "password", ProviderID: email, PasswordHash: &hash,
	}))
	acme, err := principal.ParseTenantID("acme")
	require.NoError(t, err)
	return principal.Subject{Tenant: acme, User: u.ID}
}

func TestUpgradesAV016DatabaseInPlace(t *testing.T) {
	ctx := context.Background()
	pool := emptyDatabase(t)
	require.NoError(t, legacypgx.Migrate(ctx, pool))
	old := legacypgx.NewStore(pool)
	hash := "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$legacy"
	alice := legacyAccount(t, old, "alice@example.com", hash)
	bob := legacyAccount(t, old, "bob@example.com", hash)

	require.NoError(t, migrate.Run(ctx, pool, []migrate.Module{{Name: "identity", FS: identitystore.Migrations}}),
		"the v0.16 files are bootstrapped, never re-run")
	st := identitystore.New(pool)
	require.NoError(t, st.Ping(ctx))

	got, err := st.GetUser(ctx, alice)
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", got.Email.Value())
	require.True(t, got.EmailVerifiedAt.IsZero())
	require.Zero(t, got.SecurityEpoch)
	cred, err := st.GetPassword(ctx, alice)
	require.NoError(t, err)
	require.Equal(t, hash, cred.PHC.PHC())

	a, err := st.Apply(ctx, identity.MarkEmailVerified{Subject: alice, PHC: identity.NewPasswordHash(hash + "2")})
	require.NoError(t, err)
	require.EqualValues(t, 1, a.NewEpoch)
	cred, err = st.GetPassword(ctx, alice)
	require.NoError(t, err)
	require.Equal(t, hash+"2", cred.PHC.PHC())

	_, err = st.Apply(ctx, identity.Tombstone{Subject: bob})
	require.NoError(t, err)
	email, err := identity.NewIdentifier(identity.IdentifierEmail, "bob@example.com")
	require.NoError(t, err)
	fresh, err := st.Apply(ctx, identity.CreateVerified{Tenant: bob.Tenant, Email: email, PHC: identity.NewPasswordHash(hash)})
	require.NoError(t, err, "a tombstone frees the email, even beside its v0.16 password row")
	_, err = st.GetPassword(ctx, fresh.Subject)
	require.NoError(t, err)
}

func TestPendingOutboxSkipsRowsItCannotDecode(t *testing.T) {
	ctx := context.Background()
	pool := cleanPool(t)
	st := identitystore.New(pool)
	acme, err := principal.ParseTenantID("acme")
	require.NoError(t, err)
	email, err := identity.NewIdentifier(identity.IdentifierEmail, "skip@example.com")
	require.NoError(t, err)
	created, err := st.Apply(ctx, identity.CreateVerified{Tenant: acme, Email: email})
	require.NoError(t, err)
	a, err := st.Apply(ctx, identity.Tombstone{Subject: created.Subject})
	require.NoError(t, err)
	require.Greater(t, len(a.Outbox), 4)

	ids := make([]int64, len(a.Outbox))
	for i, it := range a.Outbox {
		ids[i] = it.ID
	}
	for _, q := range []string{
		`UPDATE egauth_lifecycle_outbox SET subscriber = 'bogus' WHERE id = $1`,
		`UPDATE egauth_lifecycle_outbox SET event = 99 WHERE id = $1`,
		`UPDATE egauth_lifecycle_outbox SET payload = '{"keep": 5}' WHERE id = $1`,
		`UPDATE egauth_lifecycle_outbox SET tenant_id = 'NOT A TENANT' WHERE id = $1`,
	} {
		_, err := pool.Exec(ctx, q, ids[0])
		require.NoError(t, err)
		ids = ids[1:]
	}

	got, err := st.PendingOutbox(ctx, 100)
	require.NoError(t, err, "one undecodable row never stalls the dispatcher")
	gotIDs := make([]int64, len(got))
	for i, it := range got {
		gotIDs[i] = it.ID
	}
	require.Equal(t, ids, gotIDs, "the rows this build decodes are returned, the others stay pending")

	first, err := st.PendingOutbox(ctx, 1)
	require.NoError(t, err)
	require.Len(t, first, 1, "undecodable rows ahead never starve the limit")
	require.Equal(t, ids[0], first[0].ID)

	var pending int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM egauth_lifecycle_outbox WHERE done_at IS NULL`).Scan(&pending))
	require.Equal(t, len(a.Outbox), pending, "skipped rows are left for a replica that understands them")
}
