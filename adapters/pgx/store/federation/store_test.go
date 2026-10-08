package federation_test

import (
	"context"
	"encoding/base64"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	federationstore "github.com/JLugagne/egauth/adapters/pgx/store/federation"
	identitystore "github.com/JLugagne/egauth/adapters/pgx/store/identity"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/federation"
	"github.com/JLugagne/egauth/store/federation/storetest"
)

func seedV016(t *testing.T, _ federation.Store, p federation.ProviderSpec) {
	t.Helper()
	domains := p.Domains
	if domains == nil {
		domains = []string{}
	}
	_, err := shared.pool.Exec(context.Background(), `INSERT INTO oauth_oidc_providers
    (tenant_id, provider_name, client_id, client_secret, aad_version, auth_url, token_url, user_info_url,
     scopes, issuer, jwks_url, domains, email_verification)
VALUES ($1, $2, $3, $4, 0, $5, $6, $7, $8, $9, $10, $11, $12)`,
		p.Tenant.String(), p.Name, p.ClientID, base64.StdEncoding.EncodeToString(p.SealedSecret), p.AuthURL, p.TokenURL,
		p.UserInfoURL, strings.Join(p.Scopes, " "), p.Issuer, p.JWKSURL, domains, int16(p.EmailVerification))
	require.NoError(t, err)
}

func seedUser(t *testing.T, sub principal.Subject, deleted bool) {
	t.Helper()
	_, err := shared.pool.Exec(context.Background(), `INSERT INTO users (id, tenant_id, email, created_at, updated_at, deleted_at)
VALUES ($1, $2, $3, now(), now(), CASE WHEN $4 THEN now() END) ON CONFLICT (id) DO NOTHING`,
		sub.User, sub.Tenant.String(), sub.User.String()+"@seed.invalid", deleted)
	require.NoError(t, err)
}

func newAccount(t *testing.T, s federation.Store, tn principal.TenantID) principal.Subject {
	t.Helper()
	sub := principal.Subject{Tenant: tn, User: uuid.New()}
	seedUser(t, sub, false)
	seedPassword(t, sub)
	return sub
}

func tombstone(t *testing.T, _ federation.Store, sub principal.Subject) {
	t.Helper()
	tag, err := shared.pool.Exec(context.Background(), `UPDATE users SET deleted_at = now() WHERE id = $1 AND tenant_id = $2`,
		sub.User, sub.Tenant.String())
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
}

func seedLink(t *testing.T, _ federation.Store, l federation.LinkedIdentity) {
	t.Helper()
	seedUser(t, l.Subject, false)
	var email *string
	if l.ProviderEmail != "" {
		email = &l.ProviderEmail
	}
	_, err := shared.pool.Exec(context.Background(), `INSERT INTO identities
    (id, user_id, tenant_id, provider, provider_id, provider_email, provider_email_verified, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)`,
		uuid.New(), l.Subject.User, l.Subject.Tenant.String(), l.Key.Provider, l.Key.ProviderSubject, email,
		l.ProviderEmailVerified, l.LinkedAt)
	require.NoError(t, err)
}

func TestStoreConformance(t *testing.T) {
	storetest.Seed(t, storetest.Fixtures{SeedV016: seedV016, NewAccount: newAccount, SeedLink: seedLink, Tombstone: tombstone})
	storetest.Run(t, func(t *testing.T) federation.Store { return federationstore.New(cleanPool(t)) })
}

func TestStoreIsShared(t *testing.T) {
	s := federationstore.New(cleanPool(t))
	require.Equal(t, store.Shared, s.Durability())
	require.NoError(t, s.Ping(context.Background()))
}

func tenant(t *testing.T, name string) principal.TenantID {
	t.Helper()
	id, err := principal.ParseTenantID(name)
	require.NoError(t, err)
	return id
}

func seedPassword(t *testing.T, sub principal.Subject) {
	t.Helper()
	_, err := shared.pool.Exec(context.Background(), `INSERT INTO identities
    (id, user_id, tenant_id, provider, provider_id, password_hash, created_at, updated_at)
VALUES ($1, $2, $3, 'password', $4, 'phc', now(), now())`, uuid.New(), sub.User, sub.Tenant.String(), sub.User.String())
	require.NoError(t, err)
}

func TestLinksExcludePasswordAndTombstonedAccounts(t *testing.T) {
	ctx := context.Background()
	s := federationstore.New(cleanPool(t))
	alice := principal.Subject{Tenant: tenant(t, "tenant-a"), User: uuid.New()}
	seedUser(t, alice, false)
	seedPassword(t, alice)
	seedLink(t, s, federation.LinkedIdentity{Subject: alice, Key: federation.LinkKey{Provider: "google", ProviderSubject: "g-1"}})

	_, err := s.FindLinked(ctx, alice.Tenant, federation.LinkKey{Provider: "password", ProviderSubject: alice.User.String()})
	require.ErrorIs(t, err, store.ErrNotFound, "a password credential is never a federated link")
	list, err := s.LinkedFor(ctx, alice)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, "google", list[0].Key.Provider)

	gone := principal.Subject{Tenant: alice.Tenant, User: uuid.New()}
	seedUser(t, gone, true)
	seedLink(t, s, federation.LinkedIdentity{Subject: gone, Key: federation.LinkKey{Provider: "google", ProviderSubject: "g-gone"}})
	_, err = s.FindLinked(ctx, gone.Tenant, federation.LinkKey{Provider: "google", ProviderSubject: "g-gone"})
	require.ErrorIs(t, err, store.ErrNotFound, "a tombstoned account cannot be logged into through its link")

	require.NoError(t, s.DeleteForSubject(ctx, alice))
	require.NoError(t, s.EraseTenant(ctx, alice.Tenant))
	var passwords int
	require.NoError(t, shared.pool.QueryRow(ctx, `SELECT count(*) FROM identities WHERE provider = 'password'`).Scan(&passwords))
	require.Equal(t, 1, passwords, "the identity store owns the password credential")
}

func TestUnverifiedEmailIsNeverReportedVerified(t *testing.T) {
	ctx := context.Background()
	s := federationstore.New(cleanPool(t))
	sub := principal.Subject{Tenant: tenant(t, "tenant-a"), User: uuid.New()}
	seedLink(t, s, federation.LinkedIdentity{Subject: sub, Key: federation.LinkKey{Provider: "github", ProviderSubject: "1"}, ProviderEmailVerified: true})
	got, err := s.FindLinked(ctx, sub.Tenant, federation.LinkKey{Provider: "github", ProviderSubject: "1"})
	require.NoError(t, err)
	require.False(t, got.ProviderEmailVerified, "a verified flag without an email verifies nothing")
}

func legacyOnly(t *testing.T) fs.FS {
	t.Helper()
	raw, err := fs.ReadFile(federationstore.Migrations, "migrations/001_init.sql")
	require.NoError(t, err)
	return fstest.MapFS{"migrations/001_init.sql": &fstest.MapFile{Data: raw}}
}

func TestMigrationKeepsV016Rows(t *testing.T) {
	ctx := context.Background()
	pool := emptyDatabase(t)
	require.NoError(t, migrate.Run(ctx, pool, []migrate.Module{{Name: "federation", FS: legacyOnly(t)}}))
	_, err := pool.Exec(ctx, `INSERT INTO oauth_oidc_providers
    (tenant_id, provider_name, client_id, client_secret, auth_url, token_url, issuer, jwks_url, scopes)
VALUES ('tenant-a', 'google', 'cid', $1, 'https://a', 'https://t', 'https://i', 'https://j', 'openid email')`,
		base64.StdEncoding.EncodeToString([]byte{1, 2, 3}))
	require.NoError(t, err)
	modules := []migrate.Module{{Name: "identity", FS: identitystore.Migrations}, {Name: "federation", FS: federationstore.Migrations}}
	require.NoError(t, migrate.Run(ctx, pool, modules))
	require.NoError(t, migrate.Run(ctx, pool, modules), "a re-run is a no-op")

	s := federationstore.New(pool)
	require.NoError(t, s.Ping(ctx))
	n, err := s.CountLegacySealed(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "a v0.16 row is legacy-sealed")
	p, err := s.GetProvider(ctx, tenant(t, "tenant-a"), "google")
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 3}, p.SealedSecret)
	require.Equal(t, []string{"openid", "email"}, p.Scopes)
	require.Equal(t, "https://i", p.Issuer)
	require.Equal(t, federation.Never, p.EmailVerification, "a v0.16 provider trusts no email claim")
	require.Empty(t, p.Domains)
	rows, cur, err := s.V016Sealed(ctx, store.Cursor{}, 10)
	require.NoError(t, err)
	require.Equal(t, []federation.V016Row{{Ref: federation.SealedRef{Tenant: tenant(t, "tenant-a"), Provider: "google"}, Sealed: []byte{1, 2, 3}}}, rows)
	require.False(t, cur.IsZero(), "existing rows get a listing position")
}

func TestPingRequiresTheIdentitySchema(t *testing.T) {
	ctx := context.Background()
	pool := emptyDatabase(t)
	require.NoError(t, migrate.Run(ctx, pool, []migrate.Module{{Name: "federation", FS: federationstore.Migrations}}))
	require.Error(t, federationstore.New(pool).Ping(ctx), "links are read from the identity tables, so a missing identity schema fails Ping")
	require.NoError(t, migrate.Run(ctx, pool, []migrate.Module{{Name: "identity", FS: identitystore.Migrations}}))
	require.NoError(t, federationstore.New(pool).Ping(ctx))
}
