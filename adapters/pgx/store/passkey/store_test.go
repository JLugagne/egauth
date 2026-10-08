package passkey_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	passkeystore "github.com/JLugagne/egauth/adapters/pgx/store/passkey"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/passkey"
	"github.com/JLugagne/egauth/store/passkey/storetest"
)

func TestStoreConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) passkey.Store { return passkeystore.New(cleanPool(t)) })
}

func TestStoreIsShared(t *testing.T) {
	s := passkeystore.New(cleanPool(t))
	require.Equal(t, store.Shared, s.Durability())
	require.NoError(t, s.Ping(context.Background()))
}

func TestV016RowsReadAsLegacyAndActive(t *testing.T) {
	ctx := context.Background()
	pool := cleanPool(t)
	s := passkeystore.New(pool)
	tn, err := principal.ParseTenantID("t")
	require.NoError(t, err)
	sub := principal.Subject{Tenant: tn, User: uuid.New()}
	_, err = pool.Exec(ctx, `INSERT INTO passkey_credentials (tenant_id, user_id, credential_id, public_key, sign_count, data, created_at)
VALUES ('t', $1, '\x0102', '\x03', 12, '\x04', now())`, sub.User)
	require.NoError(t, err)

	got, err := s.Get(ctx, tn, passkey.CredentialID{1, 2})
	require.NoError(t, err)
	require.Equal(t, passkey.Legacy, got.Discoverable, "a v0.16 row predates residency")
	require.True(t, got.Discoverable.NeedsReregistration())
	require.Nil(t, got.SuspendedAt)
	require.EqualValues(t, 12, got.SignCount)
	ok, err := s.HasActive(ctx, sub)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestMigration004IsIdempotent(t *testing.T) {
	pool := cleanPool(t)
	sql, err := passkeystore.Migrations.ReadFile("migrations/004_discoverable_suspend.sql")
	require.NoError(t, err)
	_, err = pool.Exec(context.Background(), string(sql))
	require.NoError(t, err)
	_, err = pool.Exec(context.Background(), string(sql))
	require.NoError(t, err)
}

func TestSuspendedAtKeepsTheFirstInstantAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	s := passkeystore.New(cleanPool(t))
	tn, err := principal.ParseTenantID("t")
	require.NoError(t, err)
	sub := principal.Subject{Tenant: tn, User: uuid.New()}
	first := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, s.Save(ctx, passkey.Credential{Subject: sub, ID: passkey.CredentialID("a"), PublicKey: []byte("k"), CreatedAt: first}))
	require.NoError(t, s.Suspend(ctx, sub, passkey.CredentialID("a"), first))
	require.NoError(t, s.Suspend(ctx, sub, passkey.CredentialID("a"), first.Add(time.Hour)))
	got, err := s.Get(ctx, tn, passkey.CredentialID("a"))
	require.NoError(t, err)
	require.True(t, first.Equal(*got.SuspendedAt))
}
