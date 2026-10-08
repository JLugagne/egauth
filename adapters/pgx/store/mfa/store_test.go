package mfa_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mfastore "github.com/JLugagne/egauth/adapters/pgx/store/mfa"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/mfa/storetest"
)

func seedV016(t *testing.T, _ mfa.Store, sub principal.Subject, sealed []byte) {
	t.Helper()
	_, err := shared.pool.Exec(context.Background(), `INSERT INTO mfa_totp (tenant_id, user_id, secret, created_at) VALUES ($1, $2, $3, now())`,
		sub.Tenant.String(), sub.User, base64.StdEncoding.EncodeToString(sealed))
	require.NoError(t, err)
}

func TestStoreConformance(t *testing.T) {
	storetest.Seed(t, storetest.Fixtures{SeedV016: seedV016})
	storetest.Run(t, func(t *testing.T) mfa.Store { return mfastore.New(cleanPool(t)) })
}

func TestStoreIsShared(t *testing.T) {
	s := mfastore.New(cleanPool(t))
	require.Equal(t, store.Shared, s.Durability())
	require.NoError(t, s.Ping(context.Background()))
}

func TestV016RowsAreLegacyUntilResealed(t *testing.T) {
	ctx := context.Background()
	pool := cleanPool(t)
	s := mfastore.New(pool)
	tn, err := principal.ParseTenantID("t")
	require.NoError(t, err)
	sub := principal.Subject{Tenant: tn, User: uuid.New()}
	_, err = pool.Exec(ctx, `INSERT INTO mfa_totp (tenant_id, user_id, secret, confirmed_at, last_used_step, created_at)
VALUES ('t', $1, $2, now(), 77, now())`, sub.User, base64.StdEncoding.EncodeToString([]byte("v016-blob")))
	require.NoError(t, err)

	got, err := s.GetTOTP(ctx, sub)
	require.NoError(t, err)
	require.Equal(t, mfa.AADVersionLegacy, got.AADVersion)
	require.Equal(t, []byte("v016-blob"), got.Sealed)
	require.EqualValues(t, 77, got.LastUsedStep)
	require.True(t, got.Confirmed())
	n, err := s.CountLegacySealed(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)

	ok, err := s.ReplaceSealed(ctx, mfa.Reseal{Ref: mfa.SealedRef{Subject: sub}, Old: []byte("v016-blob"), New: []byte("v017")})
	require.NoError(t, err)
	require.True(t, ok)
	n, err = s.CountLegacySealed(ctx)
	require.NoError(t, err)
	require.Zero(t, n)
}

func TestStoredSecretIsTheOpaqueBytes(t *testing.T) {
	ctx := context.Background()
	pool := cleanPool(t)
	s := mfastore.New(pool)
	tn, err := principal.ParseTenantID("t")
	require.NoError(t, err)
	sub := principal.Subject{Tenant: tn, User: uuid.New()}
	sealed := bytes.Repeat([]byte{0xfe, 0x01}, 40)
	require.NoError(t, s.SaveTOTP(ctx, mfa.Enrollment{Subject: sub, Sealed: sealed, AADVersion: mfa.AADVersionCurrent, CreatedAt: time.Now()}))
	var secret string
	var version int16
	require.NoError(t, pool.QueryRow(ctx, `SELECT secret, aad_version FROM mfa_totp WHERE user_id = $1`, sub.User).Scan(&secret, &version))
	require.Equal(t, base64.StdEncoding.EncodeToString(sealed), secret)
	require.EqualValues(t, 1, version)
}

func TestRecoveryCodesAreStoredAsGiven(t *testing.T) {
	ctx := context.Background()
	pool := cleanPool(t)
	s := mfastore.New(pool)
	tn, err := principal.ParseTenantID("t")
	require.NoError(t, err)
	sub := principal.Subject{Tenant: tn, User: uuid.New()}
	require.NoError(t, s.ReplaceRecoveryCodes(ctx, sub, []string{"hash-a", "hash-b"}))
	var hashes []string
	rows, err := pool.Query(ctx, `SELECT code_hash FROM mfa_recovery_codes WHERE user_id = $1 ORDER BY code_hash`, sub.User)
	require.NoError(t, err)
	for rows.Next() {
		var h string
		require.NoError(t, rows.Scan(&h))
		hashes = append(hashes, h)
	}
	require.NoError(t, rows.Err())
	require.Equal(t, []string{"hash-a", "hash-b"}, hashes)
}

func TestMigration005IsIdempotent(t *testing.T) {
	pool := cleanPool(t)
	sql, err := mfastore.Migrations.ReadFile("migrations/005_kek_v1.sql")
	require.NoError(t, err)
	_, err = pool.Exec(context.Background(), string(sql))
	require.NoError(t, err)
	_, err = pool.Exec(context.Background(), string(sql))
	require.NoError(t, err)
}
