package tokens_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	tokensstore "github.com/JLugagne/egauth/adapters/pgx/store/tokens"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/tokens"
	"github.com/JLugagne/egauth/store/tokens/storetest"
)

func travel(t *testing.T, _ tokens.Store, d time.Duration) {
	t.Helper()
	ctx := context.Background()
	for _, q := range []string{
		`UPDATE egauth_refresh_tokens SET idle_expires_at = idle_expires_at - $1::bigint * interval '1 microsecond',
    family_expires_at = family_expires_at - $1::bigint * interval '1 microsecond',
    created_at = created_at - $1::bigint * interval '1 microsecond',
    consumed_at = consumed_at - $1::bigint * interval '1 microsecond',
    revoked_at = revoked_at - $1::bigint * interval '1 microsecond'`,
		`UPDATE egauth_revocations SET created_at = created_at - $1::bigint * interval '1 microsecond',
    expires_at = expires_at - $1::bigint * interval '1 microsecond'`,
		`UPDATE tokens SET created_at = created_at - $1::bigint * interval '1 microsecond',
    expires_at = expires_at - $1::bigint * interval '1 microsecond',
    revoked_at = revoked_at - $1::bigint * interval '1 microsecond'`,
	} {
		_, err := shared.pool.Exec(ctx, q, d.Microseconds())
		require.NoError(t, err)
	}
}

func TestStoreConformance(t *testing.T) {
	storetest.Seed(t, storetest.Fixtures{Restore: tokens.RestoreRefreshRecord, Travel: travel})
	storetest.Run(t, func(t *testing.T) tokens.Store { return tokensstore.New(cleanPool(t)) })
}

func TestStoreIsShared(t *testing.T) {
	s := tokensstore.New(cleanPool(t))
	require.Equal(t, store.Shared, s.Durability())
	require.NoError(t, s.Ping(context.Background()))
}

var issued = time.Now().UTC().Truncate(time.Microsecond)

func record(t *testing.T, sub principal.Subject, lineage, family uuid.UUID, fp string, seed byte) tokens.RefreshRecord {
	t.Helper()
	sum := sha256.Sum256([]byte{seed, 0x7a})
	now := issued
	r, err := tokens.RestoreRefreshRecord(tokens.RefreshRow{
		TokenHash: sum[:], Family: family, Subject: sub, Lineage: lineage,
		Sealed: principal.SealedFromBytes([]byte("sealed")), ClientFingerprint: []byte(fp),
		IdleExpiresAt: now.Add(time.Hour), FamilyExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
	})
	require.NoError(t, err)
	return r
}

func TestReuseDecisionIsSharedAcrossInstances(t *testing.T) {
	pool := cleanPool(t)
	first, second := tokensstore.New(pool), tokensstore.New(pool)
	ctx := context.Background()
	tn, err := principal.ParseTenantID("t")
	require.NoError(t, err)
	sub := principal.Subject{Tenant: tn, User: uuid.New()}
	lineage, family := uuid.New(), uuid.New()
	a := record(t, sub, lineage, family, "client", 1)
	require.NoError(t, first.Create(ctx, a))
	_, err = first.ConsumeForRotation(ctx, tokens.RotationRequest{Presented: a.TokenHash(), Next: record(t, sub, lineage, family, "client", 2)})
	require.NoError(t, err)

	_, err = second.ConsumeForRotation(ctx, tokens.RotationRequest{Presented: a.TokenHash(), Next: record(t, sub, lineage, family, "client", 3)})
	require.ErrorIs(t, err, tokens.ErrConcurrent, "the consuming client is persisted, not remembered by one process (T-21)")
	_, err = second.ConsumeForRotation(ctx, tokens.RotationRequest{Presented: a.TokenHash(), Next: record(t, sub, lineage, family, "thief", 4)})
	require.ErrorIs(t, err, tokens.ErrReused)
	st, err := first.FamilyState(ctx, tn, family)
	require.NoError(t, err)
	require.True(t, st.Revoked)
}

func TestConsumptionIsStampedWithTheDatabaseClock(t *testing.T) {
	pool := cleanPool(t)
	s := tokensstore.New(pool)
	ctx := context.Background()
	tn, err := principal.ParseTenantID("t")
	require.NoError(t, err)
	sub := principal.Subject{Tenant: tn, User: uuid.New()}
	lineage, family := uuid.New(), uuid.New()
	a := record(t, sub, lineage, family, "client", 5)
	require.NoError(t, s.Create(ctx, a))
	rot, err := s.ConsumeForRotation(ctx, tokens.RotationRequest{Presented: a.TokenHash(), Next: record(t, sub, lineage, family, "client", 6)})
	require.NoError(t, err)
	var stored time.Time
	var by []byte
	require.NoError(t, pool.QueryRow(ctx, `SELECT consumed_at, consumed_by FROM egauth_refresh_tokens WHERE hash = $1`, a.TokenHash()).Scan(&stored, &by))
	require.True(t, rot.ConsumedAt.Equal(stored))
	require.Equal(t, []byte("client"), by)
	var dbNow time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT now()`).Scan(&dbNow))
	require.WithinDuration(t, dbNow, stored, time.Minute)
}
