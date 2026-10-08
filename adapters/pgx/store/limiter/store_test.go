package limiter_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	limiterstore "github.com/JLugagne/egauth/adapters/pgx/store/limiter"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/limiter"
	"github.com/JLugagne/egauth/store/limiter/storetest"
)

func TestLimiterConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) limiter.Limiter { return limiterstore.New(cleanPool(t)) })
}

func TestLimiterIsSharedAndNeverStoresValues(t *testing.T) {
	pool := cleanPool(t)
	l := limiterstore.New(pool)
	require.Equal(t, store.Shared, l.Durability())
	require.NoError(t, l.Ping(context.Background()))

	k := limiter.Key{Class: limiter.LoginClient, Value: "198.51.100.77"}
	d, err := l.Allow(context.Background(), k)
	require.NoError(t, err)
	require.True(t, d.Allowed)
	var rows int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM egauth_ratelimit WHERE key = $1 AND position($2::bytea in key) = 0`,
		k.StorageKey(), []byte(k.Value)).Scan(&rows))
	require.Equal(t, 1, rows, "the bucket is keyed by the StorageKey digest and never contains the value")

	var unlogged string
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT relpersistence::text FROM pg_class WHERE relname = 'egauth_ratelimit'`).Scan(&unlogged))
	require.Equal(t, "u", unlogged)
}

func TestReapDeletesOnlyRefilledBucketsAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	pool := cleanPool(t)
	l := limiterstore.New(pool)
	refilled := limiter.Key{Class: limiter.SelfTest, Value: "refilled"}
	drained := limiter.Key{Class: limiter.SelfTest, Value: "drained"}
	for _, k := range []limiter.Key{refilled, drained} {
		for range k.Class.Budget().Burst {
			d, err := l.Allow(ctx, k)
			require.NoError(t, err)
			require.True(t, d.Allowed)
		}
	}
	budget := limiter.SelfTest.Budget()
	_, err := pool.Exec(ctx, `UPDATE egauth_ratelimit SET updated_at = now() - make_interval(secs => $2::double precision) WHERE key = $1`,
		refilled.StorageKey(), (time.Duration(budget.Burst+1) * budget.Refill).Seconds())
	require.NoError(t, err)

	n, err := l.ReapExpired(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	var left [][]byte
	rows, err := pool.Query(ctx, `SELECT key FROM egauth_ratelimit`)
	require.NoError(t, err)
	for rows.Next() {
		var k []byte
		require.NoError(t, rows.Scan(&k))
		left = append(left, k)
	}
	require.NoError(t, rows.Err())
	require.Equal(t, [][]byte{drained.StorageKey()}, left)
	d, err := l.Allow(ctx, drained)
	require.NoError(t, err)
	require.False(t, d.Allowed, "the drained bucket survived the reap")
}
