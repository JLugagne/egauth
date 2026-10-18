package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/store/limiter"
	"github.com/JLugagne/egauth/store/limiter/memory"
	"github.com/JLugagne/egauth/store/limiter/storetest"
)

func TestLimiterConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) limiter.Limiter { return memory.New() })
}

func TestRefillAndReapFollowTheClock(t *testing.T) {
	ctx := context.Background()
	tc := clock.NewTest(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	l := memory.NewWithClock(tc.Clock())
	k := limiter.Key{Class: limiter.SelfTest, Value: "v"}
	for range k.Class.Budget().Burst {
		d, err := l.Allow(ctx, k)
		require.NoError(t, err)
		require.True(t, d.Allowed)
	}
	d, err := l.Allow(ctx, k)
	require.NoError(t, err)
	require.False(t, d.Allowed)
	require.InDelta(t, float64(time.Hour), float64(d.RetryAfter), float64(time.Second))

	tc.Advance(d.RetryAfter)
	d, err = l.Allow(ctx, k)
	require.NoError(t, err)
	require.True(t, d.Allowed, "one token is back after RetryAfter")
	d, err = l.Allow(ctx, k)
	require.NoError(t, err)
	require.False(t, d.Allowed)

	n, err := l.ReapExpired(ctx)
	require.NoError(t, err)
	require.Zero(t, n)
	tc.Advance(time.Duration(k.Class.Budget().Burst) * k.Class.Budget().Refill)
	n, err = l.ReapExpired(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "a bucket that refilled to Burst is dropped")
}

func TestSetInstancesDividesTheBudget(t *testing.T) {
	ctx := context.Background()
	tc := clock.NewTest(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	l := memory.NewWithClock(tc.Clock())
	l.SetInstances(5)
	k := limiter.Key{Class: limiter.LoginClient, Value: "v"}
	want := limiter.LoginClient.Budget().PerInstance(5).Burst
	for i := range want {
		d, err := l.Allow(ctx, k)
		require.NoError(t, err)
		require.True(t, d.Allowed, "call %d", i+1)
	}
	d, err := l.Allow(ctx, k)
	require.NoError(t, err)
	require.False(t, d.Allowed)
	require.Greater(t, d.RetryAfter, limiter.LoginClient.Budget().Refill/2)

	l.SetInstances(0)
	l.SetInstances(1)
}

func TestAnEarlierReadingNeverRefillsABucket(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	tc := clock.NewTest(at)
	l := memory.NewWithClock(tc.Clock())
	k := limiter.Key{Class: limiter.SelfTest, Value: "v"}
	for range k.Class.Budget().Burst {
		_, err := l.Allow(ctx, k)
		require.NoError(t, err)
	}
	tc.Set(at.Add(-k.Class.Budget().Refill))
	d, err := l.Allow(ctx, k)
	require.NoError(t, err)
	require.False(t, d.Allowed)
	tc.Set(at)
	d, err = l.Allow(ctx, k)
	require.NoError(t, err)
	require.False(t, d.Allowed, "a call that read the clock earlier moved the bucket back in time and minted a token")
}
