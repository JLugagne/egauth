// Package storetest holds the conformance suite of limiter.Limiter implementations.
package storetest

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/limiter"
)

const goroutines = 64

var classes = []limiter.Class{
	limiter.LoginIdentifier, limiter.LoginClient, limiter.CodeRequestIdentifier,
	limiter.CodeRequestClient, limiter.RegisterClient, limiter.SelfTest,
}

// Run exercises the limiter.Limiter contract against limiters returned by newLimiter, at the library
// budgets of each Class. Each subtest gets a fresh limiter. Budgets refill in minutes, so the suite
// observes exhaustion but not refill; implementations test refill with their own clock.
func Run(t *testing.T, newLimiter func(*testing.T) limiter.Limiter) {
	t.Helper()
	suites := map[string]func(*testing.T, limiter.Limiter){
		"Base":               baseSuite,
		"BurstPlusOneDenied": burstPlusOne,
		"InvalidKeys":        invalidKeys,
		"KeyIsolation":       keyIsolation,
		"ConcurrentAllow":    concurrentAllow,
		"EraseTenant":        eraseTenant,
		"ReapKeepsDrained":   reapKeepsDrained,
		"CanceledContext":    canceledContext,
	}
	for name, fn := range suites {
		t.Run(name, func(t *testing.T) { fn(t, newLimiter(t)) })
	}
}

func tenantFor(t *testing.T, c limiter.Class, name string) principal.TenantID {
	t.Helper()
	if !c.PerTenant() {
		return principal.TenantID{}
	}
	id, err := principal.ParseTenantID(name)
	require.NoError(t, err)
	return id
}

func keyFor(t *testing.T, c limiter.Class) limiter.Key {
	t.Helper()
	return limiter.Key{Class: c, Tenant: tenantFor(t, c, "tenant-a"), Value: "value-" + uuid.NewString()}
}

func drain(t *testing.T, l limiter.Limiter, k limiter.Key) {
	t.Helper()
	for range k.Class.Budget().Burst {
		d, err := l.Allow(context.Background(), k)
		require.NoError(t, err)
		require.True(t, d.Allowed)
	}
}

func baseSuite(t *testing.T, l limiter.Limiter) {
	ctx := context.Background()
	require.NoError(t, l.Ping(ctx))
	require.True(t, l.Durability().Valid())
	n, err := l.ReapExpired(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, int64(0))
	require.NoError(t, l.EraseTenant(ctx, principal.TenantID{}))
}

func burstPlusOne(t *testing.T, l limiter.Limiter) {
	ctx := context.Background()
	for _, c := range classes {
		k := keyFor(t, c)
		budget := c.Budget()
		for i := range budget.Burst {
			d, err := l.Allow(ctx, k)
			require.NoError(t, err, c.String())
			require.True(t, d.Allowed, "%s call %d of %d", c, i+1, budget.Burst)
			require.Zero(t, d.RetryAfter)
		}
		d, err := l.Allow(ctx, k)
		require.NoError(t, err)
		require.False(t, d.Allowed, "%s call %d must be denied", c, budget.Burst+1)
		require.Positive(t, d.RetryAfter)
		require.LessOrEqual(t, d.RetryAfter, budget.Refill)
		again, err := l.Allow(ctx, k)
		require.NoError(t, err)
		require.False(t, again.Allowed, "a denied call never earns tokens")
	}
}

func invalidKeys(t *testing.T, l limiter.Limiter) {
	ctx := context.Background()
	tenant, err := principal.ParseTenantID("tenant-a")
	require.NoError(t, err)
	for name, k := range map[string]limiter.Key{
		"zero class":           {Value: "v"},
		"undeclared class":     {Class: limiter.Class(200), Value: "v"},
		"empty value":          {Class: limiter.LoginClient},
		"oversized value":      {Class: limiter.LoginClient, Value: strings.Repeat("x", 257)},
		"tenant on client key": {Class: limiter.LoginClient, Tenant: tenant, Value: "v"},
	} {
		d, err := l.Allow(ctx, k)
		require.Error(t, err, name)
		require.False(t, d.Allowed, name)
	}
	d, err := l.Allow(ctx, limiter.Key{Class: limiter.LoginClient, Value: strings.Repeat("x", 256)})
	require.NoError(t, err)
	require.True(t, d.Allowed)
}

func keyIsolation(t *testing.T, l limiter.Limiter) {
	ctx := context.Background()
	value := "shared-" + uuid.NewString()
	a, err := principal.ParseTenantID("tenant-a")
	require.NoError(t, err)
	b, err := principal.ParseTenantID("tenant-b")
	require.NoError(t, err)

	inA := limiter.Key{Class: limiter.LoginIdentifier, Tenant: a, Value: value}
	inB := limiter.Key{Class: limiter.LoginIdentifier, Tenant: b, Value: value}
	drain(t, l, inA)
	d, err := l.Allow(ctx, inA)
	require.NoError(t, err)
	require.False(t, d.Allowed)
	d, err = l.Allow(ctx, inB)
	require.NoError(t, err)
	require.True(t, d.Allowed, "the same identifier in another tenant has its own bucket")

	other := limiter.Key{Class: limiter.CodeRequestIdentifier, Tenant: a, Value: value}
	d, err = l.Allow(ctx, other)
	require.NoError(t, err)
	require.True(t, d.Allowed, "classes never share a bucket")

	client := limiter.Key{Class: limiter.LoginClient, Value: value}
	drain(t, l, client)
	d, err = l.Allow(ctx, limiter.Key{Class: limiter.LoginClient, Value: value + "-other"})
	require.NoError(t, err)
	require.True(t, d.Allowed, "distinct values have distinct buckets")
	d, err = l.Allow(ctx, limiter.Key{Class: limiter.CodeRequestClient, Value: value})
	require.NoError(t, err)
	require.True(t, d.Allowed)
}

func concurrentAllow(t *testing.T, l limiter.Limiter) {
	k := keyFor(t, limiter.SelfTest)
	var allowed atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range goroutines {
		wg.Go(func() {
			<-start
			d, err := l.Allow(context.Background(), k)
			if err == nil && d.Allowed {
				allowed.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, k.Class.Budget().Burst, allowed.Load(), "concurrent callers never exceed the burst")
}

func eraseTenant(t *testing.T, l limiter.Limiter) {
	ctx := context.Background()
	a, err := principal.ParseTenantID("tenant-a")
	require.NoError(t, err)
	b, err := principal.ParseTenantID("tenant-b")
	require.NoError(t, err)
	value := "v-" + uuid.NewString()

	inA := limiter.Key{Class: limiter.LoginIdentifier, Tenant: a, Value: value}
	codeA := limiter.Key{Class: limiter.CodeRequestIdentifier, Tenant: a, Value: value}
	inB := limiter.Key{Class: limiter.LoginIdentifier, Tenant: b, Value: value}
	client := limiter.Key{Class: limiter.LoginClient, Value: value}
	for _, k := range []limiter.Key{inA, codeA, inB, client} {
		drain(t, l, k)
	}

	require.NoError(t, l.EraseTenant(ctx, a))
	for _, k := range []limiter.Key{inA, codeA} {
		d, err := l.Allow(ctx, k)
		require.NoError(t, err)
		require.True(t, d.Allowed, "%s bucket of the erased tenant is gone", k.Class)
	}
	for _, k := range []limiter.Key{inB, client} {
		d, err := l.Allow(ctx, k)
		require.NoError(t, err)
		require.False(t, d.Allowed, "%s bucket outside the erased tenant stays", k.Class)
	}
}

func reapKeepsDrained(t *testing.T, l limiter.Limiter) {
	ctx := context.Background()
	k := keyFor(t, limiter.SelfTest)
	drain(t, l, k)
	_, err := l.ReapExpired(ctx)
	require.NoError(t, err)
	d, err := l.Allow(ctx, k)
	require.NoError(t, err)
	require.False(t, d.Allowed, "reaping never refills a bucket that has not refilled")
}

func canceledContext(t *testing.T, l limiter.Limiter) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	d, err := l.Allow(ctx, keyFor(t, limiter.LoginClient))
	require.Error(t, err)
	require.False(t, d.Allowed, "a failed Allow never allows")
}
