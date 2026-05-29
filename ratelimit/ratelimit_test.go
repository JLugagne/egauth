package ratelimit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/libauth/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock is a manually-advanced time source for deterministic tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestTokenBucket_BurstThenDeny(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{t: time.Unix(0, 0)}
	tb := ratelimit.NewTokenBucket(3, time.Second, ratelimit.WithClock(clk.now))

	// First 3 requests consume the burst.
	for i := 0; i < 3; i++ {
		allowed, _ := tb.Allow(ctx, "ip-1")
		assert.True(t, allowed, "burst request %d should be allowed", i)
	}

	// 4th is denied, with a retry-after up to the refill interval.
	allowed, retry := tb.Allow(ctx, "ip-1")
	assert.False(t, allowed)
	assert.Greater(t, retry, time.Duration(0))
	assert.LessOrEqual(t, retry, time.Second)
}

func TestTokenBucket_RefillsOverTime(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{t: time.Unix(0, 0)}
	tb := ratelimit.NewTokenBucket(1, time.Second, ratelimit.WithClock(clk.now))

	allowed, _ := tb.Allow(ctx, "k")
	require.True(t, allowed)
	allowed, _ = tb.Allow(ctx, "k")
	require.False(t, allowed, "second immediate request exhausts the single token")

	clk.advance(time.Second) // one token refilled
	allowed, _ = tb.Allow(ctx, "k")
	assert.True(t, allowed, "after the refill interval the request is allowed again")
}

func TestTokenBucket_KeysAreIndependent(t *testing.T) {
	ctx := context.Background()
	tb := ratelimit.NewTokenBucket(1, time.Hour)

	allowed, _ := tb.Allow(ctx, "a")
	require.True(t, allowed)
	allowed, _ = tb.Allow(ctx, "a")
	require.False(t, allowed)

	allowed, _ = tb.Allow(ctx, "b")
	assert.True(t, allowed, "a different key has its own budget")
}

func TestTokenBucket_Cleanup(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{t: time.Unix(0, 0)}
	tb := ratelimit.NewTokenBucket(2, time.Second, ratelimit.WithClock(clk.now))

	tb.Allow(ctx, "x") // creates a bucket, now below full
	assert.Equal(t, 0, tb.Cleanup(), "a partially-used bucket is retained")

	clk.advance(10 * time.Second) // fully refilled
	assert.Equal(t, 1, tb.Cleanup(), "a fully-refilled bucket is dropped")
}

func TestMiddleware_PassesThroughThenBlocks(t *testing.T) {
	tb := ratelimit.NewTokenBucket(1, time.Hour)
	var hits int
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	})
	h := ratelimit.Middleware(tb, nil)(next)

	req := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/login", nil)
		r.RemoteAddr = "203.0.113.7:1234"
		return r
	}

	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req())
	assert.Equal(t, http.StatusOK, rec1.Code)

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req())
	assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
	assert.NotEmpty(t, rec2.Header().Get("Retry-After"))
	assert.Equal(t, 1, hits, "the blocked request must not reach the next handler")
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.4:55555"
	assert.Equal(t, "198.51.100.4", ratelimit.ClientIP(r))
}
