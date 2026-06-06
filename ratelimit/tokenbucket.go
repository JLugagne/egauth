package ratelimit

import (
	"context"
	"sync"
	"time"
)

// TokenBucket is a process-local, per-key token-bucket Limiter. Each key gets a bucket with
// capacity burst that refills one token every refillInterval. A request consumes one token;
// when none are available it is rejected with the time until the next token. It is safe for
// concurrent use.
//
// # Production requirement: periodic eviction is MANDATORY
//
// A new per-key bucket is allocated on the first Allow call for that key and is only freed by
// Cleanup. Without periodic eviction a flood of unique keys (IPs, user IDs, request paths) grows
// the internal map without bound — a trivial denial-of-service vector in any Internet-facing
// deployment.
//
// Use [github.com/JLugagne/egauth/janitor] to schedule eviction at startup:
//
//	tb := ratelimit.NewTokenBucket(10, time.Second)
//	j := janitor.Start(ctx, time.Minute, func() {
//	    tb.Cleanup()
//	})
//	defer j.Stop()
//
// Cleanup drops only fully-refilled buckets (those indistinguishable from a fresh one), so it
// does not reset the limit for any key that is still under pressure.
type TokenBucket struct {
	mu      sync.Mutex
	burst   float64
	refill  time.Duration // duration to accrue one token
	buckets map[string]*bucketState
	now     func() time.Time
}

type bucketState struct {
	tokens float64
	last   time.Time
}

// Option configures a TokenBucket.
type Option func(*TokenBucket)

// WithClock injects the time source, for deterministic tests. Defaults to time.Now.
func WithClock(now func() time.Time) Option {
	return func(tb *TokenBucket) {
		if now != nil {
			tb.now = now
		}
	}
}

// NewTokenBucket creates a limiter where each key may burst up to burst requests and then
// sustains one request per refillInterval. burst is floored at 1 and refillInterval at 1ns.
func NewTokenBucket(burst int, refillInterval time.Duration, opts ...Option) *TokenBucket {
	if burst < 1 {
		burst = 1
	}
	if refillInterval < time.Nanosecond {
		refillInterval = time.Nanosecond
	}
	tb := &TokenBucket{
		burst:   float64(burst),
		refill:  refillInterval,
		buckets: make(map[string]*bucketState),
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(tb)
	}
	return tb
}

// Allow consumes one token for key, refilling first based on elapsed time.
func (tb *TokenBucket) Allow(ctx context.Context, key string) (bool, time.Duration) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := tb.now()
	b, ok := tb.buckets[key]
	if !ok {
		b = &bucketState{tokens: tb.burst, last: now}
		tb.buckets[key] = b
	} else {
		b.tokens += float64(now.Sub(b.last)) / float64(tb.refill)
		if b.tokens > tb.burst {
			b.tokens = tb.burst
		}
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	// Time to accrue the fractional token still missing to reach 1.
	need := 1 - b.tokens
	return false, time.Duration(need * float64(tb.refill))
}

// Cleanup removes buckets that have fully refilled (i.e. are indistinguishable from a fresh
// bucket), bounding memory under a flood of unique keys. Returns the number removed.
func (tb *TokenBucket) Cleanup() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := tb.now()
	removed := 0
	for key, b := range tb.buckets {
		tokens := b.tokens + float64(now.Sub(b.last))/float64(tb.refill)
		if tokens >= tb.burst {
			delete(tb.buckets, key)
			removed++
		}
	}
	return removed
}

var _ Limiter = (*TokenBucket)(nil)
