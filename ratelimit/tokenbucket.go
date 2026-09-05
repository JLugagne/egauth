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
// # Bounding memory growth
//
// By default, TokenBucket bounds memory growth by capping the number of tracked keys
// to [DefaultMaxKeys] and evicting the least-pressured bucket when capacity is reached.
//
// Two complementary strategies are available:
//
//   - [WithMaxKeys] overrides the default cap on the number of tracked keys. When a new key arrives
//     and the cap is reached, the bucket that is closest to full (least under pressure) is
//     evicted. This makes the limiter self-contained with no external scheduler required.
//
//   - Periodic [Cleanup] via [github.com/JLugagne/egauth/janitor] (the original model):
//     Cleanup drops only fully-refilled buckets, so it does not reset any key that is still
//     under pressure.
//
// DefaultMaxKeys is the default hard cap on the number of distinct keys
// tracked simultaneously by a TokenBucket limiter to prevent memory exhaustion DoS.
const DefaultMaxKeys = 100000

type TokenBucket struct {
	mu      sync.Mutex
	burst   float64
	refill  time.Duration // duration to accrue one token
	maxKeys int           // hard cap on number of tracked keys
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
// By default, maxKeys is set to DefaultMaxKeys (100,000) to bound memory growth.
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
		maxKeys: DefaultMaxKeys,
		buckets: make(map[string]*bucketState),
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(tb)
	}
	return tb
}

// Allow consumes one token for key, refilling first based on elapsed time. When the bucket
// was created with [WithMaxKeys] or default capacity and the cap is reached, the least-pressured bucket is
// evicted before inserting the new key.
func (tb *TokenBucket) Allow(ctx context.Context, key string) (bool, time.Duration) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := tb.now()
	b, ok := tb.buckets[key]
	if !ok {
		// Enforce the maxKeys cap: evict the bucket that has refilled the most
		// (least under pressure) to make room for the new key.
		for tb.maxKeys > 0 && len(tb.buckets) >= tb.maxKeys {
			tb.evictOne(now)
		}
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

// WithMaxKeys sets a hard cap on the number of distinct keys the TokenBucket
// tracks simultaneously. When [TokenBucket.Allow] is called with a new key and
// the cap is already reached, the bucket that has refilled the most (i.e. is
// least under pressure — closest to burst capacity) is evicted to make room.
// Fully-refilled buckets are always preferred for eviction.
//
// If n <= 0, DefaultMaxKeys is used.
func WithMaxKeys(n int) Option {
	return func(tb *TokenBucket) {
		if n <= 0 {
			n = DefaultMaxKeys
		}
		tb.maxKeys = n
	}
}

// KeyCount returns the current number of tracked keys. Useful in tests and
// monitoring to verify the bounded-store invariant.
func (tb *TokenBucket) KeyCount() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return len(tb.buckets)
}

// MaxKeys returns the configured maximum number of keys tracked simultaneously.
func (tb *TokenBucket) MaxKeys() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.maxKeys
}

// evictOne removes the single bucket that is least under pressure (closest to
// fully-refilled). Fully-refilled buckets are preferred; among partially-refilled
// ones the one with the most tokens (accounting for elapsed time) is chosen.
// Must be called with tb.mu held.
func (tb *TokenBucket) evictOne(now time.Time) {
	var (
		evictKey  string
		evictToks float64
		found     bool
		sampled   int
	)
	// Go maps iterate in random order. Sampling 5 elements is sufficient for finding
	// a reasonably good candidate for eviction in O(1) time.
	for k, b := range tb.buckets {
		toks := b.tokens + float64(now.Sub(b.last))/float64(tb.refill)
		if toks > tb.burst {
			toks = tb.burst
		}
		if !found || toks > evictToks {
			evictToks = toks
			evictKey = k
			found = true
		}
		sampled++
		if sampled >= 5 {
			break
		}
	}
	if found {
		delete(tb.buckets, evictKey)
	}
}
