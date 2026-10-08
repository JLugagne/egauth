// Package memory provides an in-process token-bucket limiter.Limiter. It reports store.Ephemeral:
// buckets are private to the process, so several instances together allow n times the budget unless
// the composition root hands this limiter the live instance count through SetInstances.
package memory

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/limiter"
)

// MaxBuckets bounds the buckets held at once. At the bound, Allow first drops buckets that have
// refilled and then fails closed with store.ErrCapacity.
const MaxBuckets = 1 << 20

var (
	_ limiter.Limiter        = (*Limiter)(nil)
	_ limiter.InstanceScaler = (*Limiter)(nil)
)

type bucket struct {
	class   limiter.Class
	tokens  float64
	updated time.Time
}

// Limiter is safe for concurrent use.
type Limiter struct {
	clk       clock.Clock
	mu        sync.Mutex
	buckets   map[string]*bucket
	instances int
}

// New returns an empty limiter that reads the wall clock and enforces the full library budgets.
func New() *Limiter { return NewWithClock(clock.Clock{}) }

// NewWithClock returns an empty limiter that reads c; the composition root passes the library clock.
func NewWithClock(c clock.Clock) *Limiter {
	return &Limiter{clk: c, buckets: map[string]*bucket{}, instances: 1}
}

func (l *Limiter) SetInstances(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.instances = max(n, 1)
}

func (l *Limiter) Ping(ctx context.Context) error { return ctx.Err() }

func (l *Limiter) Durability() store.Durability { return store.Ephemeral }

func (l *Limiter) EraseTenant(ctx context.Context, t principal.TenantID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range []limiter.Class{limiter.LoginIdentifier, limiter.CodeRequestIdentifier} {
		prefix := string(limiter.TenantPrefix(c, t))
		for k := range l.buckets {
			if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
				delete(l.buckets, k)
			}
		}
	}
	return nil
}

func (l *Limiter) ReapExpired(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	now := l.clk.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	return int64(l.sweep(now)), nil
}

func (l *Limiter) sweep(now time.Time) int {
	n := 0
	for k, b := range l.buckets {
		budget := b.class.Budget().PerInstance(l.instances)
		if refilled(b, budget, now) >= float64(budget.Burst) {
			delete(l.buckets, k)
			n++
		}
	}
	return n
}

func refilled(b *bucket, budget limiter.Budget, now time.Time) float64 {
	elapsed := max(now.Sub(b.updated), 0)
	return min(b.tokens+float64(elapsed)/float64(budget.Refill), float64(budget.Burst))
}

func (l *Limiter) Allow(ctx context.Context, key limiter.Key) (limiter.Decision, error) {
	if err := ctx.Err(); err != nil {
		return limiter.Decision{}, err
	}
	if !key.Valid() {
		return limiter.Decision{}, errors.New("limiter: invalid key")
	}
	now := l.clk.Now()
	sk := string(key.StorageKey())
	l.mu.Lock()
	defer l.mu.Unlock()
	budget := key.Class.Budget().PerInstance(l.instances)
	b, ok := l.buckets[sk]
	if !ok {
		if len(l.buckets) >= MaxBuckets {
			l.sweep(now)
		}
		if len(l.buckets) >= MaxBuckets {
			return limiter.Decision{}, store.ErrCapacity
		}
		b = &bucket{class: key.Class, tokens: float64(budget.Burst), updated: now}
		l.buckets[sk] = b
	}
	b.tokens = refilled(b, budget, now)
	b.updated = now
	if b.tokens >= 1 {
		b.tokens--
		return limiter.Decision{Allowed: true}, nil
	}
	wait := time.Duration((1 - b.tokens) * float64(budget.Refill))
	return limiter.Decision{RetryAfter: max(wait, time.Nanosecond)}, nil
}
