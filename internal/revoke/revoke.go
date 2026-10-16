// Package revoke holds the per-process revocation caches of DESIGN.md section 7.4: session families
// (sid to state), subject security epochs and tenant keysets. Each cache follows the same
// lookup-then-follow rules, so a freshly started replica needs no backfill and nothing is ever
// decided by comparing timestamps (T-04, C-18):
//
//   - Follow: Poll reads the store's change feed from a store-issued cursor and evicts every entry
//     it names. Start runs it every PollInterval.
//   - Lookup: a miss records the cursor position, then reads the store. The answer is cached only
//     when no poll was applied in between, so a change is never lost to a racing lookup.
//   - Bounded staleness: an entry is trusted only while the last successful poll is younger than
//     PollBound. Otherwise every check reads the store, so a dead or never-started poller still
//     rejects a revoked sid or a stale epoch.
//   - Size: each cache is an LRU of bounded size; eviction only causes a new lookup.
//
// A store that cannot answer yields ErrUnavailable, which callers map to 503 auth_unavailable, and
// emits event.RevocationUnavailable.
package revoke

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/store"
)

const (
	// PollInterval is how often a started cache reads its change feed.
	PollInterval = 2 * time.Second
	// PollBound is the age past which the last successful poll no longer vouches for cached
	// entries: every check then reads the store. It is the revocation latency bound of both
	// session backends.
	PollBound = 3 * PollInterval
	// DefaultCapacity is the number of entries a cache keeps when Config.Capacity is zero.
	DefaultCapacity = 10000
)

const maxPagesPerPoll = 256

var (
	// ErrUnavailable reports that the store could not answer a revocation check; the request must
	// fail with 503 auth_unavailable, never proceed.
	ErrUnavailable = errors.New("revoke: revocation state unavailable")
	// ErrStale is returned by Ready while the last successful poll is older than PollBound or no
	// poll ever succeeded.
	ErrStale = errors.New("revoke: last successful poll is older than PollBound")
	// ErrNotLive reports a session family that is unknown, revoked, past its absolute expiry, or
	// of another tenant, subject or lineage.
	ErrNotLive = errors.New("revoke: session family is not live")
	// ErrStaleEpoch reports a session sealed under another security epoch than the subject's
	// current one, or a subject that no longer exists.
	ErrStaleEpoch = errors.New("revoke: security epoch is stale")
	// ErrInvalidConfig reports a nil source or lookup, or a negative capacity.
	ErrInvalidConfig = errors.New("revoke: invalid cache configuration")
	errBacklog       = errors.New("revoke: change feed backlog exceeds one poll")
)

// Config is shared by every cache constructor. The zero Clock reads the wall clock; the
// composition root passes the library clock. A nil Events drops RevocationUnavailable. A zero
// Capacity selects DefaultCapacity.
type Config struct {
	Clock    clock.Clock
	Events   event.Sink
	Capacity int
}

type follower[K comparable, V any] struct {
	name   string
	feed   func(ctx context.Context, c store.Cursor) ([]K, store.Cursor, error)
	lookup func(ctx context.Context, k K) (V, error)
	scope  func(k K) audit.Scope
	clk    clock.Clock
	events event.Sink

	mu       sync.Mutex
	cursor   store.Cursor
	gen      uint64
	polled   bool
	lastPoll time.Time
	entries  *lru[K, V]

	pollMu sync.Mutex

	runMu  sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func newFollower[K comparable, V any](name string, cfg Config, feed func(context.Context, store.Cursor) ([]K, store.Cursor, error), lookup func(context.Context, K) (V, error), scope func(K) audit.Scope) (*follower[K, V], error) {
	if feed == nil || lookup == nil {
		return nil, errors.Join(ErrInvalidConfig, errors.New("revoke: "+name+" needs a source"))
	}
	if cfg.Capacity < 0 {
		return nil, errors.Join(ErrInvalidConfig, errors.New("revoke: negative capacity"))
	}
	capacity := cfg.Capacity
	if capacity == 0 {
		capacity = DefaultCapacity
	}
	return &follower[K, V]{
		name: name, feed: feed, lookup: lookup, scope: scope,
		clk: cfg.Clock, events: cfg.Events,
		entries: newLRU[K, V](capacity),
	}, nil
}

func (f *follower[K, V]) freshLocked(now time.Time) bool {
	return f.polled && !now.Before(f.lastPoll) && now.Sub(f.lastPoll) < PollBound
}

func (f *follower[K, V]) get(ctx context.Context, k K) (V, error) {
	f.mu.Lock()
	fresh := f.freshLocked(f.clk.Now())
	if fresh {
		if v, ok := f.entries.get(k); ok {
			f.mu.Unlock()
			return v, nil
		}
	}
	since, gen := f.cursor, f.gen
	f.mu.Unlock()

	v, err := f.lookup(ctx, k)
	if err != nil {
		var zero V
		if errors.Is(err, store.ErrNotFound) {
			return zero, err
		}
		if ctx.Err() == nil {
			_ = audit.Emit(ctx, f.events, event.RevocationUnavailable, f.scope(k), audit.Detail{Reason: f.name}, err)
		}
		return zero, errors.Join(ErrUnavailable, err)
	}
	if fresh {
		f.mu.Lock()
		if f.gen == gen && f.cursor == since && f.freshLocked(f.clk.Now()) {
			f.entries.put(k, v)
		}
		f.mu.Unlock()
	}
	return v, nil
}

func (f *follower[K, V]) forget(k K) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries.remove(k)
	f.gen++
}

// Poll reads the change feed from the cache's cursor until it is caught up, evicting every entry
// it names, and marks the cache fresh. A cursor the store no longer retains (store.ErrNotFound)
// drops every entry and restarts from the beginning of the feed. Concurrent calls are serialised.
// It returns ErrUnavailable joined with the store error when the feed cannot be read, and an error
// when the backlog is longer than one poll reads; after either failure the cache is not marked fresh and
// stops trusting its entries once PollBound has elapsed.
func (f *follower[K, V]) Poll(ctx context.Context) error {
	f.pollMu.Lock()
	defer f.pollMu.Unlock()
	began := f.clk.Now()
	f.mu.Lock()
	cur := f.cursor
	f.mu.Unlock()
	reset := false
	for range maxPagesPerPoll {
		changed, next, err := f.feed(ctx, cur)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) && !cur.IsZero() && !reset {
				reset = true
				cur = store.Cursor{}
				f.mu.Lock()
				f.entries.clear()
				f.cursor = cur
				f.gen++
				f.mu.Unlock()
				continue
			}
			return errors.Join(ErrUnavailable, err)
		}
		advanced := next.After(cur)
		f.mu.Lock()
		for _, k := range changed {
			f.entries.remove(k)
		}
		if advanced {
			f.cursor = next
		}
		f.gen++
		f.mu.Unlock()
		if len(changed) == 0 || !advanced {
			f.mu.Lock()
			f.polled, f.lastPoll = true, began
			f.mu.Unlock()
			return nil
		}
		cur = next
	}
	return errBacklog
}

// Ready returns ErrStale unless the last successful poll is younger than PollBound. Requests stay
// correct either way, reading the store; Ready lets the readiness probe report the lag.
func (f *follower[K, V]) Ready() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.freshLocked(f.clk.Now()) {
		return ErrStale
	}
	return nil
}

// Len returns the number of cached entries.
func (f *follower[K, V]) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.entries.len()
}

// Start polls at once, then every PollInterval, until Stop. It is idempotent while running and may
// be called again after Stop. No context governs the poller, so no request deadline can end it.
func (f *follower[K, V]) Start() {
	f.runMu.Lock()
	defer f.runMu.Unlock()
	if f.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	f.cancel, f.done = cancel, done
	go f.run(ctx, done)
}

// Stop ends the poller started by Start and waits for it. It is idempotent. Checks made after Stop
// read the store once PollBound has elapsed, so they keep failing closed.
func (f *follower[K, V]) Stop() {
	f.runMu.Lock()
	defer f.runMu.Unlock()
	if f.cancel == nil {
		return
	}
	f.cancel()
	<-f.done
	f.cancel, f.done = nil, nil
}

func (f *follower[K, V]) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(PollInterval)
	defer ticker.Stop()
	for {
		f.pollOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (f *follower[K, V]) pollOnce(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, PollInterval)
	defer cancel()
	_ = f.Poll(pctx)
}
