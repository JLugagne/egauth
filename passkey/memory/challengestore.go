package memory

import (
	"container/heap"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/JLugagne/egauth/passkey"
)

// DefaultMaxChallenges caps how many unexpired challenges a single tenant may have outstanding.
// Reaching the cap fails the ceremony closed (Put returns ErrChallengeStoreFull) rather than
// evicting a live entry, because evicting would consume a legitimate user's in-flight ceremony to
// make room for an attacker's.
//
// The value is generous for real traffic: a challenge lives for one ceremony timeout, so a tenant
// reaches this cap only by starting far more ceremonies than it finishes. The handlers that begin a
// ceremony are unauthenticated by design (a login must be startable by an anonymous visitor), so
// without a cap an attacker's request volume translates directly into retained memory.
const DefaultMaxChallenges = 4096

// ErrChallengeStoreFull is returned by Put when the tenant already holds MaxChallenges unexpired
// entries. It is a deliberate fail-closed signal: the ceremony cannot start, and the caller maps it
// to a retryable server-side error rather than silently dropping someone else's challenge.
var ErrChallengeStoreFull = fmt.Errorf("%w: challenge store is full for this tenant", passkey.ErrStoreCapacityReached)

// ChallengeStore is an in-memory implementation of passkey.ChallengeStore. It provides
// single-use, TTL-bounded storage of in-flight ceremony challenges to block replay (SEC-05).
// Entries are keyed on (tenant, challenge) and reaped from an expiry-ordered index. It is safe for
// concurrent use.
//
// Bounded by design: every tenant is capped at MaxChallenges unexpired entries, so an unauthenticated
// flood of ceremony starts cannot grow the map without limit. Insertion is O(log n) — expired
// entries are popped from an expiry index instead of the whole map being rescanned on every write,
// which matters because Put runs on the request path.
//
// This is suitable for single-process deployments and tests. A multi-process deployment should use
// a shared backend; a pgx-backed ChallengeStore is a documented follow-up (see passkey/pgx) and is
// intentionally not implemented in this pass.
type ChallengeStore struct {
	mu sync.Mutex
	// entries maps key -> absolute expiry. It is the authority for Consume.
	entries map[string]time.Time
	// expiry is an index over entries ordered by expiry, used to reap without a full scan. Entries
	// may appear more than once (a key re-Put after being replaced), so a pop is validated against
	// entries before it is honoured.
	expiry expiryHeap
	// live counts unexpired entries per tenant, so the cap check is O(1).
	live map[string]int
	// max caps live entries per tenant. Non-positive means DefaultMaxChallenges.
	max int
	// now is the time source (overridable in tests).
	now func() time.Time
}

// ChallengeStoreOption configures a ChallengeStore.
type ChallengeStoreOption func(*ChallengeStore)

// WithMaxChallenges caps unexpired challenges per tenant. A non-positive value selects
// DefaultMaxChallenges; the cap cannot be disabled, because an uncapped store on an
// unauthenticated endpoint is the defect this bound exists to prevent.
func WithMaxChallenges(n int) ChallengeStoreOption {
	return func(s *ChallengeStore) { s.max = n }
}

// WithClock overrides the time source (primarily for tests).
func WithClock(now func() time.Time) ChallengeStoreOption {
	return func(s *ChallengeStore) {
		if now != nil {
			s.now = now
		}
	}
}

// NewChallengeStore returns an empty in-memory ChallengeStore.
func NewChallengeStore(opts ...ChallengeStoreOption) *ChallengeStore {
	s := &ChallengeStore{
		entries: make(map[string]time.Time),
		live:    make(map[string]int),
		max:     DefaultMaxChallenges,
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.max <= 0 {
		s.max = DefaultMaxChallenges
	}
	return s
}

// MaxChallenges returns the per-tenant cap this store enforces.
func (s *ChallengeStore) MaxChallenges() int { return s.max }

func challengeKey(tenant, challenge string) string {
	return tenant + "\x00" + challenge
}

// Put records an issued challenge with an absolute expiry.
//
// Expired entries are reaped from the expiry index (not by scanning the map), and the tenant is
// refused once it holds MaxChallenges live entries, so an unauthenticated caller cannot grow the
// store without bound or make each write cost more than the last.
func (s *ChallengeStore) Put(_ context.Context, tenantID, challenge string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.reapLocked(now)

	key := challengeKey(tenantID, challenge)
	if _, replacing := s.entries[key]; !replacing && s.live[tenantID] >= s.max {
		return ErrChallengeStoreFull
	}

	if _, replacing := s.entries[key]; !replacing {
		s.live[tenantID]++
	}
	s.entries[key] = expiresAt
	heap.Push(&s.expiry, expiryEntry{key: key, tenantID: tenantID, at: expiresAt})
	return nil
}

// Consume atomically removes the challenge and reports whether it was present and unexpired.
// A second Consume of the same challenge returns (false, nil).
func (s *ChallengeStore) Consume(_ context.Context, tenantID, challenge string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	key := challengeKey(tenantID, challenge)
	expiry, found := s.entries[key]
	if !found {
		return false, nil
	}
	// Single-use: delete regardless of expiry so a stale entry cannot linger.
	delete(s.entries, key)
	if s.live[tenantID] > 0 {
		s.live[tenantID]--
	}
	if !now.Before(expiry) {
		return false, nil
	}
	return true, nil
}

// DeleteExpired drops every expired entry and returns how many were removed. The store reaps
// lazily on Put, so calling this is optional; it exists so a deployment can drive reclamation from
// the janitor package on its own schedule.
func (s *ChallengeStore) DeleteExpired(_ context.Context, tenantID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := len(s.entries)
	s.reapLocked(s.now())
	return before - len(s.entries), nil
}

// Len reports how many entries the store currently holds, including entries that have expired but
// not yet been reaped.
func (s *ChallengeStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// reapLocked pops expired entries from the expiry index. The caller must hold s.mu.
//
// A key can appear more than once in the index (a replaced entry leaves its old index row behind),
// so a popped row is only honoured when it still matches the entry it names.
func (s *ChallengeStore) reapLocked(now time.Time) {
	for s.expiry.Len() > 0 {
		top := s.expiry[0]
		if now.Before(top.at) {
			return
		}
		heap.Pop(&s.expiry)
		current, ok := s.entries[top.key]
		if !ok || current != top.at {
			// Stale index row: the key was consumed, replaced, or already reaped.
			continue
		}
		delete(s.entries, top.key)
		if s.live[top.tenantID] > 0 {
			s.live[top.tenantID]--
		}
	}
}

// expiryEntry is one row of the expiry index.
type expiryEntry struct {
	key      string
	tenantID string
	at       time.Time
}

// expiryHeap is a min-heap on at, so reaping only ever touches entries that have actually expired.
type expiryHeap []expiryEntry

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].at.Before(h[j].at) }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(x any)        { *h = append(*h, x.(expiryEntry)) }
func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

var _ passkey.ChallengeStore = (*ChallengeStore)(nil)
