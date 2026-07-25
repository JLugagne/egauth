package memory

import (
	"context"
	"sync"
	"time"

	"github.com/JLugagne/egauth/passkey"
)

// DefaultMaxChallengeEntries is the default hard cap on the number of live challenges an in-memory
// ChallengeStore keeps. Put is reachable from the UNAUTHENTICATED BeginRegistration / BeginLogin
// endpoints, so an unbounded map is a memory-exhaustion lever for an anonymous caller. Once the cap
// is reached, the OLDEST-ISSUED challenge is evicted to make room for the new one (see
// WithMaxEntries), which bounds memory at the cost of failing the evicted ceremony at Finish.
const DefaultMaxChallengeEntries = 100_000

// maxPruneStepsPerPut bounds how many queued entries a single Put may examine while reclaiming
// expired ones. Prune work is therefore amortised — every queued entry is examined at most once
// across its lifetime — instead of the whole live set being swept on every insertion.
const maxPruneStepsPerPut = 8

// ChallengeStore is an in-memory implementation of passkey.ChallengeStore. It provides
// single-use, TTL-bounded storage of in-flight ceremony challenges to block replay (SEC-05).
// Entries are keyed on (tenant, challenge) and reclaimed by an amortised, bounded prune, and the
// live set is hard-capped (see DefaultMaxChallengeEntries). It is safe for concurrent use.
//
// This is suitable for SINGLE-PROCESS deployments and tests only: each replica keeps its own map,
// so a ceremony begun on one pod cannot be finished on another. A multi-process deployment must
// use a shared backend — the Postgres-backed implementation in
// github.com/JLugagne/egauth/adapters/pgx/passkey (pgx.NewChallengeStore).
type ChallengeStore struct {
	mu      sync.Mutex
	entries map[string]time.Time // key: tenant \x00 challenge -> absolute expiry
	queue   []queuedChallenge    // insertion-ordered view of entries, used to reclaim without a full sweep
	head    int                  // index of the oldest not-yet-examined queue slot
	max     int
	scanned uint64 // instrumentation: queued entries examined while pruning, read by the internal tests
}

type queuedChallenge struct {
	key     string
	expires time.Time
}

// ChallengeStoreOption configures an in-memory ChallengeStore.
type ChallengeStoreOption func(*ChallengeStore)

// WithMaxEntries caps how many live challenges the store keeps (default
// DefaultMaxChallengeEntries). When the cap is reached, Put evicts the OLDEST-ISSUED challenge
// before recording the new one: the eviction policy is deliberately FIFO so a flood of fresh
// anonymous ceremonies cannot pin memory, and the ceremony whose challenge was evicted fails at
// Finish exactly as an expired one would. A non-positive n restores the default.
func WithMaxEntries(n int) ChallengeStoreOption {
	return func(s *ChallengeStore) {
		if n > 0 {
			s.max = n
		}
	}
}

// NewChallengeStore returns an empty in-memory ChallengeStore.
func NewChallengeStore(opts ...ChallengeStoreOption) *ChallengeStore {
	s := &ChallengeStore{entries: make(map[string]time.Time), max: DefaultMaxChallengeEntries}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func challengeKey(tenant, challenge string) string {
	return tenant + "\x00" + challenge
}

// Put records an issued challenge with an absolute expiry. It performs a bounded amount of expiry
// reclamation per call, so its cost does not grow with the number of live (or previously live)
// entries, and evicts the oldest challenge when the store is at its cap.
func (s *ChallengeStore) Put(_ context.Context, tenantID, challenge string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now())
	s.evictLocked()
	key := challengeKey(tenantID, challenge)
	if _, exists := s.entries[key]; !exists {
		s.queue = append(s.queue, queuedChallenge{key: key, expires: expiresAt})
	}
	s.entries[key] = expiresAt
	return nil
}

// Consume atomically removes the challenge and reports whether it was present and unexpired.
// A second Consume of the same challenge returns (false, nil).
func (s *ChallengeStore) Consume(_ context.Context, tenantID, challenge string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	key := challengeKey(tenantID, challenge)
	expiry, found := s.entries[key]
	if !found {
		return false, nil
	}
	// Single-use: delete regardless of expiry so a stale entry cannot linger. The matching queue
	// slot is left behind and skipped by the next prune, which keeps Consume O(1).
	delete(s.entries, key)
	if !now.Before(expiry) {
		return false, nil
	}
	return true, nil
}

// pruneLocked reclaims at most maxPruneStepsPerPut oldest queue slots whose entry is already gone
// (consumed) or expired. Insertion order is not expiry order when TTLs differ, so it stops at the
// first slot that is still live: the cap in evictLocked is what bounds the store in that case. The
// caller must hold s.mu.
func (s *ChallengeStore) pruneLocked(now time.Time) {
	for steps := 0; steps < maxPruneStepsPerPut && s.head < len(s.queue); steps++ {
		s.scanned++
		slot := s.queue[s.head]
		expiry, live := s.entries[slot.key]
		if live && now.Before(expiry) {
			return
		}
		if live && !now.Before(expiry) {
			delete(s.entries, slot.key)
		}
		s.queue[s.head] = queuedChallenge{}
		s.head++
		s.compactLocked()
	}
}

// evictLocked enforces the hard cap by dropping the oldest-issued challenges until there is room
// for one more. Every queue slot is examined at most once over its lifetime, so the work is
// amortised O(1) per Put. The caller must hold s.mu.
func (s *ChallengeStore) evictLocked() {
	for len(s.entries) >= s.max && s.head < len(s.queue) {
		s.scanned++
		slot := s.queue[s.head]
		delete(s.entries, slot.key)
		s.queue[s.head] = queuedChallenge{}
		s.head++
		s.compactLocked()
	}
}

// compactLocked drops the consumed prefix of the queue once it dominates, so the backing array
// tracks the live set rather than the peak. Copying only when the prefix is at least half the
// queue keeps the amortised cost per entry constant. The caller must hold s.mu.
func (s *ChallengeStore) compactLocked() {
	if s.head < 64 || s.head*2 < len(s.queue) {
		return
	}
	remaining := copy(s.queue, s.queue[s.head:])
	clear(s.queue[remaining:])
	s.queue = s.queue[:remaining]
	s.head = 0
}

var _ passkey.ChallengeStore = (*ChallengeStore)(nil)
