package memory

import (
	"context"
	"sync"
	"time"

	"github.com/JLugagne/egauth/passkey"
)

// ChallengeStore is an in-memory implementation of passkey.ChallengeStore. It provides
// single-use, TTL-bounded storage of in-flight ceremony challenges to block replay (SEC-05).
// Entries are keyed on (tenant, challenge) and pruned lazily on access. It is safe for
// concurrent use.
//
// This is suitable for single-process deployments and tests. A multi-process deployment
// should use a shared backend; a pgx-backed ChallengeStore is a documented follow-up
// (see passkey/pgx) and is intentionally not implemented in this pass.
type ChallengeStore struct {
	mu      sync.Mutex
	entries map[string]time.Time // key: tenant \x00 challenge -> absolute expiry
}

// NewChallengeStore returns an empty in-memory ChallengeStore.
func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{entries: make(map[string]time.Time)}
}

func challengeKey(tenant, challenge string) string {
	return tenant + "\x00" + challenge
}

// Put records an issued challenge with an absolute expiry.
func (s *ChallengeStore) Put(_ context.Context, tenantID, challenge string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now())
	s.entries[challengeKey(tenantID, challenge)] = expiresAt
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
	// Single-use: delete regardless of expiry so a stale entry cannot linger.
	delete(s.entries, key)
	if !now.Before(expiry) {
		return false, nil
	}
	return true, nil
}

// pruneLocked drops expired entries. The caller must hold s.mu.
func (s *ChallengeStore) pruneLocked(now time.Time) {
	for k, expiry := range s.entries {
		if !now.Before(expiry) {
			delete(s.entries, k)
		}
	}
}

var _ passkey.ChallengeStore = (*ChallengeStore)(nil)
