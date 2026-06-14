// Package memory provides an in-memory otp.Store, primarily for tests and
// single-process use.
//
// # Production requirement: periodic eviction is MANDATORY
//
// The Store grows without bound unless DeleteExpired is called periodically.
// Every expired OTP code row remains in the in-memory map until explicitly
// purged; under load a production deployment that skips periodic eviction will
// exhaust available memory, creating a trivial denial-of-service vector.
//
// Use [github.com/JLugagne/egauth/janitor] to schedule eviction at startup:
//
//	store := memory.NewStore()
//	j := janitor.Start(ctx, 5*time.Minute, func() {
//	    store.DeleteExpired(context.Background(), tenantID)
//	})
//	defer j.Stop()
//
// This in-memory backend is suitable for tests and single-binary deployments
// where controlled restart bounds the total OTP count. For persistent or
// horizontally-scaled deployments, use the otp/pgx backend instead.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/JLugagne/egauth/otp"
	"github.com/google/uuid"
)

// Store is an in-memory implementation of otp.Store.
// Store is an in-memory implementation of otp.Store.
//
// By default the store is unbounded; OTP growth is controlled by periodic
// calls to DeleteExpired (e.g. via [github.com/JLugagne/egauth/janitor]).
// Use [NewBoundedStore] for a store that enforces a hard cap and self-evicts
// on insertion: it first removes already-expired codes, then the code with
// the soonest ExpiresAt, so live codes are preserved as long as possible.
type Store struct {
	mu      sync.RWMutex
	maxSize int                 // 0 means unbounded
	codes   map[string]*otp.OTP // key: tenant \x00 subject \x00 purpose
}

// NewStore creates a new in-memory Store.
func NewStore() *Store {
	return &Store{codes: make(map[string]*otp.OTP)}
}

func key(tenantID string, subjectID uuid.UUID, purpose string) string {
	return tenantID + "\x00" + subjectID.String() + "\x00" + purpose
}

func (s *Store) SaveOTP(ctx context.Context, tenantID string, o *otp.OTP) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if o.TenantID != "" && o.TenantID != tenantID {
		return otp.ErrTenantMismatch
	}
	stored := *o
	stored.TenantID = tenantID

	k := key(tenantID, o.SubjectID, o.Purpose)
	// SaveOTP is an upsert: if the key already exists we overwrite it (same slot, no growth).
	// Only evict if we are inserting a genuinely new key and the cap would be exceeded.
	if _, exists := s.codes[k]; !exists && s.maxSize > 0 && len(s.codes) >= s.maxSize {
		s.evictOneLocked()
	}
	s.codes[k] = &stored
	return nil
}

func (s *Store) GetOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) (*otp.OTP, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	o, ok := s.codes[key(tenantID, subjectID, purpose)]
	if !ok {
		return nil, otp.ErrCodeNotFound
	}
	cpy := *o
	return &cpy, nil
}

func (s *Store) IncrementOTPAttempts(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	o, ok := s.codes[key(tenantID, subjectID, purpose)]
	if !ok {
		return 0, otp.ErrCodeNotFound
	}
	o.Attempts++
	return o.Attempts, nil
}

func (s *Store) ConsumeOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose, expectedCodeHash string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := key(tenantID, subjectID, purpose)
	o, ok := s.codes[k]
	if !ok {
		return false, nil
	}
	// Identity guard: only delete the row that still matches the hash the verifier compared
	// against. A code reissued since that read carries a different hash and must be left intact.
	if o.CodeHash != expectedCodeHash {
		return false, nil
	}
	delete(s.codes, k)
	return true, nil
}

func (s *Store) DeleteOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.codes, key(tenantID, subjectID, purpose))
	return nil
}

// DeleteExpired purges codes past their expiry within the given tenant, returning the number deleted.
func (s *Store) DeleteExpired(ctx context.Context, tenantID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var deleted int64
	for k, code := range s.codes {
		if code.TenantID != tenantID {
			continue
		}
		if code.ExpiresAt.Before(now) {
			delete(s.codes, k)
			deleted++
		}
	}
	return deleted, nil
}

var _ otp.Store = (*Store)(nil)

// NewBoundedStore creates a bounded in-memory OTP Store that never holds more
// than maxSize codes. When a SaveOTP call would exceed the cap, the store
// first evicts already-expired codes; if the cap is still reached it evicts
// the code with the soonest ExpiresAt. maxSize must be >= 1; values below 1
// are floored to 1.
//
// The existing [NewStore] constructor remains available for callers who prefer
// the unbounded model and control growth via periodic [Store.DeleteExpired]
// calls (e.g. via [github.com/JLugagne/egauth/janitor]).
func NewBoundedStore(maxSize int) *Store {
	if maxSize < 1 {
		maxSize = 1
	}
	return &Store{
		maxSize: maxSize,
		codes:   make(map[string]*otp.OTP),
	}
}

// Len returns the current number of OTP codes held by the store.
// It is primarily useful in tests.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.codes)
}

// evictOneLocked removes one OTP code to make room for a new insertion.
// Must be called with the write lock held.
// Policy: evict the code with the soonest ExpiresAt (expired codes first,
// then the one expiring next).
func (s *Store) evictOneLocked() {
	var (
		victimKey string
		victimAt  time.Time
		found     bool
	)
	now := time.Now()
	// First pass: look for an already-expired code.
	for k, code := range s.codes {
		if code.ExpiresAt.Before(now) {
			if !found || code.ExpiresAt.Before(victimAt) {
				victimKey = k
				victimAt = code.ExpiresAt
				found = true
			}
		}
	}
	if found {
		delete(s.codes, victimKey)
		return
	}
	// Second pass: no expired code — evict the one expiring soonest.
	for k, code := range s.codes {
		if !found || code.ExpiresAt.Before(victimAt) {
			victimKey = k
			victimAt = code.ExpiresAt
			found = true
		}
	}
	if found {
		delete(s.codes, victimKey)
	}
}
