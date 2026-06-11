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
type Store struct {
	mu    sync.RWMutex
	codes map[string]*otp.OTP // key: tenant \x00 subject \x00 purpose
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
	s.codes[key(tenantID, o.SubjectID, o.Purpose)] = &stored
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
