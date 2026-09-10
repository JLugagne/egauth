// Package memory provides an in-memory mfa.Store, primarily for tests and single-process use.
//
// # Bounding memory growth
//
// [NewStore] is bounded by default: the store retains at most [DefaultMaxEntries]
// per-user recovery-code attempt records, evicting the stalest record when a new
// user is tracked at the cap. It is the only map that can be grown by callers
// without an existing enrollment, so it is the only one capped.
//
// TOTP enrollments and recovery codes are durable per-user security state (one
// record per account), so they are never silently evicted; [NewUnboundedStore]
// removes even the recovery-attempt cap for callers that schedule periodic
// [Store.DeleteStaleRecoveryAttempts] reaping (e.g. via
// [github.com/JLugagne/egauth/janitor]) instead.
package memory

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/JLugagne/egauth/mfa"
	"github.com/google/uuid"
)

type recoveryAttempt struct {
	failedAttempts int
	lastAttemptAt  time.Time
}

// Store is an in-memory implementation of mfa.Store.
//
// Stores created by [NewStore] cap the number of tracked recovery-attempt records
// at [DefaultMaxEntries]; TOTP enrollments and recovery codes are durable and are
// never evicted.
type Store struct {
	mu               sync.RWMutex
	maxSize          int // cap on recoveryAttempts; 0 means unbounded
	totp             map[string]*mfa.TOTPEnrollment
	recovery         map[string][]*mfa.RecoveryCode
	recoveryAttempts map[string]*recoveryAttempt
}

// DefaultMaxEntries is the default hard cap on the number of per-user recovery-code attempt
// records an in-memory Store created by [NewStore] tracks. It is deliberately generous so
// ordinary single-process use never hits it; it exists because recovery attempts can be recorded
// for caller-supplied user IDs even when no enrollment exists, so the map is otherwise a memory
// exhaustion vector.
const DefaultMaxEntries = 100_000

// NewStore creates a new in-memory Store bounded by [DefaultMaxEntries].
func NewStore() *Store {
	return NewBoundedStore(DefaultMaxEntries)
}

// NewBoundedStore creates a new in-memory Store that tracks at most maxSize
// recovery-attempt records. When a new user is tracked at the cap the stalest
// record (earliest last attempt) is evicted. maxSize must be >= 1; values below
// 1 are floored to 1.
func NewBoundedStore(maxSize int) *Store {
	if maxSize < 1 {
		maxSize = 1
	}
	return &Store{
		maxSize:          maxSize,
		totp:             make(map[string]*mfa.TOTPEnrollment),
		recovery:         make(map[string][]*mfa.RecoveryCode),
		recoveryAttempts: make(map[string]*recoveryAttempt),
	}
}

// NewUnboundedStore creates a new in-memory Store with no cap on the number of
// recovery-attempt records. Prefer [NewStore]'s bounded default.
func NewUnboundedStore() *Store {
	return &Store{
		totp:             make(map[string]*mfa.TOTPEnrollment),
		recovery:         make(map[string][]*mfa.RecoveryCode),
		recoveryAttempts: make(map[string]*recoveryAttempt),
	}
}

// MaxEntries returns the configured hard cap on the number of recovery-attempt
// records the store tracks. Zero means the store is unbounded (see
// [NewUnboundedStore]).
func (s *Store) MaxEntries() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxSize
}

func key(tenant string, userID uuid.UUID) string {
	return tenant + "\x00" + userID.String()
}

func (s *Store) SaveTOTP(ctx context.Context, tenantID string, e *mfa.TOTPEnrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e.TenantID != "" && e.TenantID != tenantID {
		return mfa.ErrTenantMismatch
	}
	stored := *e
	stored.TenantID = tenantID
	s.totp[key(tenantID, e.UserID)] = &stored
	return nil
}

func (s *Store) ConfirmEnrollment(ctx context.Context, tenantID string, e *mfa.TOTPEnrollment, codeHashes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e.TenantID != "" && e.TenantID != tenantID {
		return mfa.ErrTenantMismatch
	}
	stored := *e
	stored.TenantID = tenantID
	s.totp[key(tenantID, e.UserID)] = &stored

	now := time.Now()
	codes := make([]*mfa.RecoveryCode, 0, len(codeHashes))
	for _, h := range codeHashes {
		codes = append(codes, &mfa.RecoveryCode{
			UserID:    e.UserID,
			TenantID:  tenantID,
			CodeHash:  h,
			CreatedAt: now,
		})
	}
	s.recovery[key(tenantID, e.UserID)] = codes
	delete(s.recoveryAttempts, key(tenantID, e.UserID))
	return nil
}

func (s *Store) GetTOTP(ctx context.Context, tenantID string, userID uuid.UUID) (*mfa.TOTPEnrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	e, ok := s.totp[key(tenantID, userID)]
	if !ok {
		return nil, mfa.ErrNotEnrolled
	}
	cpy := *e
	return &cpy, nil
}

func (s *Store) DeleteTOTP(ctx context.Context, tenantID string, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.totp, key(tenantID, userID))
	return nil
}

func (s *Store) MarkTOTPUsed(ctx context.Context, tenantID string, userID uuid.UUID, step int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.totp[key(tenantID, userID)]
	if !ok {
		// Match the pgx guarded-UPDATE semantics: a missing row simply does not apply.
		return false, nil
	}
	if step <= e.LastUsedStep {
		return false, nil // replay: not strictly newer than the last accepted step
	}
	e.LastUsedStep = step
	e.FailedAttempts = 0          // a fresh accepted code clears the lock-out budget
	e.LastAttemptAt = time.Time{} // reset decay timestamp alongside the counter
	return true, nil
}

func (s *Store) IncrementTOTPAttempts(ctx context.Context, tenantID string, userID uuid.UUID, now time.Time, maxAttempts int, lockoutDuration time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.totp[key(tenantID, userID)]
	if !ok {
		return 0, mfa.ErrNotEnrolled
	}

	if maxAttempts > 0 && e.FailedAttempts >= maxAttempts {
		decayed := false
		if lockoutDuration > 0 && !e.LastAttemptAt.IsZero() && now.Sub(e.LastAttemptAt) > lockoutDuration {
			decayed = true
		}
		if !decayed {
			// Locked and not decayed: DoS fix: do not increment or bump timestamp,
			// but return an over-limit count so the service knows it's locked.
			return e.FailedAttempts + 1, nil
		}
		// Decayed
		e.FailedAttempts = 1
		e.LastAttemptAt = now
		return e.FailedAttempts, nil
	}

	e.FailedAttempts++
	e.LastAttemptAt = now
	return e.FailedAttempts, nil
}

func (s *Store) ReplaceRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID, codeHashes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	codes := make([]*mfa.RecoveryCode, 0, len(codeHashes))
	for _, h := range codeHashes {
		codes = append(codes, &mfa.RecoveryCode{
			UserID:    userID,
			TenantID:  tenantID,
			CodeHash:  h,
			CreatedAt: now,
		})
	}
	s.recovery[key(tenantID, userID)] = codes
	delete(s.recoveryAttempts, key(tenantID, userID))
	return nil
}

func (s *Store) ConsumeRecoveryCode(ctx context.Context, tenantID string, userID uuid.UUID, codeHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	codes := s.recovery[key(tenantID, userID)]
	for _, c := range codes {
		if c.UsedAt == nil && c.CodeHash == codeHash {
			now := time.Now()
			c.UsedAt = &now
			// A valid recovery code is a successful second-factor verification: clear the TOTP
			// lock-out budget and decay timestamp if an enrollment exists (no-op otherwise).
			if e, ok := s.totp[key(tenantID, userID)]; ok {
				e.FailedAttempts = 0
				e.LastAttemptAt = time.Time{}
			}
			delete(s.recoveryAttempts, key(tenantID, userID))
			return nil
		}
	}
	return mfa.ErrRecoveryCodeNotFound
}

func (s *Store) DeleteRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.recovery, key(tenantID, userID))
	delete(s.recoveryAttempts, key(tenantID, userID))
	return nil
}

func (s *Store) IncrementRecoveryAttempts(ctx context.Context, tenantID string, userID uuid.UUID, now time.Time, maxAttempts int, lockoutDuration time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := key(tenantID, userID)
	att, ok := s.recoveryAttempts[k]
	if !ok {
		if s.maxSize > 0 && len(s.recoveryAttempts) >= s.maxSize {
			s.evictStalestRecoveryAttemptLocked()
		}
		att = &recoveryAttempt{}
		s.recoveryAttempts[k] = att
	}

	if maxAttempts > 0 && att.failedAttempts >= maxAttempts {
		decayed := false
		if lockoutDuration > 0 && !att.lastAttemptAt.IsZero() && now.Sub(att.lastAttemptAt) > lockoutDuration {
			decayed = true
		}
		if !decayed {
			return att.failedAttempts + 1, nil
		}
		att.failedAttempts = 1
		att.lastAttemptAt = now
		return att.failedAttempts, nil
	}

	att.failedAttempts++
	att.lastAttemptAt = now
	return att.failedAttempts, nil
}

func (s *Store) ResetRecoveryAttempts(ctx context.Context, tenantID string, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.recoveryAttempts, key(tenantID, userID))
	return nil
}

// DeleteStaleRecoveryAttempts removes recovery-attempt records within tenantID whose last
// recorded attempt is strictly before cutoff, returning the number removed. It is the
// schedulable reaper for [NewUnboundedStore] callers (the bounded default needs none); run it
// via [github.com/JLugagne/egauth/janitor] with a cutoff comfortably older than the configured
// lockout window.
func (s *Store) DeleteStaleRecoveryAttempts(ctx context.Context, tenantID string, cutoff time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prefix := tenantID + "\x00"
	var deleted int64
	for k, att := range s.recoveryAttempts {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if att.lastAttemptAt.Before(cutoff) {
			delete(s.recoveryAttempts, k)
			deleted++
		}
	}
	return deleted, nil
}

// evictStalestRecoveryAttemptLocked removes the recovery-attempt record with the
// earliest lastAttemptAt to make room for a new one. Must be called with the write
// lock held.
func (s *Store) evictStalestRecoveryAttemptLocked() {
	var (
		victimKey string
		victimAt  time.Time
		found     bool
	)
	for k, att := range s.recoveryAttempts {
		if !found || att.lastAttemptAt.Before(victimAt) {
			victimKey = k
			victimAt = att.lastAttemptAt
			found = true
		}
	}
	if found {
		delete(s.recoveryAttempts, victimKey)
	}
}

var _ mfa.Store = (*Store)(nil)

func (s *Store) ResetTOTPAttempts(ctx context.Context, tenantID string, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.totp[key(tenantID, userID)]
	if !ok {
		return mfa.ErrNotEnrolled
	}
	e.FailedAttempts = 0
	e.LastAttemptAt = time.Time{}
	return nil
}
