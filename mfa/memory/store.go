// Package memory provides an in-memory mfa.Store, primarily for tests and single-process use.
package memory

import (
	"context"
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
type Store struct {
	mu               sync.RWMutex
	totp             map[string]*mfa.TOTPEnrollment
	recovery         map[string][]*mfa.RecoveryCode
	recoveryAttempts map[string]*recoveryAttempt
}

// NewStore creates a new in-memory Store.
func NewStore() *Store {
	return &Store{
		totp:             make(map[string]*mfa.TOTPEnrollment),
		recovery:         make(map[string][]*mfa.RecoveryCode),
		recoveryAttempts: make(map[string]*recoveryAttempt),
	}
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
