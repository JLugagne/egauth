// Package memory provides an in-memory mfa.Store, primarily for tests and single-process use.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/JLugagne/libauth/mfa"
	"github.com/google/uuid"
)

// Store is an in-memory implementation of mfa.Store.
type Store struct {
	mu       sync.RWMutex
	totp     map[string]*mfa.TOTPEnrollment
	recovery map[string][]*mfa.RecoveryCode
	strict   bool
}

// Option configures a Store.
type Option func(*Store)

// WithStrictTenancy makes every tenant-scoped operation require a non-empty tenant
// (mfa.ErrTenantRequired otherwise). Off by default, where an empty tenant is the valid default
// single-tenant partition. Enable it in multi-tenant deployments so a forgotten WithTenant fails
// loudly instead of silently operating on the shared empty-tenant partition.
func WithStrictTenancy() Option { return func(s *Store) { s.strict = true } }

// NewStore creates a new in-memory Store.
func NewStore(opts ...Option) *Store {
	s := &Store{
		totp:     make(map[string]*mfa.TOTPEnrollment),
		recovery: make(map[string][]*mfa.RecoveryCode),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// resolveTenant extracts the operation tenant, enforcing ErrTenantRequired in strict mode.
func (s *Store) resolveTenant(opts []mfa.Option) (string, error) {
	o := mfa.ApplyOptions(opts)
	tenant := ""
	if o.TenantID != nil {
		tenant = *o.TenantID
	}
	if s.strict && tenant == "" {
		return "", mfa.ErrTenantRequired
	}
	return tenant, nil
}

func key(tenant string, userID uuid.UUID) string {
	return tenant + "\x00" + userID.String()
}

func (s *Store) SaveTOTP(ctx context.Context, e *mfa.TOTPEnrollment, opts ...mfa.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return err
	}
	stored := *e
	stored.TenantID = tenant
	s.totp[key(tenant, e.UserID)] = &stored
	return nil
}

func (s *Store) GetTOTP(ctx context.Context, userID uuid.UUID, opts ...mfa.Option) (*mfa.TOTPEnrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return nil, err
	}
	e, ok := s.totp[key(tenant, userID)]
	if !ok {
		return nil, mfa.ErrNotEnrolled
	}
	cpy := *e
	return &cpy, nil
}

func (s *Store) DeleteTOTP(ctx context.Context, userID uuid.UUID, opts ...mfa.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return err
	}
	delete(s.totp, key(tenant, userID))
	return nil
}

func (s *Store) MarkTOTPUsed(ctx context.Context, userID uuid.UUID, step int64, opts ...mfa.Option) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return false, err
	}
	e, ok := s.totp[key(tenant, userID)]
	if !ok {
		// Match the pgx guarded-UPDATE semantics: a missing row simply does not apply.
		return false, nil
	}
	if step <= e.LastUsedStep {
		return false, nil // replay: not strictly newer than the last accepted step
	}
	e.LastUsedStep = step
	return true, nil
}

func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, codeHashes []string, opts ...mfa.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return err
	}
	now := time.Now()
	codes := make([]*mfa.RecoveryCode, 0, len(codeHashes))
	for _, h := range codeHashes {
		codes = append(codes, &mfa.RecoveryCode{
			UserID:    userID,
			TenantID:  tenant,
			CodeHash:  h,
			CreatedAt: now,
		})
	}
	s.recovery[key(tenant, userID)] = codes
	return nil
}

func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID uuid.UUID, codeHash string, opts ...mfa.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return err
	}
	codes := s.recovery[key(tenant, userID)]
	for _, c := range codes {
		if c.UsedAt == nil && c.CodeHash == codeHash {
			now := time.Now()
			c.UsedAt = &now
			return nil
		}
	}
	return mfa.ErrRecoveryCodeNotFound
}

func (s *Store) DeleteRecoveryCodes(ctx context.Context, userID uuid.UUID, opts ...mfa.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return err
	}
	delete(s.recovery, key(tenant, userID))
	return nil
}

var _ mfa.Store = (*Store)(nil)
