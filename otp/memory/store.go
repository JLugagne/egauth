// Package memory provides an in-memory otp.Store, primarily for tests and single-process use.
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
	mu     sync.RWMutex
	codes  map[string]*otp.OTP // key: tenant \x00 subject \x00 purpose
	strict bool
}

// Option configures a Store.
type Option func(*Store)

// WithStrictTenancy makes every operation require a non-empty tenant (ErrTenantRequired
// otherwise). Off by default (empty tenant is the default single-tenant partition); enable it
// in multi-tenant deployments so a forgotten WithTenant fails loudly. (DeleteExpired is exempt.)
func WithStrictTenancy() Option { return func(s *Store) { s.strict = true } }

// NewStore creates a new in-memory Store.
func NewStore(opts ...Option) *Store {
	s := &Store{codes: make(map[string]*otp.OTP)}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func tenantOf(opts []otp.Option) string {
	o := otp.ApplyOptions(opts)
	if o.TenantID == nil {
		return ""
	}
	return *o.TenantID
}

// resolveTenant extracts the operation tenant, enforcing ErrTenantRequired in strict mode.
func (s *Store) resolveTenant(opts []otp.Option) (string, error) {
	tenant := tenantOf(opts)
	if s.strict && tenant == "" {
		return "", otp.ErrTenantRequired
	}
	return tenant, nil
}

func key(tenant string, subjectID uuid.UUID, purpose string) string {
	return tenant + "\x00" + subjectID.String() + "\x00" + purpose
}

func (s *Store) SaveOTP(ctx context.Context, o *otp.OTP, opts ...otp.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return err
	}
	stored := *o
	stored.TenantID = tenant
	s.codes[key(tenant, o.SubjectID, o.Purpose)] = &stored
	return nil
}

func (s *Store) GetOTP(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) (*otp.OTP, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return nil, err
	}
	o, ok := s.codes[key(tenant, subjectID, purpose)]
	if !ok {
		return nil, otp.ErrCodeNotFound
	}
	cpy := *o
	return &cpy, nil
}

func (s *Store) IncrementOTPAttempts(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return 0, err
	}
	o, ok := s.codes[key(tenant, subjectID, purpose)]
	if !ok {
		return 0, otp.ErrCodeNotFound
	}
	o.Attempts++
	return o.Attempts, nil
}

func (s *Store) ConsumeOTP(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return false, err
	}
	k := key(tenant, subjectID, purpose)
	if _, ok := s.codes[k]; !ok {
		return false, nil
	}
	delete(s.codes, k)
	return true, nil
}

func (s *Store) DeleteOTP(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return err
	}
	delete(s.codes, key(tenant, subjectID, purpose))
	return nil
}

// DeleteExpired purges codes past their expiry, returning the number deleted. With WithTenant it
// sweeps a single tenant, otherwise all.
func (s *Store) DeleteExpired(ctx context.Context, opts ...otp.Option) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	o := otp.ApplyOptions(opts)
	now := time.Now()
	var deleted int64
	for k, code := range s.codes {
		if o.TenantID != nil && code.TenantID != *o.TenantID {
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
