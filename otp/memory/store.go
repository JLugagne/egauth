// Package memory provides an in-memory otp.Store, primarily for tests and single-process use.
package memory

import (
	"context"
	"sync"

	"github.com/JLugagne/libauth/otp"
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

func tenantOf(opts []otp.Option) string {
	o := otp.ApplyOptions(opts)
	if o.TenantID == nil {
		return ""
	}
	return *o.TenantID
}

func key(tenant string, subjectID uuid.UUID, purpose string) string {
	return tenant + "\x00" + subjectID.String() + "\x00" + purpose
}

func (s *Store) SaveOTP(ctx context.Context, o *otp.OTP, opts ...otp.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant := tenantOf(opts)
	stored := *o
	stored.TenantID = tenant
	s.codes[key(tenant, o.SubjectID, o.Purpose)] = &stored
	return nil
}

func (s *Store) GetOTP(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) (*otp.OTP, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	o, ok := s.codes[key(tenantOf(opts), subjectID, purpose)]
	if !ok {
		return nil, otp.ErrCodeNotFound
	}
	cpy := *o
	return &cpy, nil
}

func (s *Store) IncrementOTPAttempts(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	o, ok := s.codes[key(tenantOf(opts), subjectID, purpose)]
	if !ok {
		return 0, otp.ErrCodeNotFound
	}
	o.Attempts++
	return o.Attempts, nil
}

func (s *Store) ConsumeOTP(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := key(tenantOf(opts), subjectID, purpose)
	if _, ok := s.codes[k]; !ok {
		return false, nil
	}
	delete(s.codes, k)
	return true, nil
}

func (s *Store) DeleteOTP(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.codes, key(tenantOf(opts), subjectID, purpose))
	return nil
}

var _ otp.Store = (*Store)(nil)
