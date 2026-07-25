// Package memory is the zero-dependency, in-process keystore.Store backend. It is the default
// for tests and single-node deployments; production multi-node deployments should use a
// persistent backend such as adapters/pgx/keystore.
//
// Secrets handed to this store are already KEK-sealed by the keystore.Manager, so even an
// in-memory store never holds plaintext signing material outside an active sign/verify call.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/JLugagne/egauth/keystore"
)

// Store is an in-memory keystore.Store. The zero value is not usable; call New.
type Store struct {
	mu sync.RWMutex
	// tenants maps tenantID -> (keyID -> key). A present (possibly empty) inner map means the
	// tenant exists; absence means it was never provisioned.
	tenants map[string]map[string]keystore.SigningKey
	// now is the time source; overridable via WithClock for deterministic tests. Defaults to time.Now.
	now func() time.Time
}

// Option configures a Store.
type Option func(*Store)

// WithClock overrides the store's time source (for deterministic tests). It must be the same
// clock the keystore.Manager is configured with, so active/expired evaluation agrees across the
// two layers. The zero value is time.Now.
func WithClock(now func() time.Time) Option {
	return func(s *Store) {
		if now != nil {
			s.now = now
		}
	}
}

// New returns a ready, empty in-memory Store.
func New(opts ...Option) *Store {
	s := &Store{
		tenants: make(map[string]map[string]keystore.SigningKey),
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

var _ keystore.Store = (*Store)(nil)

// CreateTenant records a new tenant with its initial key. It returns keystore.ErrTenantExists if
// the tenant already has key material.
func (s *Store) CreateTenant(ctx context.Context, tenantID string, initial keystore.SigningKey) error {
	if err := guardTenant(tenantID, initial); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[tenantID]; ok {
		return keystore.ErrTenantExists
	}
	initial.TenantID = tenantID
	s.tenants[tenantID] = map[string]keystore.SigningKey{initial.KeyID: initial}
	return nil
}

// TenantExists reports whether the tenant record exists. A revoked (keyless) tenant still exists:
// only DeleteTenant removes the partition, which is what keeps a revocation from being undone by a
// lazily-provisioning Manager.
func (s *Store) TenantExists(ctx context.Context, tenantID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.tenants[tenantID]
	return ok, nil
}

// PutSigningKey inserts or replaces a key for the tenant, auto-creating the tenant partition.
func (s *Store) PutSigningKey(ctx context.Context, tenantID string, key keystore.SigningKey) error {
	if err := guardTenant(tenantID, key); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := s.tenants[tenantID]
	if keys == nil {
		keys = make(map[string]keystore.SigningKey)
		s.tenants[tenantID] = keys
	}
	key.TenantID = tenantID
	keys[key.KeyID] = key
	return nil
}

// ActiveSigningKey returns the tenant's newest active key. Among active keys the one with the
// latest CreatedAt wins (deterministic active selection after a rotation). It returns
// keystore.ErrNoActiveKey for a known tenant with no active key and keystore.ErrTenantNotFound only
// when the tenant record is absent.
func (s *Store) ActiveSigningKey(ctx context.Context, tenantID string) (keystore.SigningKey, error) {
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys, ok := s.tenants[tenantID]
	if !ok {
		return keystore.SigningKey{}, keystore.ErrTenantNotFound
	}
	var best keystore.SigningKey
	found := false
	for _, k := range keys {
		if !k.IsActive(now) {
			continue
		}
		if !found || k.CreatedAt.After(best.CreatedAt) {
			best, found = k, true
		}
	}
	if !found {
		return keystore.SigningKey{}, keystore.ErrNoActiveKey
	}
	return best, nil
}

// VerificationKeys returns every key that may still verify a token (active plus
// retired-but-unexpired), keyed by KeyID.
func (s *Store) VerificationKeys(ctx context.Context, tenantID string) (map[string]keystore.SigningKey, error) {
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys, ok := s.tenants[tenantID]
	if !ok {
		return nil, keystore.ErrTenantNotFound
	}
	out := make(map[string]keystore.SigningKey, len(keys))
	for id, k := range keys {
		if k.IsExpired(now) {
			continue
		}
		out[id] = k
	}
	return out, nil
}

// RotateSigningKey installs next as the new key and retires the current active key (verify-only),
// capping its NotAfter at retiredAt so RetireExpiredKeys reaps it once the overlap elapses.
func (s *Store) RotateSigningKey(ctx context.Context, tenantID string, next keystore.SigningKey, retiredAt time.Time) error {
	if err := guardTenant(tenantID, next); err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, ok := s.tenants[tenantID]
	if !ok {
		return keystore.ErrTenantNotFound
	}
	// Retire every currently-active key.
	for id, k := range keys {
		if !k.IsActive(now) {
			continue
		}
		ra := retiredAt
		k.RetiredAt = &ra
		// Cap the retired key's NotAfter at the overlap boundary so it is reaped on schedule.
		if k.NotAfter.IsZero() || k.NotAfter.After(retiredAt) {
			k.NotAfter = retiredAt
		}
		keys[id] = k
	}
	next.TenantID = tenantID
	keys[next.KeyID] = next
	return nil
}

// RetireExpiredKeys deletes keys whose NotAfter is at or before now, returning the count removed.
// It never removes a key that is still active.
func (s *Store) RetireExpiredKeys(ctx context.Context, tenantID string, now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, ok := s.tenants[tenantID]
	if !ok {
		return 0, keystore.ErrTenantNotFound
	}
	var n int64
	for id, k := range keys {
		if k.IsActive(now) {
			continue
		}
		if k.IsExpired(now) {
			delete(keys, id)
			n++
		}
	}
	return n, nil
}

// RevokeTenantKeys immediately removes every key for the tenant, leaving the (now keyless)
// tenant partition in place.
func (s *Store) RevokeTenantKeys(ctx context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[tenantID]; !ok {
		return keystore.ErrTenantNotFound
	}
	s.tenants[tenantID] = make(map[string]keystore.SigningKey)
	return nil
}

// DeleteTenant removes the tenant and all its keys. Deleting an absent tenant is a no-op success.
func (s *Store) DeleteTenant(ctx context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tenants, tenantID)
	return nil
}

// guardTenant fails closed when a key's embedded TenantID contradicts the operation's tenantID.
func guardTenant(tenantID string, key keystore.SigningKey) error {
	if key.TenantID != "" && key.TenantID != tenantID {
		return keystore.ErrTenantMismatch
	}
	return nil
}
