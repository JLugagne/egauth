// Package memory provides an in-memory passkey.Store, primarily for tests and single-process
// use.
package memory

import (
	"bytes"
	"context"
	"strings"
	"sync"

	"github.com/JLugagne/egauth/passkey"
	"github.com/google/uuid"
)

// Store is an in-memory implementation of passkey.Store.
type Store struct {
	mu     sync.RWMutex
	creds  map[string][]*passkey.Credential // key: tenant \x00 userID
	strict bool
}

// Option configures a Store.
type Option func(*Store)

// WithStrictTenancy makes every tenant-scoped operation require a non-empty tenant
// (passkey.ErrTenantRequired otherwise). Off by default, where an empty tenant is the valid
// default single-tenant partition. Enable it in multi-tenant deployments so a forgotten
// WithTenant fails loudly instead of silently operating on the shared empty-tenant partition.
func WithStrictTenancy() Option { return func(s *Store) { s.strict = true } }

// NewStore creates a new in-memory Store.
func NewStore(opts ...Option) *Store {
	s := &Store{creds: make(map[string][]*passkey.Credential)}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// resolveTenant extracts the operation tenant, enforcing ErrTenantRequired in strict mode.
func (s *Store) resolveTenant(opts []passkey.Option) (string, error) {
	o := passkey.ApplyOptions(opts)
	tenant := ""
	if o.TenantID != nil {
		tenant = *o.TenantID
	}
	if s.strict && tenant == "" {
		return "", passkey.ErrTenantRequired
	}
	return tenant, nil
}

func key(tenant string, userID uuid.UUID) string {
	return tenant + "\x00" + userID.String()
}

func clone(c *passkey.Credential) *passkey.Credential {
	cp := *c
	cp.ID = append([]byte(nil), c.ID...)
	cp.PublicKey = append([]byte(nil), c.PublicKey...)
	cp.Data = append([]byte(nil), c.Data...)
	return &cp
}

func (s *Store) SaveCredential(ctx context.Context, c *passkey.Credential, opts ...passkey.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return err
	}
	// Enforce the same uniqueness the pgx PRIMARY KEY (tenant_id, credential_id) does: a
	// credential ID is unique tenant-wide, across all users.
	prefix := tenant + "\x00"
	for k, list := range s.creds {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		for _, existing := range list {
			if bytes.Equal(existing.ID, c.ID) {
				return passkey.ErrCredentialExists
			}
		}
	}

	stored := clone(c)
	stored.TenantID = tenant
	k := key(tenant, c.UserID)
	s.creds[k] = append(s.creds[k], stored)
	return nil
}

func (s *Store) GetCredentials(ctx context.Context, userID uuid.UUID, opts ...passkey.Option) ([]*passkey.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return nil, err
	}
	stored := s.creds[key(tenant, userID)]
	out := make([]*passkey.Credential, 0, len(stored))
	for _, c := range stored {
		out = append(out, clone(c))
	}
	return out, nil
}

func (s *Store) UpdateCredential(ctx context.Context, c *passkey.Credential, opts ...passkey.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return err
	}
	list := s.creds[key(tenant, c.UserID)]
	for i, existing := range list {
		if bytes.Equal(existing.ID, c.ID) {
			updated := clone(c)
			updated.TenantID = existing.TenantID
			updated.CreatedAt = existing.CreatedAt // preserve creation time
			list[i] = updated
			return nil
		}
	}
	return passkey.ErrCredentialNotFound
}

func (s *Store) DeleteCredential(ctx context.Context, userID uuid.UUID, credentialID []byte, opts ...passkey.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return err
	}
	k := key(tenant, userID)
	list := s.creds[k]
	for i, existing := range list {
		if bytes.Equal(existing.ID, credentialID) {
			s.creds[k] = append(list[:i], list[i+1:]...)
			return nil
		}
	}
	return passkey.ErrCredentialNotFound
}

var _ passkey.Store = (*Store)(nil)
