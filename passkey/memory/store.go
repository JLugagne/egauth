// Package memory provides an in-memory passkey.Store, primarily for tests and single-process
// use.
package memory

import (
	"bytes"
	"context"
	"strings"
	"sync"

	"github.com/JLugagne/libauth/passkey"
	"github.com/google/uuid"
)

// Store is an in-memory implementation of passkey.Store.
type Store struct {
	mu    sync.RWMutex
	creds map[string][]*passkey.Credential // key: tenant \x00 userID
}

// NewStore creates a new in-memory Store.
func NewStore() *Store {
	return &Store{creds: make(map[string][]*passkey.Credential)}
}

func tenantOf(opts []passkey.Option) string {
	o := passkey.ApplyOptions(opts)
	if o.TenantID == nil {
		return ""
	}
	return *o.TenantID
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

	tenant := tenantOf(opts)
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

	stored := s.creds[key(tenantOf(opts), userID)]
	out := make([]*passkey.Credential, 0, len(stored))
	for _, c := range stored {
		out = append(out, clone(c))
	}
	return out, nil
}

func (s *Store) UpdateCredential(ctx context.Context, c *passkey.Credential, opts ...passkey.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	list := s.creds[key(tenantOf(opts), c.UserID)]
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

	k := key(tenantOf(opts), userID)
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
