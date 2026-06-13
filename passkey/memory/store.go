// Package memory provides an in-memory passkey.Store, primarily for tests and single-process
// deployments.
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
	mu    sync.RWMutex
	creds map[string][]*passkey.Credential // key: tenant \x00 userID
}

// NewStore creates a new in-memory Store.
func NewStore() *Store {
	return &Store{creds: make(map[string][]*passkey.Credential)}
}

func key(tenant string, userID uuid.UUID) string {
	return tenant + "\x00" + userID.String()
}

func clone(c *passkey.Credential) *passkey.Credential {
	cp := *c
	cp.ID = append([]byte(nil), c.ID...)
	cp.PublicKey = append([]byte(nil), c.PublicKey...)
	cp.Data = append([]byte(nil), c.Data...)
	// Deep-copy the reference-type management metadata so the store never aliases
	// caller-owned data (a later mutation of the caller's slice/pointer must not
	// leak into the stored record, and vice versa). nil stays nil.
	if c.Transports != nil {
		cp.Transports = append([]string(nil), c.Transports...)
	}
	if c.LastUsedAt != nil {
		t := *c.LastUsedAt
		cp.LastUsedAt = &t
	}
	return &cp
}

// SaveCredential persists a newly registered credential. If c.TenantID is non-empty and
// differs from tenantID, it returns ErrTenantMismatch; otherwise it sets c.TenantID = tenantID.
func (s *Store) SaveCredential(ctx context.Context, tenantID string, c *passkey.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if c.TenantID != "" && c.TenantID != tenantID {
		return passkey.ErrTenantMismatch
	}

	// Enforce the same uniqueness the pgx PRIMARY KEY (tenant_id, credential_id) does: a
	// credential ID is unique tenant-wide, across all users.
	prefix := tenantID + "\x00"
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
	stored.TenantID = tenantID
	k := key(tenantID, c.UserID)
	s.creds[k] = append(s.creds[k], stored)
	return nil
}

// GetCredentials returns all credentials registered by the user (empty slice if none).
func (s *Store) GetCredentials(ctx context.Context, tenantID string, userID uuid.UUID) ([]*passkey.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stored := s.creds[key(tenantID, userID)]
	out := make([]*passkey.Credential, 0, len(stored))
	for _, c := range stored {
		out = append(out, clone(c))
	}
	return out, nil
}

// UpdateCredential persists changes to an existing credential (notably the signature counter
// after a successful login). Returns ErrCredentialNotFound if absent.
func (s *Store) UpdateCredential(ctx context.Context, tenantID string, c *passkey.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	list := s.creds[key(tenantID, c.UserID)]
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

// DeleteCredential removes one of the user's credentials by its credential ID. Returns
// ErrCredentialNotFound if absent.
func (s *Store) DeleteCredential(ctx context.Context, tenantID string, userID uuid.UUID, credentialID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := key(tenantID, userID)
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
