// Package memory provides an in-memory passkey.Store, primarily for tests and single-process
// deployments.
package memory

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/JLugagne/egauth/passkey"
	"github.com/google/uuid"
)

// DefaultMaxCredentialsPerUser caps how many authenticators one account may register. WebAuthn
// practice is a handful (a phone, a laptop, a security key); the cap exists so the per-user slice
// cannot grow without bound, and it fails closed rather than evicting an existing authenticator.
const DefaultMaxCredentialsPerUser = 20

// DefaultMaxCredentialsPerTenant caps the total credentials a tenant may hold, so one account on a
// shared in-memory store cannot consume unbounded memory on behalf of the whole tenant.
const DefaultMaxCredentialsPerTenant = 8192

// ErrTooManyCredentials is returned by SaveCredential when the user (or the tenant) already holds
// the configured maximum. It is deliberately fail-closed: evicting a credential to make room would
// lock a legitimate user out of an authenticator they still rely on.
var ErrTooManyCredentials = fmt.Errorf("%w: credential limit reached", passkey.ErrStoreCapacityReached)

// Store is an in-memory implementation of passkey.Store.
//
// Credential IDs are indexed tenant-wide, so the uniqueness the pgx PRIMARY KEY
// (tenant_id, credential_id) provides is enforced with one map lookup instead of a scan over every
// credential in the tenant. Registration and login both call into this store on the request path,
// so the per-save cost must not grow with the size of the tenant.
type Store struct {
	mu    sync.RWMutex
	creds map[string][]*passkey.Credential // key: tenant \x00 userID
	// byID indexes credential IDs tenant-wide: tenant \x00 credentialID -> owner key. It mirrors
	// the pgx unique index and makes the duplicate check O(1).
	byID map[string]string
	// counts tracks credentials per tenant, so the tenant cap is O(1).
	counts map[string]int
	// maxPerUser and maxPerTenant cap the store. Non-positive selects the Default* values; the
	// caps cannot be disabled, because an uncapped store lets a single account grow the tenant's
	// memory without bound.
	maxPerUser   int
	maxPerTenant int
}

// StoreOption configures a Store.
type StoreOption func(*Store)

// WithMaxCredentialsPerUser caps authenticators per account. A non-positive value selects
// DefaultMaxCredentialsPerUser.
func WithMaxCredentialsPerUser(n int) StoreOption {
	return func(s *Store) { s.maxPerUser = n }
}

// WithMaxCredentialsPerTenant caps credentials per tenant. A non-positive value selects
// DefaultMaxCredentialsPerTenant.
func WithMaxCredentialsPerTenant(n int) StoreOption {
	return func(s *Store) { s.maxPerTenant = n }
}

// NewStore creates a new in-memory Store.
func NewStore(opts ...StoreOption) *Store {
	s := &Store{
		creds:        make(map[string][]*passkey.Credential),
		byID:         make(map[string]string),
		counts:       make(map[string]int),
		maxPerUser:   DefaultMaxCredentialsPerUser,
		maxPerTenant: DefaultMaxCredentialsPerTenant,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.maxPerUser <= 0 {
		s.maxPerUser = DefaultMaxCredentialsPerUser
	}
	if s.maxPerTenant <= 0 {
		s.maxPerTenant = DefaultMaxCredentialsPerTenant
	}
	return s
}

// Limits reports the per-user and per-tenant caps this store enforces.
func (s *Store) Limits() (perUser, perTenant int) { return s.maxPerUser, s.maxPerTenant }

func key(tenant string, userID uuid.UUID) string {
	return tenant + "\x00" + userID.String()
}

// idKey indexes a credential ID within its tenant, mirroring the pgx unique index on
// (tenant_id, credential_id).
func idKey(tenant string, credentialID []byte) string {
	return tenant + "\x00" + string(credentialID)
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
//
// A credential the user already holds is rejected with ErrCredentialExists, a credential held by
// ANY user in the tenant is rejected with ErrCredentialExists (matching the pgx unique index), and
// reaching either cap is rejected with ErrTooManyCredentials. Every check is a map lookup, so the
// cost of a save does not grow with the tenant's credential count.
func (s *Store) SaveCredential(_ context.Context, tenantID string, c *passkey.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if c.TenantID != "" && c.TenantID != tenantID {
		return passkey.ErrTenantMismatch
	}

	if _, exists := s.byID[idKey(tenantID, c.ID)]; exists {
		return passkey.ErrCredentialExists
	}

	k := key(tenantID, c.UserID)
	if len(s.creds[k]) >= s.maxPerUser {
		return ErrTooManyCredentials
	}
	if s.counts[tenantID] >= s.maxPerTenant {
		return ErrTooManyCredentials
	}

	stored := clone(c)
	stored.TenantID = tenantID
	s.creds[k] = append(s.creds[k], stored)
	s.byID[idKey(tenantID, stored.ID)] = k
	s.counts[tenantID]++
	return nil
}

// GetCredentials returns all credentials registered by the user (empty slice if none).
func (s *Store) GetCredentials(_ context.Context, tenantID string, userID uuid.UUID) ([]*passkey.Credential, error) {
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
func (s *Store) UpdateCredential(_ context.Context, tenantID string, c *passkey.Credential) error {
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
// ErrCredentialNotFound if absent. Deleting frees both the tenant-wide credential ID and a slot
// against the caps, so a user who removes an authenticator can register another.
func (s *Store) DeleteCredential(_ context.Context, tenantID string, userID uuid.UUID, credentialID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := key(tenantID, userID)
	list := s.creds[k]
	for i, existing := range list {
		if bytes.Equal(existing.ID, credentialID) {
			s.creds[k] = append(list[:i], list[i+1:]...)
			delete(s.byID, idKey(tenantID, existing.ID))
			if s.counts[tenantID] > 0 {
				s.counts[tenantID]--
			}
			return nil
		}
	}
	return passkey.ErrCredentialNotFound
}

var _ passkey.Store = (*Store)(nil)
