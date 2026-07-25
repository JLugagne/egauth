package keystoretest_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/keystore/keystoretest"
)

// sqlModelStore mirrors the semantics of the SQL-backed keystore backend
// (adapters/pgx/keystore) in memory: a tenant record that exists independently of its key rows,
// key rows deleted by revocation, and the tenant row surviving until DeleteTenant. It exists so
// the cross-backend contract (which sentinel is returned when, and what VerificationKeys does for
// a known-but-keyless tenant) is pinned in the core module, without Docker.
type sqlModelStore struct {
	mu      sync.Mutex
	tenants map[string]struct{}
	rows    map[string]map[string]keystore.SigningKey
	now     func() time.Time
}

func newSQLModelStore(now func() time.Time) *sqlModelStore {
	if now == nil {
		now = time.Now
	}
	return &sqlModelStore{
		tenants: map[string]struct{}{},
		rows:    map[string]map[string]keystore.SigningKey{},
		now:     now,
	}
}

func (s *sqlModelStore) CreateTenant(ctx context.Context, tenantID string, initial keystore.SigningKey) error {
	if err := modelGuard(tenantID, initial); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[tenantID]; ok {
		return keystore.ErrTenantExists
	}
	s.tenants[tenantID] = struct{}{}
	initial.TenantID = tenantID
	s.rows[tenantID] = map[string]keystore.SigningKey{initial.KeyID: initial}
	return nil
}

func (s *sqlModelStore) TenantExists(ctx context.Context, tenantID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.tenants[tenantID]
	return ok, nil
}

func (s *sqlModelStore) PutSigningKey(ctx context.Context, tenantID string, key keystore.SigningKey) error {
	if err := modelGuard(tenantID, key); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenants[tenantID] = struct{}{}
	rows := s.rows[tenantID]
	if rows == nil {
		rows = map[string]keystore.SigningKey{}
		s.rows[tenantID] = rows
	}
	key.TenantID = tenantID
	rows[key.KeyID] = key
	return nil
}

func (s *sqlModelStore) ActiveSigningKey(ctx context.Context, tenantID string) (keystore.SigningKey, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[tenantID]; !ok {
		return keystore.SigningKey{}, keystore.ErrTenantNotFound
	}
	var best keystore.SigningKey
	found := false
	for _, k := range s.rows[tenantID] {
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

func (s *sqlModelStore) VerificationKeys(ctx context.Context, tenantID string) (map[string]keystore.SigningKey, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[tenantID]; !ok {
		return nil, keystore.ErrTenantNotFound
	}
	out := map[string]keystore.SigningKey{}
	for id, k := range s.rows[tenantID] {
		if k.IsExpired(now) {
			continue
		}
		out[id] = k
	}
	return out, nil
}

func (s *sqlModelStore) RotateSigningKey(ctx context.Context, tenantID string, next keystore.SigningKey, retiredAt time.Time) error {
	if err := modelGuard(tenantID, next); err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[tenantID]; !ok {
		return keystore.ErrTenantNotFound
	}
	rows := s.rows[tenantID]
	if rows == nil {
		rows = map[string]keystore.SigningKey{}
		s.rows[tenantID] = rows
	}
	for id, k := range rows {
		if !k.IsActive(now) {
			continue
		}
		ra := retiredAt
		k.RetiredAt = &ra
		if k.NotAfter.IsZero() || k.NotAfter.After(retiredAt) {
			k.NotAfter = retiredAt
		}
		rows[id] = k
	}
	next.TenantID = tenantID
	rows[next.KeyID] = next
	return nil
}

func (s *sqlModelStore) RetireExpiredKeys(ctx context.Context, tenantID string, now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for id, k := range s.rows[tenantID] {
		if k.IsExpired(now) {
			delete(s.rows[tenantID], id)
			n++
		}
	}
	return n, nil
}

func (s *sqlModelStore) RevokeTenantKeys(ctx context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[tenantID]; !ok {
		return keystore.ErrTenantNotFound
	}
	delete(s.rows, tenantID)
	return nil
}

func (s *sqlModelStore) DeleteTenant(ctx context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tenants, tenantID)
	delete(s.rows, tenantID)
	return nil
}

func modelGuard(tenantID string, key keystore.SigningKey) error {
	if key.TenantID != "" && key.TenantID != tenantID {
		return keystore.ErrTenantMismatch
	}
	return nil
}

// TestSQLModelStoreConformance runs the full conformance suite against the SQL-backed semantics
// model, so a divergence between the row-backed backend and the contract is caught in the core
// module without a database.
func TestSQLModelStoreConformance(t *testing.T) {
	keystoretest.StoreContractTesting(t, func(now func() time.Time) keystore.Store {
		return newSQLModelStore(now)
	})
}

// TestSQLModelStore_RevokeSurvivesLazyProvisioning pins the security-relevant sentinel rule: a
// revoked tenant still exists, so a lazily-provisioning Manager must NOT mint a replacement
// signing key behind the operator's back.
func TestSQLModelStore_RevokeSurvivesLazyProvisioning(t *testing.T) {
	ctx := context.Background()
	store := newSQLModelStore(time.Now)
	kek, err := keystore.NewKEK(bytes.Repeat([]byte("k"), keystore.KEKKeyLength))
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	mgr, err := keystore.NewManager(store, kek, keystore.WithLazyProvisioning())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := mgr.RevokeTenantKeys(ctx, "acme"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := mgr.ActiveSigningKey(ctx, "acme"); !errors.Is(err, keystore.ErrNoActiveKey) {
		t.Fatalf("revocation reversed: ActiveSigningKey err = %v, want ErrNoActiveKey", err)
	}
}
