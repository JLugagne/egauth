package jwt

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
)

// countingKeyStore is a test KeyStore that records how many times the backing store is consulted
// per tenant, and lets a test rotate a tenant's active key id to model a keystore rotation.
type countingKeyStore struct {
	mu          sync.Mutex
	activeCalls map[string]int
	verifyCalls map[string]int
	activeKid   map[string]string
}

func newCountingKeyStore() *countingKeyStore {
	return &countingKeyStore{
		activeCalls: map[string]int{},
		verifyCalls: map[string]int{},
		activeKid:   map[string]string{},
	}
}

func (s *countingKeyStore) kidFor(tenantID string) string {
	if k := s.activeKid[tenantID]; k != "" {
		return k
	}
	return "k1-" + tenantID
}

func (s *countingKeyStore) ActiveSigningKey(_ context.Context, tenantID string) (TenantKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeCalls[tenantID]++
	kid := s.kidFor(tenantID)
	return TenantKey{KeyID: kid, Secret: []byte("secret-" + kid)}, nil
}

func (s *countingKeyStore) VerificationKeys(_ context.Context, tenantID string) (map[string]TenantKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifyCalls[tenantID]++
	kid := s.kidFor(tenantID)
	return map[string]TenantKey{kid: {KeyID: kid, Secret: []byte("secret-" + kid)}}, nil
}

func (s *countingKeyStore) rotate(tenantID, newKid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeKid[tenantID] = newKid
}

func (s *countingKeyStore) calls(tenantID string) (active, verify int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeCalls[tenantID], s.verifyCalls[tenantID]
}

func TestCachingKeyStore_ServesFromCacheWithinTTL(t *testing.T) {
	backing := newCountingKeyStore()
	cache := NewCachingKeyStore(backing, time.Minute)

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := cache.ActiveSigningKey(ctx, "tenant-a"); err != nil {
			t.Fatalf("ActiveSigningKey: %v", err)
		}
		if _, err := cache.VerificationKeys(ctx, "tenant-a"); err != nil {
			t.Fatalf("VerificationKeys: %v", err)
		}
	}

	active, verify := backing.calls("tenant-a")
	// The first ActiveSigningKey fills both halves of the entry in one read; every subsequent
	// call within the TTL is served from cache.
	if active != 1 || verify != 1 {
		t.Fatalf("expected backing consulted once per kind, got active=%d verify=%d", active, verify)
	}
}

func TestCachingKeyStore_ReResolvesAfterTTL(t *testing.T) {
	backing := newCountingKeyStore()
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	cache := NewCachingKeyStore(backing, 30*time.Second, WithCacheClock(clock))

	ctx := context.Background()
	if _, err := cache.ActiveSigningKey(ctx, "tenant-a"); err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}
	// Within TTL: still cached.
	now = now.Add(29 * time.Second)
	if _, err := cache.ActiveSigningKey(ctx, "tenant-a"); err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}
	if active, _ := backing.calls("tenant-a"); active != 1 {
		t.Fatalf("expected 1 backing read within TTL, got %d", active)
	}
	// Past TTL: re-resolves.
	now = now.Add(2 * time.Second) // total 31s > 30s TTL
	if _, err := cache.ActiveSigningKey(ctx, "tenant-a"); err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}
	if active, _ := backing.calls("tenant-a"); active != 2 {
		t.Fatalf("expected 2 backing reads after TTL expiry, got %d", active)
	}
}

func TestCachingKeyStore_InvalidateOnRotation(t *testing.T) {
	backing := newCountingKeyStore()
	cache := NewCachingKeyStore(backing, time.Hour) // long TTL so only invalidation can refresh

	ctx := context.Background()
	k, err := cache.ActiveSigningKey(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}
	if k.KeyID != "k1-tenant-a" {
		t.Fatalf("unexpected initial kid %q", k.KeyID)
	}

	// Rotate the backing key, then prove the cache still serves the stale kid until invalidated.
	backing.rotate("tenant-a", "k2")
	k, _ = cache.ActiveSigningKey(ctx, "tenant-a")
	if k.KeyID != "k1-tenant-a" {
		t.Fatalf("expected stale cached kid before invalidation, got %q", k.KeyID)
	}

	cache.Invalidate("tenant-a")
	k, _ = cache.ActiveSigningKey(ctx, "tenant-a")
	if k.KeyID != "k2" {
		t.Fatalf("expected rotated kid after invalidation, got %q", k.KeyID)
	}
}

func TestCachingKeyStore_InvalidatesOnKeystoreEvents(t *testing.T) {
	cases := []struct {
		name  string
		typ   event.Type
		flush bool
	}{
		{"renewed", "tenant.keys_renewed", true},
		{"revoked", "tenant.keys_revoked", true},
		{"deleted", "tenant.deleted", true},
		{"unrelated", "tenant.provisioned", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backing := newCountingKeyStore()
			cache := NewCachingKeyStore(backing, time.Hour)
			ctx := context.Background()

			if _, err := cache.ActiveSigningKey(ctx, "tenant-a"); err != nil {
				t.Fatalf("ActiveSigningKey: %v", err)
			}
			backing.rotate("tenant-a", "k2")

			// Deliver the event exactly as a keystore.Manager would through its event.Sink.
			cache.EmitEvent(ctx, event.Event{Type: tc.typ, TenantID: "tenant-a"})

			k, _ := cache.ActiveSigningKey(ctx, "tenant-a")
			if tc.flush && k.KeyID != "k2" {
				t.Fatalf("expected cache flushed on %s, still serving %q", tc.typ, k.KeyID)
			}
			if !tc.flush && k.KeyID != "k1-tenant-a" {
				t.Fatalf("expected cache untouched by %s, got %q", tc.typ, k.KeyID)
			}
		})
	}
}

func TestCachingKeyStore_VerificationKeysReturnsCopy(t *testing.T) {
	backing := newCountingKeyStore()
	cache := NewCachingKeyStore(backing, time.Hour)
	ctx := context.Background()

	keys, err := cache.VerificationKeys(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("VerificationKeys: %v", err)
	}
	// Mutating the returned map must not corrupt the cached entry.
	for k := range keys {
		delete(keys, k)
	}
	keys["forged"] = TenantKey{KeyID: "forged", Secret: []byte("x")}

	again, err := cache.VerificationKeys(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("VerificationKeys: %v", err)
	}
	if _, ok := again["forged"]; ok {
		t.Fatal("cache returned a mutable map; forged key leaked into cached state")
	}
	if _, ok := again["k1-tenant-a"]; !ok {
		t.Fatal("cached verification key was clobbered by caller mutation")
	}
}

// TestCachingKeyStore_NilDelegatePanics documents the fail-fast contract.
func TestCachingKeyStore_NilDelegatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on nil delegate")
		}
	}()
	_ = NewCachingKeyStore(nil, time.Minute)
}

// compile-time assertions: CachingKeyStore is both a KeyStore and an event.Sink.
var (
	_ KeyStore   = (*CachingKeyStore)(nil)
	_ event.Sink = (*CachingKeyStore)(nil)
)
