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

func (s *countingKeyStore) ActiveSigningKey(_ context.Context, tenantID string) (Signer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeCalls[tenantID]++
	kid := s.kidFor(tenantID)
	return mustHMACSigner(kid), nil
}

func (s *countingKeyStore) VerificationKeys(_ context.Context, tenantID string) (map[string]Signer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifyCalls[tenantID]++
	kid := s.kidFor(tenantID)
	return map[string]Signer{kid: mustHMACSigner(kid)}, nil
}

// mustHMACSigner builds an HMAC signer with a padded secret, panicking on the (impossible) error.
// Used where the call site has no *testing.T.
func mustHMACSigner(kid string) Signer {
	secret := []byte("secret-" + kid)
	if len(secret) < MinSecretKeyLength {
		padded := make([]byte, MinSecretKeyLength)
		copy(padded, secret)
		secret = padded
	}
	sg, err := NewHMACSigner(kid, secret)
	if err != nil {
		panic(err)
	}
	return sg
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
	for range 5 {
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
	if k.KeyID() != "k1-tenant-a" {
		t.Fatalf("unexpected initial kid %q", k.KeyID())
	}

	// Rotate the backing key, then prove the cache still serves the stale kid until invalidated.
	backing.rotate("tenant-a", "k2")
	k, _ = cache.ActiveSigningKey(ctx, "tenant-a")
	if k.KeyID() != "k1-tenant-a" {
		t.Fatalf("expected stale cached kid before invalidation, got %q", k.KeyID())
	}

	cache.Invalidate("tenant-a")
	k, _ = cache.ActiveSigningKey(ctx, "tenant-a")
	if k.KeyID() != "k2" {
		t.Fatalf("expected rotated kid after invalidation, got %q", k.KeyID())
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
			if tc.flush && k.KeyID() != "k2" {
				t.Fatalf("expected cache flushed on %s, still serving %q", tc.typ, k.KeyID())
			}
			if !tc.flush && k.KeyID() != "k1-tenant-a" {
				t.Fatalf("expected cache untouched by %s, got %q", tc.typ, k.KeyID())
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
	keys["forged"] = mustHMACSigner("forged")

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

// blockingVerifyKeyStore wraps a countingKeyStore and blocks the FIRST VerificationKeys call
// (the second delegate read of a fill) until released, so a test can inject an Invalidate while a
// cache fill is in flight. Subsequent calls pass straight through.
type blockingVerifyKeyStore struct {
	backing *countingKeyStore
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (s *blockingVerifyKeyStore) ActiveSigningKey(ctx context.Context, tenantID string) (Signer, error) {
	return s.backing.ActiveSigningKey(ctx, tenantID)
}

func (s *blockingVerifyKeyStore) VerificationKeys(ctx context.Context, tenantID string) (map[string]Signer, error) {
	s.once.Do(func() {
		close(s.entered)
		<-s.release
	})
	return s.backing.VerificationKeys(ctx, tenantID)
}

// TestCachingKeyStore_InvalidateDuringFillIsNotLost is a regression test: an Invalidate (rotation/
// revocation/deletion event) that fires while a cache fill is reading the delegate must not be
// lost. Before the fix, store() wrote unconditionally, so the in-flight fill re-cached the
// pre-rotation keyset for a full TTL — silently defeating the event sink's zero-staleness promise
// for a compromise-response key revocation.
func TestCachingKeyStore_InvalidateDuringFillIsNotLost(t *testing.T) {
	backing := newCountingKeyStore()
	del := &blockingVerifyKeyStore{
		backing: backing,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	cache := NewCachingKeyStore(del, time.Hour) // long TTL so only invalidation can refresh
	ctx := context.Background()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = cache.ActiveSigningKey(ctx, "tenant-a") // fill: reads active=k1, blocks in VerificationKeys
	}()

	<-del.entered                    // the fill has read the (old) active key and is mid-read
	backing.rotate("tenant-a", "k2") // the key is rotated/revoked in the backing store
	cache.Invalidate("tenant-a")     // ...and the invalidation event fires while the fill is open
	close(del.release)               // let the fill run store()
	<-done                           // fill finished (cached the stale keyset, or correctly dropped it)

	k, err := cache.ActiveSigningKey(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}
	if k.KeyID() != "k2" {
		t.Fatalf("invalidation during fill was lost: serving stale kid %q, want k2", k.KeyID())
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

func TestCachingKeyStore_BoundedCapacity(t *testing.T) {
	backing := newCountingKeyStore()
	cache := NewCachingKeyStore(backing, time.Hour, WithCacheMaxEntries(3))

	ctx := context.Background()
	tenants := []string{"t1", "t2", "t3", "t4", "t5"}
	for _, tenant := range tenants {
		if _, err := cache.ActiveSigningKey(ctx, tenant); err != nil {
			t.Fatalf("ActiveSigningKey(%s): %v", tenant, err)
		}
	}

	if n := cache.Len(); n != 3 {
		t.Fatalf("expected cache size bounded to 3, got %d", n)
	}
}

func TestCachingKeyStore_DefaultMaxEntries(t *testing.T) {
	backing := newCountingKeyStore()
	cache := NewCachingKeyStore(backing, time.Hour, WithCacheMaxEntries(0))
	if cache.maxEntries != DefaultKeyCacheMaxEntries {
		t.Fatalf("expected maxEntries to default to %d, got %d", DefaultKeyCacheMaxEntries, cache.maxEntries)
	}
	negCache := NewCachingKeyStore(backing, time.Hour, WithCacheMaxEntries(-10))
	if negCache.maxEntries != DefaultKeyCacheMaxEntries {
		t.Fatalf("expected maxEntries to default to %d, got %d", DefaultKeyCacheMaxEntries, negCache.maxEntries)
	}
}

func TestCachingKeyStore_EvictsExpiredEntriesWhenCapacityReached(t *testing.T) {
	backing := newCountingKeyStore()
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	ttl := 10 * time.Second
	cache := NewCachingKeyStore(backing, ttl, WithCacheMaxEntries(3), WithCacheClock(clock))

	ctx := context.Background()
	// Fill cache to capacity (3 entries: t1, t2, t3)
	for _, tenant := range []string{"t1", "t2", "t3"} {
		if _, err := cache.ActiveSigningKey(ctx, tenant); err != nil {
			t.Fatalf("ActiveSigningKey(%s): %v", tenant, err)
		}
	}
	if cache.Len() != 3 {
		t.Fatalf("expected 3 entries in cache, got %d", cache.Len())
	}

	// Advance time past TTL
	now = now.Add(ttl + time.Second)

	// Querying a new tenant t4 reaches capacity check and sweeps all expired entries
	if _, err := cache.ActiveSigningKey(ctx, "t4"); err != nil {
		t.Fatalf("ActiveSigningKey(t4): %v", err)
	}

	// The 3 expired entries should have been evicted; only t4 remains
	if cache.Len() != 1 {
		t.Fatalf("expected 1 entry in cache after sweep of expired entries, got %d", cache.Len())
	}

	// t1 was evicted, so querying t1 should hit the backing store again
	if _, err := cache.ActiveSigningKey(ctx, "t1"); err != nil {
		t.Fatalf("ActiveSigningKey(t1): %v", err)
	}
	if active, _ := backing.calls("t1"); active != 2 {
		t.Fatalf("expected t1 to be re-resolved from backing store (2 calls), got %d", active)
	}
}

func TestCachingKeyStore_EvictsOldestEntryWhenCapacityExceededByUnexpired(t *testing.T) {
	backing := newCountingKeyStore()
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	cache := NewCachingKeyStore(backing, time.Hour, WithCacheMaxEntries(3), WithCacheClock(clock))

	ctx := context.Background()
	// Store t1 at now
	if _, err := cache.ActiveSigningKey(ctx, "t1"); err != nil {
		t.Fatalf("ActiveSigningKey(t1): %v", err)
	}

	// Store t2 at now+1s
	now = now.Add(time.Second)
	if _, err := cache.ActiveSigningKey(ctx, "t2"); err != nil {
		t.Fatalf("ActiveSigningKey(t2): %v", err)
	}

	// Store t3 at now+2s
	now = now.Add(time.Second)
	if _, err := cache.ActiveSigningKey(ctx, "t3"); err != nil {
		t.Fatalf("ActiveSigningKey(t3): %v", err)
	}

	if cache.Len() != 3 {
		t.Fatalf("expected 3 entries in cache, got %d", cache.Len())
	}

	// Store t4 at now+3s; capacity exceeded by unexpired entries, so oldest entry (t1) must be evicted
	now = now.Add(time.Second)
	if _, err := cache.ActiveSigningKey(ctx, "t4"); err != nil {
		t.Fatalf("ActiveSigningKey(t4): %v", err)
	}

	if cache.Len() != 3 {
		t.Fatalf("expected cache size bounded at 3, got %d", cache.Len())
	}

	// t2, t3, t4 should still be cached (1 backing call each)
	for _, tenant := range []string{"t2", "t3", "t4"} {
		if _, err := cache.ActiveSigningKey(ctx, tenant); err != nil {
			t.Fatalf("ActiveSigningKey(%s): %v", tenant, err)
		}
		if active, _ := backing.calls(tenant); active != 1 {
			t.Fatalf("expected %s to be served from cache (1 call), got %d", tenant, active)
		}
	}

	// t1 was evicted as oldest, so querying t1 must re-read backing store (2 calls)
	if _, err := cache.ActiveSigningKey(ctx, "t1"); err != nil {
		t.Fatalf("ActiveSigningKey(t1): %v", err)
	}
	if active, _ := backing.calls("t1"); active != 2 {
		t.Fatalf("expected t1 to be re-resolved from backing store after eviction (2 calls), got %d", active)
	}
}
