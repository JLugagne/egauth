package jwt

import (
	"context"
	"testing"
	"time"
)

// The verification path is reachable UNAUTHENTICATED (anyone can present a token for any tenant),
// so it must never resolve the tenant's ACTIVE signing key: with keystore.WithLazyProvisioning that
// resolution mints a key and writes to the database, handing an anonymous caller a tenant- and
// key-creation primitive. A verify-path cache miss may read the verification set and nothing else.

func TestCachingKeyStore_VerificationKeysNeverResolvesActiveKey(t *testing.T) {
	backing := newCountingKeyStore()
	cache := NewCachingKeyStore(backing, time.Minute)

	if _, err := cache.VerificationKeys(context.Background(), "tenant-a"); err != nil {
		t.Fatalf("VerificationKeys: %v", err)
	}

	active, verify := backing.calls("tenant-a")
	if active != 0 {
		t.Fatalf("a verification-path cache miss resolved the active signing key %d time(s); it must resolve verification keys only", active)
	}
	if verify != 1 {
		t.Fatalf("expected exactly one delegate VerificationKeys read, got %d", verify)
	}
}

func TestCachingKeyStore_VerifyFillDoesNotSatisfyTheSigningPath(t *testing.T) {
	backing := newCountingKeyStore()
	cache := NewCachingKeyStore(backing, time.Minute)
	ctx := context.Background()

	if _, err := cache.VerificationKeys(ctx, "tenant-a"); err != nil {
		t.Fatalf("VerificationKeys: %v", err)
	}
	if _, err := cache.ActiveSigningKey(ctx, "tenant-a"); err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}

	if active, _ := backing.calls("tenant-a"); active != 1 {
		t.Fatalf("the signing path must still resolve the active key from the delegate, got %d calls", active)
	}
}
