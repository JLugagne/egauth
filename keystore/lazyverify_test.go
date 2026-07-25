package keystore_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/keystore/memory"
	"github.com/JLugagne/egauth/tokens/jwt"
)

// TestVerifyPathNeverLazyProvisions pins the end-to-end shape of the finding: with
// WithLazyProvisioning wired, an UNAUTHENTICATED verify for an unknown tenant (the JWKS/verify
// path resolves verification keys only) must not create the tenant nor mint a key. Provisioning
// is a privileged, deliberate act on the signing path.
func TestVerifyPathNeverLazyProvisions(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	kek, err := keystore.NewKEK(bytes.Repeat([]byte("k"), keystore.KEKKeyLength))
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	mgr, err := keystore.NewManager(store, kek, keystore.WithLazyProvisioning())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	cache := jwt.NewCachingKeyStore(keystore.NewJWTKeyStore(mgr), time.Minute)

	if _, err := cache.VerificationKeys(ctx, "attacker-chosen-tenant"); !errors.Is(err, keystore.ErrTenantNotFound) {
		t.Fatalf("verification of an unknown tenant must fail closed with ErrTenantNotFound, got %v", err)
	}

	exists, err := store.TenantExists(ctx, "attacker-chosen-tenant")
	if err != nil {
		t.Fatalf("TenantExists: %v", err)
	}
	if exists {
		t.Fatal("an unauthenticated verify provisioned a tenant: attacker-driven key creation")
	}
	if _, err := store.ActiveSigningKey(ctx, "attacker-chosen-tenant"); !errors.Is(err, keystore.ErrTenantNotFound) {
		t.Fatalf("an unauthenticated verify minted a signing key (store returned %v)", err)
	}
}

// TestSigningPathStillLazyProvisions is the companion: the documented lazy-provisioning behavior
// must survive the verify-path fix on the path it was designed for.
func TestSigningPathStillLazyProvisions(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	kek, err := keystore.NewKEK(bytes.Repeat([]byte("k"), keystore.KEKKeyLength))
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	mgr, err := keystore.NewManager(store, kek, keystore.WithLazyProvisioning())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	cache := jwt.NewCachingKeyStore(keystore.NewJWTKeyStore(mgr), time.Minute)

	if _, err := cache.ActiveSigningKey(ctx, "acme"); err != nil {
		t.Fatalf("ActiveSigningKey must lazily provision, got %v", err)
	}
	exists, err := store.TenantExists(ctx, "acme")
	if err != nil {
		t.Fatalf("TenantExists: %v", err)
	}
	if !exists {
		t.Fatal("the signing path must still lazily provision the tenant")
	}
}
