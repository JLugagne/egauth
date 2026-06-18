// Package keystoretest is the conformance suite every keystore.Store backend must pass. A
// backend's test calls StoreContractTesting with a factory that builds a fresh, empty store
// bound to a supplied clock, and gets the full battery: provision, renew (overlap continuity),
// revoke, delete, retire, and the adversarial cross-tenant isolation checks.
//
// The suite drives the store through a keystore.Manager (so it covers the seal/open round trip
// and the lifecycle), and also pokes the Store directly where the contract is store-level.
package keystoretest

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/JLugagne/egauth/keystore"
)

// testKEK is a fixed 32-byte AES-256 KEK used across the conformance suite. It is test-only
// material — never reuse it in production.
var testKEK = bytes.Repeat([]byte("k"), keystore.KEKKeyLength)

// StoreFactory returns a fresh, empty store for each subtest, so tests never share state. The
// store MUST use the supplied clock as its time source so its active/expired evaluation agrees
// with the Manager the suite constructs with the same clock.
type StoreFactory func(now func() time.Time) keystore.Store

// newPair builds a store via the factory and a Manager over it, both bound to the same clock.
func newPair(t *testing.T, newStore StoreFactory, now func() time.Time) (keystore.Store, *keystore.Manager) {
	t.Helper()
	store := newStore(now)
	kek, err := keystore.NewKEK(testKEK)
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	mgr, err := keystore.NewManager(store, kek, keystore.WithClock(now))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return store, mgr
}

// StoreContractTesting runs the full keystore conformance + isolation suite against stores
// produced by newStore.
func StoreContractTesting(t *testing.T, newStore StoreFactory) {
	t.Helper()
	t.Run("ProvisionIdempotent", func(t *testing.T) { testProvisionIdempotent(t, newStore) })
	t.Run("ActiveAndVerify", func(t *testing.T) { testActiveAndVerify(t, newStore) })
	t.Run("SecretRoundTrip", func(t *testing.T) { testSecretRoundTrip(t, newStore) })
	t.Run("RenewContinuity", func(t *testing.T) { testRenewContinuity(t, newStore) })
	t.Run("RetireExpired", func(t *testing.T) { testRetireExpired(t, newStore) })
	t.Run("RevokeKeys", func(t *testing.T) { testRevokeKeys(t, newStore) })
	t.Run("DeleteTenant", func(t *testing.T) { testDeleteTenant(t, newStore) })
	t.Run("CrossTenantIsolation", func(t *testing.T) { testCrossTenantIsolation(t, newStore) })
	t.Run("LifecycleIsolation", func(t *testing.T) { testLifecycleIsolation(t, newStore) })
	t.Run("TenantMismatchGuard", func(t *testing.T) { testTenantMismatchGuard(t, newStore) })
	t.Run("AlgRoundTrip", func(t *testing.T) { testAlgRoundTrip(t, newStore) })
	t.Run("AsymmetricProvisionRoundTrip", func(t *testing.T) { testAsymmetricProvisionRoundTrip(t, newStore) })
}

func testProvisionIdempotent(t *testing.T, newStore StoreFactory) {
	ctx := context.Background()
	_, mgr := newPair(t, newStore, time.Now)
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("second provision should be a no-op success: %v", err)
	}
	keys, err := mgr.VerificationKeys(ctx, "acme")
	if err != nil {
		t.Fatalf("VerificationKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("re-provision must not add a second key; got %d keys", len(keys))
	}
}

func testActiveAndVerify(t *testing.T, newStore StoreFactory) {
	ctx := context.Background()
	_, mgr := newPair(t, newStore, time.Now)
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	active, err := mgr.ActiveSigningKey(ctx, "acme")
	if err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}
	if active.KeyID == "" {
		t.Fatal("active key has empty KeyID")
	}
	if len(active.Secret) != 32 {
		t.Fatalf("active secret should be 32 bytes after open, got %d", len(active.Secret))
	}
	verify, err := mgr.VerificationKeys(ctx, "acme")
	if err != nil {
		t.Fatalf("VerificationKeys: %v", err)
	}
	if _, ok := verify[active.KeyID]; !ok {
		t.Fatal("active key must be in the verification set")
	}
}

func testSecretRoundTrip(t *testing.T, newStore StoreFactory) {
	ctx := context.Background()
	store, mgr := newPair(t, newStore, time.Now)
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	// The raw store must hold the SEALED secret (not the plaintext the Manager returns).
	raw, err := store.ActiveSigningKey(ctx, "acme")
	if err != nil {
		t.Fatalf("raw ActiveSigningKey: %v", err)
	}
	opened, err := mgr.ActiveSigningKey(ctx, "acme")
	if err != nil {
		t.Fatalf("manager ActiveSigningKey: %v", err)
	}
	if bytes.Equal(raw.Secret, opened.Secret) {
		t.Fatal("store must persist the KEK-sealed secret, not plaintext")
	}
	if len(raw.Secret) <= len(opened.Secret) {
		t.Fatalf("sealed secret (%d) should be longer than plaintext (%d) due to nonce+tag",
			len(raw.Secret), len(opened.Secret))
	}
}

func testRenewContinuity(t *testing.T, newStore StoreFactory) {
	ctx := context.Background()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clk := t0
	_, mgr := newPair(t, newStore, func() time.Time { return clk })

	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	preActive, _ := mgr.ActiveSigningKey(ctx, "acme")
	preID := preActive.KeyID
	preSecret := append([]byte(nil), preActive.Secret...)

	// Renew with a short overlap so we can step past it.
	clk = t0.Add(time.Hour)
	if err := mgr.RenewSigningKey(ctx, "acme", func(o *keystore.RenewOptions) {
		o.OverlapTTL = 2 * time.Hour
	}); err != nil {
		t.Fatalf("renew: %v", err)
	}

	newActive, err := mgr.ActiveSigningKey(ctx, "acme")
	if err != nil {
		t.Fatalf("active after renew: %v", err)
	}
	if newActive.KeyID == preID {
		t.Fatal("renew must produce a new active key id")
	}
	if bytes.Equal(newActive.Secret, preSecret) {
		t.Fatal("renew must produce a new active secret")
	}

	// During overlap, the OLD key must still be in the verification set (pre-renew tokens verify).
	verify, _ := mgr.VerificationKeys(ctx, "acme")
	if _, ok := verify[preID]; !ok {
		t.Fatal("old key must remain verify-only during the overlap window")
	}
	if _, ok := verify[newActive.KeyID]; !ok {
		t.Fatal("new key must be in the verification set")
	}

	// Step past the overlap and reap: the old key must be gone, the new key intact.
	clk = t0.Add(4 * time.Hour)
	if _, err := mgr.RetireExpiredKeys(ctx, "acme"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	verify, _ = mgr.VerificationKeys(ctx, "acme")
	if _, ok := verify[preID]; ok {
		t.Fatal("old key must be gone after the overlap elapses and retire runs")
	}
	if _, ok := verify[newActive.KeyID]; !ok {
		t.Fatal("new key must survive retirement")
	}
	if _, err := mgr.ActiveSigningKey(ctx, "acme"); err != nil {
		t.Fatalf("new key must still be active after retire: %v", err)
	}
}

func testRetireExpired(t *testing.T, newStore StoreFactory) {
	ctx := context.Background()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clk := t0
	_, mgr := newPair(t, newStore, func() time.Time { return clk })
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	// Retire before any expiry: nothing should be removed and the active key untouched.
	n, err := mgr.RetireExpiredKeys(ctx, "acme")
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	if n != 0 {
		t.Fatalf("no keys should be retired yet, got %d", n)
	}
	if _, err := mgr.ActiveSigningKey(ctx, "acme"); err != nil {
		t.Fatalf("active key must survive a no-op retire: %v", err)
	}
}

func testRevokeKeys(t *testing.T, newStore StoreFactory) {
	ctx := context.Background()
	_, mgr := newPair(t, newStore, time.Now)
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := mgr.RevokeTenantKeys(ctx, "acme"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := mgr.ActiveSigningKey(ctx, "acme"); err == nil {
		t.Fatal("after revoke there must be no active key")
	}
	verify, err := mgr.VerificationKeys(ctx, "acme")
	if err != nil {
		t.Fatalf("VerificationKeys after revoke: %v", err)
	}
	if len(verify) != 0 {
		t.Fatalf("revoke must leave no verification keys, got %d", len(verify))
	}
}

func testDeleteTenant(t *testing.T, newStore StoreFactory) {
	ctx := context.Background()
	store, mgr := newPair(t, newStore, time.Now)
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := mgr.DeleteTenant(ctx, "acme"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	exists, err := store.TenantExists(ctx, "acme")
	if err != nil {
		t.Fatalf("TenantExists: %v", err)
	}
	if exists {
		t.Fatal("tenant must not exist after delete")
	}
	// Idempotent: deleting again is a no-op success.
	if err := mgr.DeleteTenant(ctx, "acme"); err != nil {
		t.Fatalf("second delete must be a no-op success: %v", err)
	}
}

// testCrossTenantIsolation is the adversarial check: two tenants must never share key material,
// and operating on one must be invisible to the other.
func testCrossTenantIsolation(t *testing.T, newStore StoreFactory) {
	ctx := context.Background()
	_, mgr := newPair(t, newStore, time.Now)
	if err := mgr.ProvisionTenant(ctx, "a"); err != nil {
		t.Fatalf("provision a: %v", err)
	}
	if err := mgr.ProvisionTenant(ctx, "b"); err != nil {
		t.Fatalf("provision b: %v", err)
	}
	aKey, _ := mgr.ActiveSigningKey(ctx, "a")
	bKey, _ := mgr.ActiveSigningKey(ctx, "b")

	if aKey.KeyID == bKey.KeyID {
		t.Fatal("two tenants must not share a key id")
	}
	if bytes.Equal(aKey.Secret, bKey.Secret) {
		t.Fatal("two tenants must not share signing material")
	}
	// A's key must NOT appear in B's verification set, and vice versa.
	bVerify, _ := mgr.VerificationKeys(ctx, "b")
	if _, leaked := bVerify[aKey.KeyID]; leaked {
		t.Fatal("tenant A's key must not be verifiable as tenant B")
	}
	aVerify, _ := mgr.VerificationKeys(ctx, "a")
	if _, leaked := aVerify[bKey.KeyID]; leaked {
		t.Fatal("tenant B's key must not be verifiable as tenant A")
	}

	// Rotating A must not change B's active key at all.
	if err := mgr.RenewSigningKey(ctx, "a"); err != nil {
		t.Fatalf("renew a: %v", err)
	}
	bAfter, _ := mgr.ActiveSigningKey(ctx, "b")
	if bAfter.KeyID != bKey.KeyID || !bytes.Equal(bAfter.Secret, bKey.Secret) {
		t.Fatal("rotating tenant A must not affect tenant B's active key")
	}
}

// testLifecycleIsolation: provision A+B distinct, delete A fully, B untouched.
func testLifecycleIsolation(t *testing.T, newStore StoreFactory) {
	ctx := context.Background()
	store, mgr := newPair(t, newStore, time.Now)
	if err := mgr.ProvisionTenant(ctx, "a"); err != nil {
		t.Fatalf("provision a: %v", err)
	}
	if err := mgr.ProvisionTenant(ctx, "b"); err != nil {
		t.Fatalf("provision b: %v", err)
	}
	bBefore, _ := mgr.ActiveSigningKey(ctx, "b")

	if err := mgr.DeleteTenant(ctx, "a"); err != nil {
		t.Fatalf("delete a: %v", err)
	}
	if existsA, _ := store.TenantExists(ctx, "a"); existsA {
		t.Fatal("tenant A must be fully purged")
	}
	if existsB, _ := store.TenantExists(ctx, "b"); !existsB {
		t.Fatal("tenant B must be untouched by deleting A")
	}
	bAfter, err := mgr.ActiveSigningKey(ctx, "b")
	if err != nil {
		t.Fatalf("B active after deleting A: %v", err)
	}
	if bAfter.KeyID != bBefore.KeyID || !bytes.Equal(bAfter.Secret, bBefore.Secret) {
		t.Fatal("deleting A must not change B's key material")
	}
}

// testTenantMismatchGuard verifies the store fails closed when a key's embedded tenant
// contradicts the operation's tenant.
func testTenantMismatchGuard(t *testing.T, newStore StoreFactory) {
	ctx := context.Background()
	store := newStore(time.Now)
	mismatched := keystore.SigningKey{KeyID: "k1", TenantID: "other", Secret: []byte("x")}
	err := store.PutSigningKey(ctx, "acme", mismatched)
	if err == nil {
		t.Fatal("PutSigningKey must reject a key whose TenantID contradicts the op tenant")
	}
}

// testAlgRoundTrip asserts a non-default Alg survives a store write/read cycle. It pokes the
// Store directly with a sealed dummy DER so it exercises persistence (column/scan wiring) on
// every backend, independent of how the Manager generates asymmetric keys.
func testAlgRoundTrip(t *testing.T, newStore StoreFactory) {
	ctx := context.Background()
	store, mgr := newPair(t, newStore, time.Now)
	sealed, err := mgr.SealSecret([]byte("dummy-pkcs8-der-bytes-stand-in-for-a-key"))
	if err != nil {
		t.Fatalf("SealSecret: %v", err)
	}
	key := keystore.SigningKey{
		KeyID:     "rsa-1",
		TenantID:  "acme",
		Secret:    sealed,
		CreatedAt: time.Now(),
		Alg:       "RS256",
	}
	if err := store.PutSigningKey(ctx, "acme", key); err != nil {
		t.Fatalf("PutSigningKey: %v", err)
	}
	active, err := store.ActiveSigningKey(ctx, "acme")
	if err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}
	if active.Alg != "RS256" {
		t.Fatalf("ActiveSigningKey Alg = %q, want RS256", active.Alg)
	}
	verify, err := store.VerificationKeys(ctx, "acme")
	if err != nil {
		t.Fatalf("VerificationKeys: %v", err)
	}
	got, ok := verify["rsa-1"]
	if !ok {
		t.Fatal("verify set missing rsa-1")
	}
	if got.Alg != "RS256" {
		t.Fatalf("VerificationKeys Alg = %q, want RS256", got.Alg)
	}
}

// testAsymmetricProvisionRoundTrip drives the full Manager provision path for an asymmetric alg,
// asserting the active key carries the chosen Alg and a parseable PKCS#8 private key.
func testAsymmetricProvisionRoundTrip(t *testing.T, newStore StoreFactory) {
	ctx := context.Background()
	_, mgr := newPair(t, newStore, time.Now)
	if err := mgr.ProvisionTenant(ctx, "acme", func(o *keystore.ProvisionOptions) {
		o.Alg = "RS256"
	}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	k, err := mgr.ActiveSigningKey(ctx, "acme")
	if err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}
	if k.Alg != "RS256" {
		t.Fatalf("Alg = %q, want RS256", k.Alg)
	}
	priv, err := x509.ParsePKCS8PrivateKey(k.Secret)
	if err != nil {
		t.Fatalf("opened secret must parse as PKCS#8: %v", err)
	}
	if _, ok := priv.(*rsa.PrivateKey); !ok {
		t.Fatalf("got %T, want *rsa.PrivateKey", priv)
	}
}
