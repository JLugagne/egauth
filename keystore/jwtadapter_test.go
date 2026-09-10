package keystore_test

import (
	"context"
	"crypto/rsa"
	"testing"

	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/keystore/memory"
)

func TestJWTKeyStore_ProjectsRSASigner(t *testing.T) {
	ctx := context.Background()
	mgr := newManager(t)
	if err := mgr.ProvisionTenant(ctx, "acme", func(o *keystore.ProvisionOptions) {
		o.Alg = "RS256"
	}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	ks := keystore.NewJWTKeyStore(mgr)
	signer, err := ks.ActiveSigningKey(ctx, "acme")
	if err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}
	if signer.Method().Alg() != "RS256" {
		t.Fatalf("alg = %q, want RS256", signer.Method().Alg())
	}
	if _, ok := signer.VerifyKey().(*rsa.PublicKey); !ok {
		t.Fatalf("VerifyKey is %T, want *rsa.PublicKey", signer.VerifyKey())
	}
}

func TestJWTKeyStore_ProjectsHMACSigner(t *testing.T) {
	ctx := context.Background()
	mgr := newManager(t)
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	ks := keystore.NewJWTKeyStore(mgr)
	signer, err := ks.ActiveSigningKey(ctx, "acme")
	if err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}
	if signer.Method().Alg() != "HS256" {
		t.Fatalf("alg = %q, want HS256", signer.Method().Alg())
	}
	secret, ok := signer.VerifyKey().([]byte)
	if !ok {
		t.Fatalf("VerifyKey is %T, want []byte", signer.VerifyKey())
	}
	if len(secret) != 32 {
		t.Fatalf("HMAC secret is %d bytes, want 32", len(secret))
	}
}

// TestJWTKeyStore_RejectsAllZeroHMACSecret pins the adapter's fail-closed behavior: a stored key
// whose KEK-opened secret is all-zero must not be projected into a Signer, even though it is
// exactly MinSecretKeyLength bytes.
func TestJWTKeyStore_RejectsAllZeroHMACSecret(t *testing.T) {
	ctx := context.Background()
	kek := newKEK(t)
	sealed, err := kek.Seal(make([]byte, 32), []byte("acme"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	store := memory.New()
	if err := store.CreateTenant(ctx, "acme", keystore.SigningKey{
		KeyID:    "k-zero",
		TenantID: "acme",
		Alg:      keystore.AlgHS256,
		Secret:   sealed,
	}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	mgr, err := keystore.NewManager(store, kek)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ks := keystore.NewJWTKeyStore(mgr)
	if signer, err := ks.ActiveSigningKey(ctx, "acme"); err == nil {
		t.Fatalf("ActiveSigningKey accepted an all-zero HMAC secret: %v", signer)
	}
}

func TestJWTKeyStore_VerificationKeysAllSigners(t *testing.T) {
	ctx := context.Background()
	mgr := newManager(t)
	if err := mgr.ProvisionTenant(ctx, "acme", func(o *keystore.ProvisionOptions) {
		o.Alg = "RS256"
	}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	active, _ := mgr.ActiveSigningKey(ctx, "acme")
	preID := active.KeyID
	if err := mgr.RenewSigningKey(ctx, "acme", func(o *keystore.RenewOptions) {
		o.Alg = "RS256"
	}); err != nil {
		t.Fatalf("renew: %v", err)
	}
	newActive, _ := mgr.ActiveSigningKey(ctx, "acme")

	ks := keystore.NewJWTKeyStore(mgr)
	keys, err := ks.VerificationKeys(ctx, "acme")
	if err != nil {
		t.Fatalf("VerificationKeys: %v", err)
	}
	for _, id := range []string{preID, newActive.KeyID} {
		s, ok := keys[id]
		if !ok {
			t.Fatalf("verify set missing kid %q", id)
		}
		if s.Method().Alg() != "RS256" {
			t.Fatalf("kid %q alg = %q, want RS256", id, s.Method().Alg())
		}
		if _, ok := s.VerifyKey().(*rsa.PublicKey); !ok {
			t.Fatalf("kid %q VerifyKey is %T, want *rsa.PublicKey", id, s.VerifyKey())
		}
	}
}
