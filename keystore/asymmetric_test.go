package keystore_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/keystore/memory"
)

func newManager(t *testing.T) *keystore.Manager {
	t.Helper()
	mgr, err := keystore.NewManager(memory.New(), newKEK(t))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

// parsePKCS8 opens the key's (already-decrypted) Secret as a PKCS#8 private key.
func parsePKCS8(t *testing.T, der []byte) any {
	t.Helper()
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	return key
}

func TestManager_ProvisionRS256(t *testing.T) {
	ctx := context.Background()
	mgr := newManager(t)
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
	priv := parsePKCS8(t, k.Secret)
	rk, ok := priv.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("secret is %T, want *rsa.PrivateKey", priv)
	}
	if rk.N.BitLen() < 2048 {
		t.Fatalf("RSA key is %d bits, want >= 2048", rk.N.BitLen())
	}
}

func TestManager_ProvisionES256_EdDSA(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		alg    string
		verify func(t *testing.T, priv any)
	}{
		{"ES256", func(t *testing.T, priv any) {
			if _, ok := priv.(*ecdsa.PrivateKey); !ok {
				t.Fatalf("got %T, want *ecdsa.PrivateKey", priv)
			}
		}},
		{"EdDSA", func(t *testing.T, priv any) {
			if _, ok := priv.(ed25519.PrivateKey); !ok {
				t.Fatalf("got %T, want ed25519.PrivateKey", priv)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			mgr := newManager(t)
			if err := mgr.ProvisionTenant(ctx, "t", func(o *keystore.ProvisionOptions) {
				o.Alg = tc.alg
			}); err != nil {
				t.Fatalf("provision: %v", err)
			}
			k, err := mgr.ActiveSigningKey(ctx, "t")
			if err != nil {
				t.Fatalf("ActiveSigningKey: %v", err)
			}
			if k.Alg != tc.alg {
				t.Fatalf("Alg = %q, want %q", k.Alg, tc.alg)
			}
			tc.verify(t, parsePKCS8(t, k.Secret))
		})
	}
}

func TestManager_DefaultAlgIsHS256(t *testing.T) {
	ctx := context.Background()
	mgr := newManager(t)
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	k, err := mgr.ActiveSigningKey(ctx, "acme")
	if err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}
	if k.Alg != "" && k.Alg != keystore.AlgHS256 {
		t.Fatalf("default Alg = %q, want empty or HS256", k.Alg)
	}
	if len(k.Secret) != 32 {
		t.Fatalf("HS256 secret is %d bytes, want 32", len(k.Secret))
	}
}

func TestManager_RenewPreservesAlgChoice(t *testing.T) {
	ctx := context.Background()
	mgr := newManager(t)
	if err := mgr.ProvisionTenant(ctx, "acme", func(o *keystore.ProvisionOptions) {
		o.Alg = "RS256"
	}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := mgr.RenewSigningKey(ctx, "acme", func(o *keystore.RenewOptions) {
		o.Alg = "RS256"
	}); err != nil {
		t.Fatalf("renew: %v", err)
	}
	k, err := mgr.ActiveSigningKey(ctx, "acme")
	if err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}
	if k.Alg != "RS256" {
		t.Fatalf("after renew Alg = %q, want RS256", k.Alg)
	}
	if _, ok := parsePKCS8(t, k.Secret).(*rsa.PrivateKey); !ok {
		t.Fatal("renewed key must still parse as RSA")
	}
}

func TestManager_UnsupportedAlgErrors(t *testing.T) {
	ctx := context.Background()
	mgr := newManager(t)
	err := mgr.ProvisionTenant(ctx, "acme", func(o *keystore.ProvisionOptions) {
		o.Alg = "HS512"
	})
	if err == nil {
		t.Fatal("provision with unsupported alg must error")
	}
}
