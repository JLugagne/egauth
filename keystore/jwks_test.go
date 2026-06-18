package keystore_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/keystore"
)

func TestManagerJWKS_RSAPublishesParams(t *testing.T) {
	ctx := context.Background()
	mgr := newManager(t)
	if err := mgr.ProvisionTenant(ctx, "acme", func(o *keystore.ProvisionOptions) {
		o.Alg = "RS256"
	}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	active, _ := mgr.ActiveSigningKey(ctx, "acme")

	set, err := mgr.JWKS(ctx, "acme")
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(set.Keys))
	}
	jwk := set.Keys[0]
	if jwk.Kty != "RSA" {
		t.Fatalf("Kty = %q, want RSA", jwk.Kty)
	}
	if jwk.Kid != active.KeyID {
		t.Fatalf("Kid = %q, want %q", jwk.Kid, active.KeyID)
	}
	if jwk.N == "" || jwk.E == "" {
		t.Fatalf("RSA JWK missing N/E: %+v", jwk)
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, priv := range []string{"\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\""} {
		if strings.Contains(string(raw), priv) {
			t.Fatalf("JWKS leaks private field %s: %s", priv, raw)
		}
	}
}

func TestManagerJWKS_HMACMetadataOnly(t *testing.T) {
	ctx := context.Background()
	mgr := newManager(t)
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	set, err := mgr.JWKS(ctx, "acme")
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(set.Keys))
	}
	if set.Keys[0].Kty != "oct" {
		t.Fatalf("Kty = %q, want oct", set.Keys[0].Kty)
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "\"k\"") {
		t.Fatalf("HMAC JWKS must never emit the secret 'k': %s", raw)
	}
}

func TestManagerJWKS_MixedAfterAlgRenew(t *testing.T) {
	ctx := context.Background()
	mgr := newManager(t)
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	// Renew to RS256 with a long overlap so both keys remain verifiable.
	if err := mgr.RenewSigningKey(ctx, "acme", func(o *keystore.RenewOptions) {
		o.Alg = "RS256"
	}); err != nil {
		t.Fatalf("renew: %v", err)
	}
	set, err := mgr.JWKS(ctx, "acme")
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("want 2 keys during overlap, got %d", len(set.Keys))
	}
	var oct, rsa int
	for _, k := range set.Keys {
		switch k.Kty {
		case "oct":
			oct++
		case "RSA":
			rsa++
		}
	}
	if oct != 1 || rsa != 1 {
		t.Fatalf("want one oct + one RSA, got oct=%d rsa=%d", oct, rsa)
	}
}
