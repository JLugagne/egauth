package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestNewHMACSigner_RejectsShortSecret(t *testing.T) {
	if _, err := NewHMACSigner("k", make([]byte, MinSecretKeyLength-1)); err == nil {
		t.Fatal("expected error for a short HMAC secret")
	}
	s, err := NewHMACSigner("k", make([]byte, MinSecretKeyLength))
	if err != nil {
		t.Fatalf("unexpected error for a 32-byte secret: %v", err)
	}
	if s.KeyID() != "k" {
		t.Fatalf("KeyID = %q, want %q", s.KeyID(), "k")
	}
	if s.Method().Alg() != "HS256" {
		t.Fatalf("Alg = %q, want HS256", s.Method().Alg())
	}
}

func TestNewHMACSigner_AllowsEmptyKeyID(t *testing.T) {
	s, err := NewHMACSigner("", make([]byte, MinSecretKeyLength))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.KeyID() != "" {
		t.Fatalf("KeyID = %q, want empty", s.KeyID())
	}
}

func TestNewRSASigner_RejectsUnder2048(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate weak rsa: %v", err)
	}
	if _, err := NewRSASigner("k", weak); err == nil {
		t.Fatal("expected error for a 1024-bit RSA key")
	}
	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	s, err := NewRSASigner("k", strong)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Method().Alg() != "RS256" {
		t.Fatalf("Alg = %q, want RS256", s.Method().Alg())
	}
	if _, err := NewRSASigner("", strong); err == nil {
		t.Fatal("expected error for empty key id")
	}
	if _, err := NewRSASigner("k", nil); err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestNewECDSASigner_CurveSelectsAlg(t *testing.T) {
	cases := []struct {
		curve elliptic.Curve
		alg   string
	}{
		{elliptic.P256(), "ES256"},
		{elliptic.P384(), "ES384"},
		{elliptic.P521(), "ES512"},
	}
	for _, tc := range cases {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatalf("generate ecdsa: %v", err)
		}
		s, err := NewECDSASigner("k", key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s.Method().Alg() != tc.alg {
			t.Fatalf("Alg = %q, want %q", s.Method().Alg(), tc.alg)
		}
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := NewECDSASigner("", key); err == nil {
		t.Fatal("expected error for empty key id")
	}
	if _, err := NewECDSASigner("k", nil); err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestNewEdDSASigner(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	s, err := NewEdDSASigner("k", priv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Method().Alg() != "EdDSA" {
		t.Fatalf("Alg = %q, want EdDSA", s.Method().Alg())
	}
	if _, err := NewEdDSASigner("k", make(ed25519.PrivateKey, 10)); err == nil {
		t.Fatal("expected error for wrong-size key")
	}
	if _, err := NewEdDSASigner("", priv); err == nil {
		t.Fatal("expected error for empty key id")
	}
}
