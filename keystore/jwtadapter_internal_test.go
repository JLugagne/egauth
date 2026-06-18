package keystore

// White-box tests for signerFor's anti-corruption guards. signerFor operates on an
// already-KEK-opened SigningKey.Secret, so these craft the plaintext key material directly. They
// guard against a corrupt or hand-written keystore_keys row (a DER that does not parse, key
// material whose type contradicts the stored Alg, or an ECDSA curve that contradicts the stored
// Alg) being silently projected into a Signer instead of failing closed.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func mustMarshalPKCS8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	return der
}

func TestSignerFor_RejectsCorruptKeyMaterial(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	ecP384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}

	cases := []struct {
		name string
		key  SigningKey
	}{
		{
			// DER that does not parse as a PKCS#8 private key.
			name: "unparseable DER",
			key:  SigningKey{KeyID: "k", Alg: "RS256", Secret: []byte("this is not valid PKCS#8 DER")},
		},
		{
			// Real RSA key persisted under an ECDSA alg: the parsed type contradicts Alg.
			name: "key type contradicts alg",
			key:  SigningKey{KeyID: "k", Alg: "ES256", Secret: mustMarshalPKCS8(t, rsaKey)},
		},
		{
			// Real P-384 key persisted under ES256: the curve-derived alg (ES384) contradicts Alg.
			name: "ecdsa curve contradicts alg",
			key:  SigningKey{KeyID: "k", Alg: "ES256", Secret: mustMarshalPKCS8(t, ecP384)},
		},
		{
			// An algorithm signerFor does not support.
			name: "unsupported alg",
			key:  SigningKey{KeyID: "k", Alg: "HS512", Secret: []byte("0123456789abcdef0123456789abcdef")},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := signerFor(tc.key)
			if err == nil {
				t.Fatalf("signerFor(%s) = %v, nil; want an error", tc.name, signer)
			}
		})
	}
}
