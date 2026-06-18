package keystore

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
)

// JWK is a single entry in a tenant's JSON Web Key Set (RFC 7517).
//
// For asymmetric keys (RS256/ES256/ES384/ES512/EdDSA) a JWK carries the full PUBLIC key parameters
// and is safe to publish at a public /.well-known/jwks.json: a verifier learns only how to verify,
// never how to mint. For HS256 (a SYMMETRIC algorithm) a JWK is deliberately metadata-only: it
// carries kid/alg/use but NEVER the secret ("k"), because publishing the symmetric secret would
// hand every verifier the power to forge tokens — a critical vulnerability. So an HS256 JWKS is for
// internal introspection only; a mixed set publishes the asymmetric public keys and exposes the
// HMAC keys as metadata-only entries.
type JWK struct {
	// Kty is the key type: "RSA" | "EC" | "OKP" | "oct".
	Kty string `json:"kty"`
	// Use is the intended use: "sig" (signature).
	Use string `json:"use,omitempty"`
	// Alg is the algorithm (RS256/ES256/ES384/ES512/EdDSA/HS256).
	Alg string `json:"alg,omitempty"`
	// Kid is the key id (the JWT "kid" header value).
	Kid string `json:"kid,omitempty"`
	// N is the RSA modulus (base64url, big-endian).
	N string `json:"n,omitempty"`
	// E is the RSA public exponent (base64url, big-endian minimal).
	E string `json:"e,omitempty"`
	// Crv is the curve: "P-256" | "P-384" | "P-521" (EC) or "Ed25519" (OKP).
	Crv string `json:"crv,omitempty"`
	// X is the EC x coordinate (fixed length) or the OKP public key (base64url).
	X string `json:"x,omitempty"`
	// Y is the EC y coordinate (base64url, EC only).
	Y string `json:"y,omitempty"`
	// Note: the HMAC secret ("k") is intentionally NEVER emitted — see the type doc.
}

// JWKSet is a tenant's JSON Web Key Set.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKS returns the JWK set for a tenant: one entry per currently-verifiable key (active plus
// retired-but-unexpired). Asymmetric keys publish their full public parameters (safe to expose
// publicly); HMAC keys are metadata-only (kid/alg/use but never the secret). tenantID "" is the
// single-tenant partition.
func (m *Manager) JWKS(ctx context.Context, tenantID string) (JWKSet, error) {
	// Route through VerificationKeys (which opens the sealed secrets) so asymmetric keys can be
	// parsed to extract their public parameters.
	keys, err := m.VerificationKeys(ctx, tenantID)
	if err != nil {
		return JWKSet{}, err
	}
	set := JWKSet{Keys: make([]JWK, 0, len(keys))}
	for kid, k := range keys {
		alg := k.Alg
		if alg == "" {
			alg = AlgHS256
		}
		if alg == AlgHS256 {
			// Symmetric: metadata only, never the secret.
			set.Keys = append(set.Keys, JWK{Kty: "oct", Use: "sig", Alg: "HS256", Kid: kid})
			continue
		}
		jwk, err := publicJWKFromKey(kid, alg, k.Secret)
		if err != nil {
			return JWKSet{}, err
		}
		set.Keys = append(set.Keys, jwk)
	}
	return set, nil
}

// publicJWKFromKey parses the PKCS#8 DER of an asymmetric private key (already KEK-opened) and
// builds the public JWK with the full public parameters for the key's algorithm.
func publicJWKFromKey(kid, alg string, der []byte) (JWK, error) {
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return JWK{}, fmt.Errorf("keystore: parsing key %q for JWKS: %w", kid, err)
	}
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		pub := &key.PublicKey
		return JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: alg,
			Kid: kid,
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}, nil
	case *ecdsa.PrivateKey:
		pub := &key.PublicKey
		byteLen := (pub.Curve.Params().BitSize + 7) / 8
		return JWK{
			Kty: "EC",
			Use: "sig",
			Alg: alg,
			Kid: kid,
			Crv: pub.Curve.Params().Name,
			X:   base64.RawURLEncoding.EncodeToString(leftPad(pub.X.Bytes(), byteLen)),
			Y:   base64.RawURLEncoding.EncodeToString(leftPad(pub.Y.Bytes(), byteLen)),
		}, nil
	case ed25519.PrivateKey:
		pub := key.Public().(ed25519.PublicKey)
		return JWK{
			Kty: "OKP",
			Use: "sig",
			Alg: alg,
			Kid: kid,
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pub),
		}, nil
	default:
		return JWK{}, fmt.Errorf("keystore: unsupported public key type %T for key %q", priv, kid)
	}
}

// leftPad left-pads b with zero bytes to length n (no-op when len(b) >= n).
func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}
