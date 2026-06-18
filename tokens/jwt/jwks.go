package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

// JWK is one RFC 7517 JSON Web Key. The field set is the union across key types; empty fields are
// omitted. For HMAC keys only the non-secret metadata is emitted — the symmetric "k" value is
// intentionally never published.
type JWK struct {
	Kty string `json:"kty"`           // "RSA" | "EC" | "OKP" | "oct"
	Use string `json:"use,omitempty"` // "sig"
	Alg string `json:"alg,omitempty"` // RS256/ES256/.../EdDSA/HS256
	Kid string `json:"kid,omitempty"`
	// RSA
	N string `json:"n,omitempty"` // base64url(modulus, big-endian)
	E string `json:"e,omitempty"` // base64url(public exponent, big-endian minimal)
	// EC / OKP
	Crv string `json:"crv,omitempty"` // "P-256" | "P-384" | "P-521" (EC) or "Ed25519" (OKP)
	X   string `json:"x,omitempty"`   // base64url(coord, fixed length); OKP: 32-byte public key
	Y   string `json:"y,omitempty"`   // EC only
}

// JWKSet is an RFC 7517 JWK Set: the public verification keys this Service will accept.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// PublicJWKS returns the static-path verification keys as an RFC 7517 JWK Set suitable for
// publishing at a /.well-known/jwks.json endpoint. Asymmetric keys (RSA/EC/OKP) publish their full
// public parameters; HMAC keys publish metadata only (kty/use/alg/kid) and NEVER the symmetric
// secret. The kid-less legacy signer, if any, is included only when it carries a non-empty kid
// (an empty-kid key cannot be selected by a JWKS consumer).
func (s *Service[C]) PublicJWKS() JWKSet {
	set := JWKSet{}
	for kid, signer := range s.verifySigners {
		set.Keys = append(set.Keys, jwkFromSigner(kid, signer))
	}
	if s.legacy != nil && s.legacy.KeyID() != "" {
		// Only include the legacy signer if it is not already part of the verify set.
		if _, ok := s.verifySigners[s.legacy.KeyID()]; !ok {
			set.Keys = append(set.Keys, jwkFromSigner(s.legacy.KeyID(), s.legacy))
		}
	}
	return set
}

// jwkFromSigner builds the public JWK for one signer, switching on its verification key type.
func jwkFromSigner(kid string, signer Signer) JWK {
	alg := signer.Method().Alg()
	switch pub := signer.VerifyKey().(type) {
	case *rsa.PublicKey:
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		return JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: alg,
			Kid: kid,
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(eBytes),
		}
	case *ecdsa.PublicKey:
		// pub.Bytes() is the SEC 1 uncompressed point (0x04 || X || Y) with each coordinate
		// fixed-length to the curve byte size — exactly the fixed-width X/Y a JWK needs, and the
		// non-deprecated replacement for reading pub.X / pub.Y directly. It cannot fail here:
		// NewECDSASigner only ever holds a P-256/384/521 key.
		raw, _ := pub.Bytes()
		byteLen := (pub.Curve.Params().BitSize + 7) / 8
		return JWK{
			Kty: "EC",
			Use: "sig",
			Alg: alg,
			Kid: kid,
			Crv: crvName(pub.Curve),
			X:   base64.RawURLEncoding.EncodeToString(raw[1 : 1+byteLen]),
			Y:   base64.RawURLEncoding.EncodeToString(raw[1+byteLen:]),
		}
	case ed25519.PublicKey:
		return JWK{
			Kty: "OKP",
			Use: "sig",
			Alg: alg,
			Kid: kid,
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pub),
		}
	default:
		// HMAC ([]byte) and any unknown key: emit metadata only, never the secret.
		return JWK{Kty: "oct", Use: "sig", Alg: alg, Kid: kid}
	}
}

// crvName maps an elliptic curve to its RFC 7518 "crv" name.
func crvName(c elliptic.Curve) string {
	switch c {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return curveName(c)
	}
}
