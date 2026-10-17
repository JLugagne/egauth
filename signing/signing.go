// Package signing holds the keys egauth signs and verifies access tokens with. A Signer is opaque:
// it has no exported Sign, its key bytes are copied at construction and never returned, and HS256
// keys are stretched through HKDF so a raw environment key pasted into a JWT library mints tokens
// that egauth refuses. Every key is bound to exactly one algorithm and key id.
//
// # Stability
//
// Stability class: frozen-v1 candidate. The exported API is intended to remain
// backward-compatible for the life of v1; breaking changes require a new major version. Until v1
// is tagged the API remains pre-1.0. See docs/adr/0001-v1-scope-and-stability-classes.md.
package signing

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"log/slog"
)

// Algorithm names, as written in a JWS "alg" header.
const (
	AlgEdDSA = "EdDSA"
	AlgES256 = "ES256"
	AlgRS256 = "RS256"
	AlgHS256 = "HS256"
)

var (
	// ErrInvalidKeyID is returned for an empty or malformed key id.
	ErrInvalidKeyID = errors.New("signing: invalid key id")
	// ErrInvalidKey is returned for key material that cannot be parsed, is of another algorithm,
	// is too short or too small, or is trivially guessable.
	ErrInvalidKey = errors.New("signing: invalid key")
	// ErrZeroKey is returned when a zero Signer or Verifier is used.
	ErrZeroKey = errors.New("signing: zero key")
	// ErrNotOwner is returned by NewMinter for an owner outside egauth's internal/session/jwt and by
	// a Minter not built by NewMinter.
	ErrNotOwner = errors.New("signing: only egauth itself may sign")
	// ErrInvalidSignature is returned by Verify for an algorithm or key id other than the key's, or
	// a signature that does not verify.
	ErrInvalidSignature = errors.New("signing: invalid signature")
	// ErrNotPublishable is returned for a symmetric (HS256) key, which never appears in a JWKS.
	ErrNotPublishable = errors.New("signing: symmetric keys are never published")
	// ErrDuplicateKeyID is returned when two keys of one set share a key id.
	ErrDuplicateKeyID = errors.New("signing: duplicate key id")
	// ErrInvalidJWKS is returned by ParseJWKS for a document that is not a JWKS of public signing
	// keys with one algorithm per key id.
	ErrInvalidJWKS = errors.New("signing: invalid JWKS")
	// ErrInvalidURL is returned by JWKS for a URL that is not absolute https (http only on
	// loopback), or that carries credentials or a fragment.
	ErrInvalidURL = errors.New("signing: invalid JWKS URL")
)

// Signer is a private signing key bound to one algorithm and key id. It is built by EdDSA, ES256,
// RS256 or HS256; the zero Signer is invalid. It is immutable and safe for concurrent use.
type Signer struct {
	k *privateKey
}

type privateKey struct {
	ed  ed25519.PrivateKey
	ec  *ecdsa.PrivateKey
	rsa *rsa.PrivateKey
	mac []byte
	pub Verifier
}

// IsZero reports whether s was not built by a constructor.
func (s Signer) IsZero() bool { return s.k == nil }

// KeyID returns the key id, written as the JWS "kid" header.
func (s Signer) KeyID() string {
	if s.k == nil {
		return ""
	}
	return s.k.pub.k.kid
}

// Algorithm returns the JWS "alg" of the key.
func (s Signer) Algorithm() string {
	if s.k == nil {
		return ""
	}
	return s.k.pub.k.alg
}

// Verifier returns the verifying half of s: the public key, or the derived MAC key for HS256. It
// is how a retired signing key stays verify-only during rotation.
func (s Signer) Verifier() Verifier {
	if s.k == nil {
		return Verifier{}
	}
	return s.k.pub
}

// String renders the algorithm and key id only.
func (s Signer) String() string { return "signing.Signer{" + s.Algorithm() + " " + s.KeyID() + "}" }

// GoString renders like String.
func (s Signer) GoString() string { return s.String() }

// LogValue renders the algorithm and key id only.
func (s Signer) LogValue() slog.Value {
	return slog.GroupValue(slog.String("alg", s.Algorithm()), slog.String("kid", s.KeyID()))
}

// Verifier verifies signatures of one algorithm and key id. It comes from Signer.Verifier or
// ParseJWKS; the zero Verifier is invalid. It is immutable and safe for concurrent use.
type Verifier struct {
	k *publicKey
}

type publicKey struct {
	alg string
	kid string
	ed  ed25519.PublicKey
	ec  *ecdsa.PublicKey
	rsa *rsa.PublicKey
	mac []byte
}

// IsZero reports whether v was not built by this package.
func (v Verifier) IsZero() bool { return v.k == nil }

func (v Verifier) KeyID() string {
	if v.k == nil {
		return ""
	}
	return v.k.kid
}

// Algorithm returns the only JWS "alg" the key verifies.
func (v Verifier) Algorithm() string {
	if v.k == nil {
		return ""
	}
	return v.k.alg
}

// Symmetric reports whether the key is an HS256 MAC key, which is secret and never published.
func (v Verifier) Symmetric() bool { return v.k != nil && v.k.mac != nil }

// String renders the algorithm and key id only.
func (v Verifier) String() string {
	return "signing.Verifier{" + v.Algorithm() + " " + v.KeyID() + "}"
}

// GoString renders like String.
func (v Verifier) GoString() string { return v.String() }

// LogValue renders the algorithm and key id only.
func (v Verifier) LogValue() slog.Value {
	return slog.GroupValue(slog.String("alg", v.Algorithm()), slog.String("kid", v.KeyID()))
}

// CheckKeyIDs returns ErrDuplicateKeyID when two of vs share a key id, so that every key id maps
// to exactly one key and algorithm, and ErrZeroKey for a zero Verifier.
func CheckKeyIDs(vs ...Verifier) error {
	seen := make(map[string]bool, len(vs))
	for _, v := range vs {
		if v.IsZero() {
			return ErrZeroKey
		}
		if seen[v.k.kid] {
			return errors.Join(ErrDuplicateKeyID, errors.New("kid "+v.k.kid))
		}
		seen[v.k.kid] = true
	}
	return nil
}
