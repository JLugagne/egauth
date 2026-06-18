package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Signer abstracts a JWT signing scheme (HMAC or asymmetric).
type Signer interface {
	// KeyID is the "kid" header stamped on tokens signed by this signer and used to select it on
	// the verify path. It may be empty only for the legacy kid-less HMAC signer.
	KeyID() string
	// Method pins the JWT signing algorithm; the verify path rejects any token whose alg differs.
	Method() jwt.SigningMethod
	// SignKey returns the key material for signing: []byte for HMAC; a crypto private key
	// (*rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey) for asymmetric schemes.
	SignKey() any
	// VerifyKey returns the key material for verification: []byte for HMAC; a crypto.PublicKey for
	// asymmetric schemes.
	VerifyKey() any
}

// ErrEmptyKeyID is returned by the asymmetric signer constructors when given an empty key id.
var ErrEmptyKeyID = errors.New("jwt: asymmetric signer requires a non-empty key id")

// hmacSigner is the HS256 implementation of Signer.
type hmacSigner struct {
	keyID  string
	secret []byte
}

func (s *hmacSigner) KeyID() string             { return s.keyID }
func (s *hmacSigner) Method() jwt.SigningMethod { return jwt.SigningMethodHS256 }
func (s *hmacSigner) SignKey() any              { return s.secret }
func (s *hmacSigner) VerifyKey() any            { return s.secret }

// rsaSigner is the RS256 implementation of Signer.
type rsaSigner struct {
	keyID string
	key   *rsa.PrivateKey
}

func (s *rsaSigner) KeyID() string             { return s.keyID }
func (s *rsaSigner) Method() jwt.SigningMethod { return jwt.SigningMethodRS256 }
func (s *rsaSigner) SignKey() any              { return s.key }
func (s *rsaSigner) VerifyKey() any            { return &s.key.PublicKey }

// ecdsaSigner is the ES256/ES384/ES512 implementation of Signer; the method is fixed by the curve
// at construction time.
type ecdsaSigner struct {
	keyID  string
	key    *ecdsa.PrivateKey
	method jwt.SigningMethod
}

func (s *ecdsaSigner) KeyID() string             { return s.keyID }
func (s *ecdsaSigner) Method() jwt.SigningMethod { return s.method }
func (s *ecdsaSigner) SignKey() any              { return s.key }
func (s *ecdsaSigner) VerifyKey() any            { return &s.key.PublicKey }

// eddsaSigner is the EdDSA (Ed25519) implementation of Signer.
type eddsaSigner struct {
	keyID string
	key   ed25519.PrivateKey
}

func (s *eddsaSigner) KeyID() string             { return s.keyID }
func (s *eddsaSigner) Method() jwt.SigningMethod { return jwt.SigningMethodEdDSA }
func (s *eddsaSigner) SignKey() any              { return s.key }
func (s *eddsaSigner) VerifyKey() any            { return s.key.Public() }

// NewHMACSigner builds an HS256 signer. The secret must be at least MinSecretKeyLength bytes; the
// key id may be empty (the legacy kid-less mode). The weak-key bypass lives at the Config level,
// not here.
func NewHMACSigner(keyID string, secret []byte) (Signer, error) {
	return newHMACSignerAllowWeak(keyID, secret, false)
}

// newHMACSignerAllowWeak builds an HS256 signer, optionally permitting a sub-minimum secret. It is
// the unexported seam used by resolveKeyset to honor Config.InsecureAllowWeakKey; NewHMACSigner
// always passes allowWeak=false.
func newHMACSignerAllowWeak(keyID string, secret []byte, allowWeak bool) (Signer, error) {
	if !allowWeak && len(secret) < MinSecretKeyLength {
		return nil, fmt.Errorf(
			"secret is only %d bytes; HS256 requires at least %d bytes to resist brute-force attacks (set InsecureAllowWeakKey in tests only)",
			len(secret), MinSecretKeyLength,
		)
	}
	return &hmacSigner{keyID: keyID, secret: secret}, nil
}

// NewRSASigner builds an RS256 signer. The key must be non-nil, at least 2048 bits, and carry a
// non-empty key id (asymmetric schemes have no legacy kid-less mode).
func NewRSASigner(keyID string, key *rsa.PrivateKey) (Signer, error) {
	if key == nil {
		return nil, errors.New("jwt: RSA signer requires a non-nil key")
	}
	if keyID == "" {
		return nil, ErrEmptyKeyID
	}
	if key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("jwt: RSA key is only %d bits; at least 2048 are required", key.N.BitLen())
	}
	return &rsaSigner{keyID: keyID, key: key}, nil
}

// NewECDSASigner builds an ECDSA signer, selecting ES256/ES384/ES512 from the key's curve
// (P-256/P-384/P-521). The key must be non-nil, on a supported curve, and carry a non-empty key id.
func NewECDSASigner(keyID string, key *ecdsa.PrivateKey) (Signer, error) {
	if key == nil {
		return nil, errors.New("jwt: ECDSA signer requires a non-nil key")
	}
	if keyID == "" {
		return nil, ErrEmptyKeyID
	}
	var method jwt.SigningMethod
	switch key.Curve {
	case elliptic.P256():
		method = jwt.SigningMethodES256
	case elliptic.P384():
		method = jwt.SigningMethodES384
	case elliptic.P521():
		method = jwt.SigningMethodES512
	default:
		return nil, fmt.Errorf("jwt: unsupported ECDSA curve %q", curveName(key.Curve))
	}
	return &ecdsaSigner{keyID: keyID, key: key, method: method}, nil
}

// curveName returns the curve's name for error messages, tolerating a nil Params.
func curveName(c elliptic.Curve) string {
	if c == nil || c.Params() == nil {
		return "<nil>"
	}
	return c.Params().Name
}

// NewEdDSASigner builds an EdDSA (Ed25519) signer. The key must be a well-formed Ed25519 private
// key and carry a non-empty key id.
func NewEdDSASigner(keyID string, key ed25519.PrivateKey) (Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("jwt: Ed25519 key is %d bytes; %d are required", len(key), ed25519.PrivateKeySize)
	}
	if keyID == "" {
		return nil, ErrEmptyKeyID
	}
	return &eddsaSigner{keyID: keyID, key: key}, nil
}
