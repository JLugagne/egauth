package signing

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strconv"
)

const (
	hs256Info      = "egauth/jwt-hs256/v2"
	hs256KeyLength = 32
	minHS256Key    = 32
	minRSABits     = 2048
	minRSAExponent = 65537
	maxKeyIDLen    = 128
)

// EdDSA returns an Ed25519 signer. key is a 32-byte seed, or a PKCS#8 private key in DER or PEM.
// A trivially guessable seed or a credential published in egauth's examples or docs returns
// ErrInvalidKey. The key bytes are copied.
func EdDSA(kid string, key []byte) (Signer, error) {
	if err := checkKeyID(kid); err != nil {
		return Signer{}, err
	}
	var priv ed25519.PrivateKey
	if len(key) == ed25519.SeedSize {
		priv = ed25519.NewKeyFromSeed(key)
	} else {
		parsed, err := parsePKCS8(key)
		if err != nil {
			return Signer{}, err
		}
		p, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return Signer{}, errors.Join(ErrInvalidKey, errors.New("not an Ed25519 key"))
		}
		priv = p
	}
	if err := checkSecret(priv.Seed()); err != nil {
		return Signer{}, errors.Join(ErrInvalidKey, err)
	}
	pub := append(ed25519.PublicKey(nil), priv.Public().(ed25519.PublicKey)...)
	return Signer{k: &privateKey{
		ed:  priv,
		pub: Verifier{k: &publicKey{alg: AlgEdDSA, kid: kid, ed: pub}},
	}}, nil
}

// ES256 returns an ECDSA P-256 signer. key is a PKCS#8 or SEC 1 private key in DER or PEM, or a
// raw 32-byte scalar. Any other curve returns ErrInvalidKey. The key bytes are copied.
func ES256(kid string, key []byte) (Signer, error) {
	if err := checkKeyID(kid); err != nil {
		return Signer{}, err
	}
	priv, err := parseEC(key)
	if err != nil {
		return Signer{}, err
	}
	if priv.Curve != elliptic.P256() {
		return Signer{}, errors.Join(ErrInvalidKey, errors.New("ES256 requires a P-256 key"))
	}
	scalar, err := priv.Bytes()
	if err != nil {
		return Signer{}, errors.Join(ErrInvalidKey, err)
	}
	if err := checkSecret(scalar); err != nil {
		return Signer{}, errors.Join(ErrInvalidKey, err)
	}
	return Signer{k: &privateKey{
		ec:  priv,
		pub: Verifier{k: &publicKey{alg: AlgES256, kid: kid, ec: &priv.PublicKey}},
	}}, nil
}

func parseEC(key []byte) (*ecdsa.PrivateKey, error) {
	if len(key) == 32 {
		priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), key)
		if err != nil {
			return nil, errors.Join(ErrInvalidKey, err)
		}
		return priv, nil
	}
	der, err := decodePEM(key)
	if err != nil {
		return nil, err
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		priv, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.Join(ErrInvalidKey, errors.New("not an ECDSA key"))
		}
		return priv, nil
	}
	priv, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, errors.Join(ErrInvalidKey, err)
	}
	return priv, nil
}

// RS256 returns an RSA PKCS#1 v1.5 SHA-256 signer. key is a PKCS#8 or PKCS#1 private key in DER or
// PEM, of at least 2048 bits with a public exponent of at least 65537; anything weaker returns
// ErrInvalidKey. The key bytes are copied.
func RS256(kid string, key []byte) (Signer, error) {
	if err := checkKeyID(kid); err != nil {
		return Signer{}, err
	}
	der, err := decodePEM(key)
	if err != nil {
		return Signer{}, err
	}
	var priv *rsa.PrivateKey
	if parsed, perr := x509.ParsePKCS8PrivateKey(der); perr == nil {
		p, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return Signer{}, errors.Join(ErrInvalidKey, errors.New("not an RSA key"))
		}
		priv = p
	} else if priv, err = x509.ParsePKCS1PrivateKey(der); err != nil {
		return Signer{}, errors.Join(ErrInvalidKey, err)
	}
	if bits := priv.N.BitLen(); bits < minRSABits {
		return Signer{}, errors.Join(ErrInvalidKey, errors.New("RSA key has "+strconv.Itoa(bits)+" bits, at least 2048 required"))
	}
	if priv.E < minRSAExponent {
		return Signer{}, errors.Join(ErrInvalidKey, errors.New("RSA public exponent below 65537"))
	}
	if err := priv.Validate(); err != nil {
		return Signer{}, errors.Join(ErrInvalidKey, err)
	}
	return Signer{k: &privateKey{
		rsa: priv,
		pub: Verifier{k: &publicKey{alg: AlgRS256, kid: kid, rsa: &priv.PublicKey}},
	}}, nil
}

// HS256 returns an HMAC-SHA-256 signer whose MAC key is HKDF-SHA256(key, salt nil, info
// "egauth/jwt-hs256/v2"): a token MACed with key itself fails verification. key must be at least
// 32 bytes, not trivially guessable and not a credential published in egauth's examples or docs
// (exact copy or near-copy), otherwise ErrInvalidKey. Only the derived key is kept.
// HS256 keys are never published, so a deployment using them cannot serve resource servers.
func HS256(kid string, key []byte) (Signer, error) {
	if err := checkKeyID(kid); err != nil {
		return Signer{}, err
	}
	if len(key) < minHS256Key {
		return Signer{}, errors.Join(ErrInvalidKey, errors.New("HS256 key must be at least 32 bytes"))
	}
	if err := checkSecret(key); err != nil {
		return Signer{}, errors.Join(ErrInvalidKey, err)
	}
	mac, err := hkdf.Key(sha256.New, key, nil, hs256Info, hs256KeyLength)
	if err != nil {
		return Signer{}, errors.Join(ErrInvalidKey, err)
	}
	return Signer{k: &privateKey{
		mac: mac,
		pub: Verifier{k: &publicKey{alg: AlgHS256, kid: kid, mac: mac}},
	}}, nil
}

func checkKeyID(kid string) error {
	if kid == "" || len(kid) > maxKeyIDLen {
		return ErrInvalidKeyID
	}
	for i := 0; i < len(kid); i++ {
		c := kid[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == ':'
		if !ok {
			return ErrInvalidKeyID
		}
	}
	return nil
}

func decodePEM(key []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(key)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		return key, nil
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.Join(ErrInvalidKey, errors.New("expected exactly one PEM block"))
	}
	if len(block.Headers) != 0 {
		return nil, errors.Join(ErrInvalidKey, errors.New("encrypted PEM is not supported"))
	}
	return block.Bytes, nil
}

func parsePKCS8(key []byte) (any, error) {
	der, err := decodePEM(key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.Join(ErrInvalidKey, err)
	}
	return parsed, nil
}
