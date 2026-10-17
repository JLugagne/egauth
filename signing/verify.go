package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
)

// Signed is a JWS to verify: the "alg" and "kid" of its header, its signing input
// (base64url(header) "." base64url(payload)) and its decoded signature.
type Signed struct {
	Algorithm string
	KeyID     string
	Input     string
	Signature []byte
}

// Verify checks s against v. An "alg" or "kid" other than the key's returns ErrInvalidSignature
// before any cryptography, so a key is never used with another algorithm. An Ed25519 key also
// accepts the RFC 9864 "Ed25519" alg.
func (v Verifier) Verify(s Signed) error {
	if v.k == nil {
		return ErrZeroKey
	}
	k := v.k
	if s.Algorithm != k.alg && (k.ed == nil || s.Algorithm != algEd25519) {
		return errors.Join(ErrInvalidSignature, errors.New("algorithm "+s.Algorithm+" is not the key's "+k.alg))
	}
	if s.KeyID != k.kid {
		return errors.Join(ErrInvalidSignature, errors.New("key id mismatch"))
	}
	if verifies(k, []byte(s.Input), s.Signature) {
		return nil
	}
	return ErrInvalidSignature
}

func verifies(k *publicKey, input, sig []byte) bool {
	switch {
	case k.ed != nil:
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(k.ed, input, sig)
	case k.ec != nil:
		if len(sig) != 64 {
			return false
		}
		digest := sha256.Sum256(input)
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(k.ec, digest[:], r, s)
	case k.rsa != nil:
		digest := sha256.Sum256(input)
		return rsa.VerifyPKCS1v15(k.rsa, crypto.SHA256, digest[:], sig) == nil
	case k.mac != nil:
		h := hmac.New(sha256.New, k.mac)
		h.Write(input)
		return hmac.Equal(h.Sum(nil), sig)
	}
	return false
}
