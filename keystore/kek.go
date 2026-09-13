package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// KEK is a deployment Key-Encryption-Key used to envelope-encrypt tenant signing secrets at
// rest. Every secret a Store persists is sealed with the KEK (AES-256-GCM) so a database dump
// alone never yields usable signing material — the attacker also needs the KEK, which lives in
// the deployment's secret manager, not the database.
//
// The KEK is REQUIRED and fail-fast validated: NewKEK rejects any key that is not exactly 32
// bytes (AES-256), and NewManager rejects a nil KEK. There is no "no encryption" mode.
type KEK struct {
	aead cipher.AEAD
}

// KEKKeyLength is the required KEK length in bytes (AES-256).
const KEKKeyLength = 32

// ErrInvalidKEK is returned by NewKEK when the supplied key is not exactly KEKKeyLength bytes.
var ErrInvalidKEK = errors.New("keystore: KEK must be exactly 32 bytes (AES-256)")

// ErrTrivialKEK is returned by NewKEK when the supplied key is trivially known: every byte zero, or
// the same byte repeated. The KEK is the one secret that makes envelope encryption meaningful — its
// entire purpose is to be unknown to whoever holds the sealed blobs — so a constant key silently
// reduces the at-rest protection to nothing while everything still appears to work.
//
// The value this catches in practice is make([]byte, 32) from a forgotten, ignored or failed
// crypto/rand read: the length check passes, encryption succeeds, and a database dump becomes
// sufficient to recover every tenant's signing secret.
var ErrTrivialKEK = errors.New("keystore: KEK is trivially known (all zero or a repeated byte); generate it with crypto/rand or load it from a secret manager")

// ErrKEKRequired is returned by NewManager when no KEK is configured.
var ErrKEKRequired = errors.New("keystore: a KEK is required (envelope encryption is mandatory)")

// ErrCiphertextCorrupt is returned by Open when the sealed blob is too short or fails the GCM
// authentication tag — tamper or wrong-KEK detection.
var ErrCiphertextCorrupt = errors.New("keystore: sealed secret is corrupt or was sealed with a different KEK")

// NewKEK builds a KEK from a 32-byte key. It fails fast on any other length so a misconfigured
// deployment cannot start with a weak or wrong-sized key.
func NewKEK(key []byte) (*KEK, error) {
	if len(key) != KEKKeyLength {
		return nil, ErrInvalidKEK
	}
	if err := trivialKEKError(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("keystore: building AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keystore: building GCM: %w", err)
	}
	return &KEK{aead: aead}, nil
}

// Seal encrypts plaintext with a fresh random nonce, returning nonce||ciphertext||tag. An
// optional AAD slice may be passed to authenticate associated data. If len(aad) > 0, aad[0] is
// passed to aead.Seal. The result is safe to store in the database.
func (k *KEK) Seal(plaintext []byte, aad ...[]byte) ([]byte, error) {
	var extra []byte
	if len(aad) > 0 {
		extra = aad[0]
	}
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("keystore: generating nonce: %w", err)
	}
	// Seal appends the ciphertext+tag to nonce, so the nonce prefixes the returned blob.
	return k.aead.Seal(nonce, nonce, plaintext, extra), nil
}

// Open reverses Seal. An optional AAD slice may be passed; if provided, it must match the AAD
// used when sealing. If len(aad) > 0, aad[0] is passed to aead.Open. It returns ErrCiphertextCorrupt
// if the blob is too short or the authentication tag does not verify (wrong KEK, tampering, or wrong AAD).
func (k *KEK) Open(sealed []byte, aad ...[]byte) ([]byte, error) {
	var extra []byte
	if len(aad) > 0 {
		extra = aad[0]
	}
	ns := k.aead.NonceSize()
	if len(sealed) < ns {
		return nil, ErrCiphertextCorrupt
	}
	nonce, ct := sealed[:ns], sealed[ns:]
	pt, err := k.aead.Open(nil, nonce, ct, extra)
	if err != nil {
		return nil, ErrCiphertextCorrupt
	}
	return pt, nil
}

// trivialKEKError reports a non-nil error when key is attacker-guessable at any length: every byte
// zero, or a single byte value repeated throughout. Such a key satisfies the length gate, so the
// check cannot be expressed as a minimum-length rule.
//
// It mirrors tokens/jwt's trivialSecretError and the published-example denylist in passkey: every
// other key-loading path in this module refuses an all-zero or published key, and the KEK — the one
// secret whose compromise defeats all of them at once — was the exception.
func trivialKEKError(key []byte) error {
	if len(key) == 0 {
		return nil // the length check above rejects this; keep the helper total
	}
	first := key[0]
	for _, b := range key[1:] {
		if b != first {
			return nil
		}
	}
	return ErrTrivialKEK
}
