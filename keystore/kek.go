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
