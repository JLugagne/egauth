package kek

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"strconv"
)

// KeyLength is the length in bytes of every key given to NewLocal and LegacyLocalV016 (AES-256).
const KeyLength = 32

const (
	formatV1     byte = 0x01
	maxKeyIDLen       = 64
	kidInfo           = "egauth/kek-id"
	aeadInfo          = "egauth/kek-aead/v1"
	gcmNonceSize      = 12
	gcmTagSize        = 16
)

var _ KEK = (*Local)(nil)

// Local is a KEK whose keys live in process memory. The ciphertext format is
// 0x01 ‖ len(kid) ‖ kid ‖ nonce ‖ ct ‖ tag (AES-256-GCM), where
// kid = hex(SHA-256(HKDF-SHA256(key, info "egauth/kek-id"))[:8]); the header is authenticated with
// the associated data. A Local is immutable and safe for concurrent use.
type Local struct {
	current *localKey
	byID    map[string]*localKey
}

type localKey struct {
	id   string
	aead cipher.AEAD
}

// NewLocal returns a KEK that seals with current and opens ciphertexts sealed by current or any of
// previous. Rotation: deploy NewLocal(new, old), let lazy re-seal move every row to new, then drop
// old. Each key must be KeyLength bytes from a CSPRNG; a trivially guessable key, a credential
// published in egauth's examples or docs, or a duplicate returns ErrInvalidKey. The key bytes are
// copied.
func NewLocal(current []byte, previous ...[]byte) (*Local, error) {
	cur, err := newLocalKey(current)
	if err != nil {
		return nil, errors.Join(ErrInvalidKey, errors.New("current key"), err)
	}
	l := &Local{current: cur, byID: map[string]*localKey{cur.id: cur}}
	for i, raw := range previous {
		k, err := newLocalKey(raw)
		if err != nil {
			return nil, errors.Join(ErrInvalidKey, errors.New("previous key "+strconv.Itoa(i)), err)
		}
		if _, dup := l.byID[k.id]; dup {
			return nil, errors.Join(ErrInvalidKey, errors.New("previous key "+strconv.Itoa(i)+" duplicates another key"))
		}
		l.byID[k.id] = k
	}
	return l, nil
}

func newLocalKey(key []byte) (*localKey, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	return deriveLocalKey(key)
}

func deriveLocalKey(key []byte) (*localKey, error) {
	id, err := keyID(key)
	if err != nil {
		return nil, err
	}
	sub, err := hkdf.Key(sha256.New, key, nil, aeadInfo, KeyLength)
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(sub)
	if err != nil {
		return nil, err
	}
	return &localKey{id: id, aead: aead}, nil
}

func keyID(key []byte) (string, error) {
	okm, err := hkdf.Key(sha256.New, key, nil, kidInfo, KeyLength)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(okm)
	return hex.EncodeToString(sum[:8]), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts pt under the current key, binding aad and the ciphertext header.
func (l *Local) Seal(_ context.Context, pt []byte, aad AAD) ([]byte, error) {
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}
	header := make([]byte, 0, 2+len(l.current.id)+gcmNonceSize+len(pt)+gcmTagSize)
	header = append(header, formatV1, byte(len(l.current.id)))
	header = append(header, l.current.id...)
	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.Join(errors.New("kek: generating nonce"), err)
	}
	out := append(header, nonce...)
	return l.current.aead.Seal(out, nonce, pt, boundAAD(out[:2+len(l.current.id)], aad)), nil
}

// Open decrypts ct with the key named in its header.
func (l *Local) Open(_ context.Context, ct []byte, aad AAD) ([]byte, error) {
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}
	id, headerLen, err := parseHeader(ct)
	if err != nil {
		return nil, err
	}
	k, ok := l.byID[id]
	if !ok {
		return nil, ErrUnknownKey
	}
	body := ct[headerLen:]
	if len(body) < gcmNonceSize+gcmTagSize {
		return nil, ErrMalformed
	}
	pt, err := k.aead.Open(nil, body[:gcmNonceSize], body[gcmNonceSize:], boundAAD(ct[:headerLen], aad))
	if err != nil {
		return nil, ErrOpenFailed
	}
	return pt, nil
}

// CurrentKeyID returns the id of the key Seal uses.
func (l *Local) CurrentKeyID() string { return l.current.id }

// KeyIDOf returns the id of the key that sealed ct, or ErrMalformed. It does not authenticate ct.
func (l *Local) KeyIDOf(ct []byte) (string, error) {
	id, _, err := parseHeader(ct)
	return id, err
}

// String redacts the keys; only the current key id is shown.
func (l *Local) String() string { return "kek.Local{current: " + l.current.id + "}" }

// GoString redacts the keys like String.
func (l *Local) GoString() string { return l.String() }

// LogValue redacts the keys like String.
func (l *Local) LogValue() slog.Value {
	return slog.GroupValue(slog.String("current_key_id", l.current.id), slog.Int("keys", len(l.byID)))
}

func parseHeader(ct []byte) (string, int, error) {
	if len(ct) < 2 || ct[0] != formatV1 {
		return "", 0, ErrMalformed
	}
	n := int(ct[1])
	if n == 0 || n > maxKeyIDLen || len(ct) < 2+n {
		return "", 0, ErrMalformed
	}
	return string(ct[2 : 2+n]), 2 + n, nil
}

func boundAAD(header []byte, aad AAD) []byte {
	out := make([]byte, 0, len(header)+len(aad))
	out = append(out, header...)
	return append(out, aad...)
}
