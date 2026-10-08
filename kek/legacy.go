package kek

import (
	"context"
	"crypto/cipher"
	"errors"
	"log/slog"
)

type legacyLocal struct {
	aead cipher.AEAD
}

// LegacyLocalV016 returns an opener for blobs sealed by the v0.16 keystore KEK built from key
// (AES-256-GCM over the raw key, nonce||ciphertext||tag). It accepts exactly the keys v0.16
// keystore.NewKEK accepted: KeyLength bytes, not a single repeated byte and not a published example
// credential; anything else returns ErrInvalidKey. Its bytes are copied. It is removed in v0.18.
func LegacyLocalV016(key []byte) (LegacyOpener, error) {
	if err := checkLegacyKey(key); err != nil {
		return nil, errors.Join(ErrInvalidKey, err)
	}
	aead, err := newGCM(append([]byte(nil), key...))
	if err != nil {
		return nil, errors.Join(ErrInvalidKey, err)
	}
	return legacyLocal{aead: aead}, nil
}

func (l legacyLocal) OpenLegacy(_ context.Context, blob []byte, aad AAD) ([]byte, error) {
	if len(blob) < gcmNonceSize+gcmTagSize {
		return nil, ErrMalformed
	}
	var extra []byte
	if len(aad) > 0 {
		extra = aad
	}
	pt, err := l.aead.Open(nil, blob[:gcmNonceSize], blob[gcmNonceSize:], extra)
	if err != nil {
		return nil, ErrOpenFailed
	}
	return pt, nil
}

func (l legacyLocal) String() string { return "kek.LegacyLocalV016{REDACTED}" }

func (l legacyLocal) GoString() string { return l.String() }

func (l legacyLocal) LogValue() slog.Value { return slog.StringValue(l.String()) }
