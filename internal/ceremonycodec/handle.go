package ceremonycodec

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
)

var b64 = base64.RawURLEncoding.Strict()

// HandleBytes is the entropy of a stored ceremony's handle: 256 bits.
const HandleBytes = 32

// ErrInvalidHandle is returned for a handle that is malformed, forged, tampered, expired, of
// another kind or of another tenant. More specific causes are joined to it.
var ErrInvalidHandle = errors.New("ceremonycodec: invalid handle")

// Handle is the 256-bit random key of a stored ceremony record, returned to the requesting client
// (JSON handle or the bind cookie). Stores see only Hash. A short code is never a Handle (C-30).
type Handle struct {
	raw []byte
}

// NewHandle draws a Handle from crypto/rand.
func NewHandle() (Handle, error) {
	raw := make([]byte, HandleBytes)
	if _, err := rand.Read(raw); err != nil {
		return Handle{}, errors.Join(errors.New("ceremonycodec: generating handle"), err)
	}
	return Handle{raw: raw}, nil
}

// ParseHandle decodes a handle sent back by a client. Anything but 256 bits of unpadded base64url
// returns ErrInvalidHandle.
func ParseHandle(s string) (Handle, error) {
	if len(s) != b64.EncodedLen(HandleBytes) {
		return Handle{}, ErrInvalidHandle
	}
	raw, err := b64.DecodeString(s)
	if err != nil || len(raw) != HandleBytes {
		return Handle{}, ErrInvalidHandle
	}
	return Handle{raw: raw}, nil
}

// IsZero reports whether h was not built by NewHandle or ParseHandle.
func (h Handle) IsZero() bool { return len(h.raw) == 0 }

// Encode returns the wire form handed to the client: unpadded base64url.
func (h Handle) Encode() string { return b64.EncodeToString(h.raw) }

// Hash returns SHA-256 of the 32 raw bytes: the only form a store keeps or looks up.
func (h Handle) Hash() []byte {
	sum := sha256.Sum256(h.raw)
	return sum[:]
}

// String redacts the handle.
func (h Handle) String() string { return "ceremonycodec.Handle{" + redacted + "}" }

// GoString redacts like String.
func (h Handle) GoString() string { return h.String() }

// LogValue redacts like String.
func (h Handle) LogValue() slog.Value { return slog.StringValue(h.String()) }
