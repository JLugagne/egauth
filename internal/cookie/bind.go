package cookie

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"log/slog"
)

const (
	bindBytes = 32
	redacted  = "REDACTED"
)

// BindSecret is the browser-binding secret of one unauthenticated ceremony (C-38, C-69): 256
// random bits sent as the bind cookie (or the {"bind"} body field under Bearer) whose SHA-256 is
// sealed in the Pending. The zero BindSecret is invalid. It renders as REDACTED under fmt and slog.
type BindSecret struct {
	value string
	hash  [sha256.Size]byte
}

// NewBind draws a fresh BindSecret from crypto/rand.
func NewBind() (BindSecret, error) {
	var raw [bindBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return BindSecret{}, err
	}
	v := base64.RawURLEncoding.EncodeToString(raw[:])
	return BindSecret{value: v, hash: sha256.Sum256([]byte(v))}, nil
}

// Value returns the secret to hand to the client: the bind cookie value, or the body field under
// Bearer transport.
func (b BindSecret) Value() string { return b.value }

// Hash returns the SHA-256 to seal with core.Pending.WithBindHash; nil for the zero BindSecret.
func (b BindSecret) Hash() []byte {
	if b.value == "" {
		return nil
	}
	return append([]byte(nil), b.hash[:]...)
}

func (b BindSecret) String() string { return redacted }

func (b BindSecret) GoString() string { return redacted }

func (b BindSecret) LogValue() slog.Value { return slog.StringValue(redacted) }

// VerifyBind reports, in constant time, whether presented hashes to sealed. An empty presented
// value or a sealed hash that is not 32 bytes is refused, so a ceremony begun without binding can
// never be consumed as bound.
func VerifyBind(presented string, sealed []byte) bool {
	sum := sha256.Sum256([]byte(presented))
	ok := subtle.ConstantTimeCompare(sum[:], sealed) == 1
	return ok && presented != "" && len(sealed) == sha256.Size
}
