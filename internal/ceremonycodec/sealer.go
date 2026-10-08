package ceremonycodec

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/secretpolicy"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/ceremony"
)

// DataKeyBytes is the length of the deployment data key a Sealer is built from.
const DataKeyBytes = 32

const (
	handleVersion   byte = 1
	handleInfo           = "egauth/ceremony-handle/v1"
	codeInfo             = "egauth/short-code/v1"
	maxHandleChars       = 8 << 10
	minDistinctKey       = 8
	expiresAtLength      = 8
)

var (
	// ErrInvalidDataKey is returned by NewSealer for a key that is not 32 bytes, is trivially
	// guessable or is a credential published in egauth's examples or docs.
	ErrInvalidDataKey = errors.New("ceremonycodec: invalid data key")
	// ErrNotStateless is returned when a kind that is stored as a record is sealed into a handle.
	ErrNotStateless = errors.New("ceremonycodec: kind is not a stateless begin")
	// ErrExpired is returned, joined to ErrInvalidHandle, by Open for a handle at or past its
	// expiry, and by Seal for a Pending that has already expired.
	ErrExpired = errors.New("ceremonycodec: handle expired")
	// ErrWrongTenant is returned, joined to ErrInvalidHandle, for a handle sealed for another
	// tenant than the one the request resolved to. The caller answers 401 without consuming it.
	ErrWrongTenant = errors.New("ceremonycodec: handle of another tenant")
)

// Sealer seals and opens stateless ceremony handles under a subkey of the deployment data key
// (XChaCha20-Poly1305 with random 192-bit nonces, so the long-lived key never risks a nonce
// collision), and keys short-code digests (NewCode) under another subkey. It is immutable and safe
// for concurrent use.
type Sealer struct {
	aead    cipher.AEAD
	codeKey []byte
	clock   clock.Clock
}

// NewSealer derives the handle key and the short-code key from dataKey with HKDF-SHA256 (info
// "egauth/ceremony-handle/v1" and "egauth/short-code/v1") and reads expiry against c. dataKey must
// be DataKeyBytes bytes of CSPRNG output, otherwise ErrInvalidDataKey; it is not retained.
func NewSealer(dataKey []byte, c clock.Clock) (*Sealer, error) {
	if len(dataKey) != DataKeyBytes || weakKey(dataKey) || secretpolicy.Reason(dataKey) != "" {
		return nil, ErrInvalidDataKey
	}
	sub, err := hkdf.Key(sha256.New, dataKey, nil, handleInfo, chacha20poly1305.KeySize)
	if err != nil {
		return nil, errors.Join(ErrInvalidDataKey, err)
	}
	aead, err := chacha20poly1305.NewX(sub)
	if err != nil {
		return nil, errors.Join(ErrInvalidDataKey, err)
	}
	codeKey, err := hkdf.Key(sha256.New, dataKey, nil, codeInfo, sha256.Size)
	if err != nil {
		return nil, errors.Join(ErrInvalidDataKey, err)
	}
	return &Sealer{aead: aead, codeKey: codeKey, clock: c}, nil
}

func weakKey(key []byte) bool {
	var seen [256]bool
	distinct := 0
	for _, b := range key {
		if !seen[b] {
			seen[b] = true
			distinct++
		}
	}
	return distinct < minDistinctKey
}

// String redacts the key.
func (s *Sealer) String() string { return "ceremonycodec.Sealer{" + redacted + "}" }

// GoString redacts like String.
func (s *Sealer) GoString() string { return s.String() }

// LogValue redacts like String.
func (s *Sealer) LogValue() slog.Value { return slog.StringValue(s.String()) }

// Issued is a sealed stateless handle and the instant it stops opening.
type Issued struct {
	Handle    string
	ExpiresAt time.Time
}

// String redacts the handle.
func (i Issued) String() string {
	return "ceremonycodec.Issued{Handle: " + redacted + ", ExpiresAt: " + i.ExpiresAt.UTC().Format(time.RFC3339) + "}"
}

// GoString redacts like String.
func (i Issued) GoString() string { return i.String() }

// LogValue redacts the handle.
func (i Issued) LogValue() slog.Value {
	return slog.GroupValue(slog.String("handle", redacted), slog.Time("expires_at", i.ExpiresAt))
}

// Opened is an authenticated, unexpired handle of the expected kind and tenant. HandleHash keys
// the store's MarkConsumed, which makes the handle single-use until ExpiresAt.
type Opened[P any] struct {
	Pending    core.Pending
	Payload    P
	ExpiresAt  time.Time
	HandleHash []byte
}

// Seal seals kind ‖ tenant ‖ sealed p ‖ payload ‖ expiresAt into a handle. The tenant is p's and
// the expiry is the kind's ExpiresAt clamped to p's, so no handle outlives its Pending. A stored
// kind returns ErrNotStateless and an expired p returns ErrExpired.
func (c Codec[P]) Seal(s *Sealer, p core.Pending, payload P) (Issued, error) {
	if s == nil || !c.kind.Stateless() {
		return Issued{}, ErrNotStateless
	}
	body, err := c.Encode(payload)
	if err != nil {
		return Issued{}, err
	}
	sealed, err := core.SealPending(p)
	if err != nil {
		return Issued{}, errors.Join(errors.New("ceremonycodec: sealing pending"), err)
	}
	now := s.clock.Now()
	exp := c.kind.ExpiresAt(p.ExpiresAt(), now)
	if !now.Before(exp) {
		return Issued{}, ErrExpired
	}
	tenant := p.Tenant().String()
	pending := sealed.Bytes()
	pt := make([]byte, 0, 1+1+len(tenant)+4+len(pending)+4+len(body)+expiresAtLength)
	pt = append(pt, byte(c.kind), byte(len(tenant)))
	pt = append(pt, tenant...)
	pt = binary.BigEndian.AppendUint32(pt, uint32(len(pending)))
	pt = append(pt, pending...)
	pt = binary.BigEndian.AppendUint32(pt, uint32(len(body)))
	pt = append(pt, body...)
	pt = binary.BigEndian.AppendUint64(pt, uint64(exp.UnixNano()))
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return Issued{}, errors.Join(errors.New("ceremonycodec: generating nonce"), err)
	}
	out := append([]byte{handleVersion}, nonce...)
	out = s.aead.Seal(out, nonce, pt, []byte(handleInfo))
	handle := b64.EncodeToString(out)
	if len(handle) > maxHandleChars {
		return Issued{}, errors.Join(ErrMalformedPayload, errors.New("handle too large"))
	}
	return Issued{Handle: handle, ExpiresAt: exp}, nil
}

// Open authenticates handle and checks, unconditionally, that it is of the codec's kind, sealed for
// tenant t and not expired (O-07). Every failure returns ErrInvalidHandle, joined with
// ErrWrongKind, ErrWrongTenant or ErrExpired when that is the cause.
func (c Codec[P]) Open(s *Sealer, t principal.TenantID, handle string) (Opened[P], error) {
	var zero Opened[P]
	if s == nil || !c.kind.Stateless() {
		return zero, errors.Join(ErrInvalidHandle, ErrNotStateless)
	}
	if len(handle) == 0 || len(handle) > maxHandleChars {
		return zero, ErrInvalidHandle
	}
	raw, err := b64.DecodeString(handle)
	if err != nil || len(raw) < 1+chacha20poly1305.NonceSizeX+s.aead.Overhead() || raw[0] != handleVersion {
		return zero, ErrInvalidHandle
	}
	nonce := raw[1 : 1+chacha20poly1305.NonceSizeX]
	pt, err := s.aead.Open(nil, nonce, raw[1+chacha20poly1305.NonceSizeX:], []byte(handleInfo))
	if err != nil {
		return zero, ErrInvalidHandle
	}
	h, ok := parseHandle(pt)
	if !ok {
		return zero, ErrInvalidHandle
	}
	if h.kind != c.kind {
		return zero, errors.Join(ErrInvalidHandle, ErrWrongKind)
	}
	if h.tenant != t.String() {
		return zero, errors.Join(ErrInvalidHandle, ErrWrongTenant)
	}
	if !s.clock.Now().Before(h.expiresAt) {
		return zero, errors.Join(ErrInvalidHandle, ErrExpired)
	}
	p, err := core.UnsealPending(core.SealedFromBytes(h.pending))
	if err != nil || p.Tenant() != t {
		return zero, errors.Join(ErrInvalidHandle, err)
	}
	payload, err := c.Decode(h.payload)
	if err != nil {
		return zero, errors.Join(ErrInvalidHandle, err)
	}
	sum := sha256.Sum256(raw)
	return Opened[P]{Pending: p, Payload: payload, ExpiresAt: h.expiresAt, HandleHash: sum[:]}, nil
}

type handleFields struct {
	kind      ceremony.Kind
	tenant    string
	pending   []byte
	payload   []byte
	expiresAt time.Time
}

func parseHandle(pt []byte) (handleFields, bool) {
	var f handleFields
	if len(pt) < 2 {
		return f, false
	}
	f.kind = ceremony.Kind(pt[0])
	n := int(pt[1])
	rest := pt[2:]
	if len(rest) < n {
		return f, false
	}
	f.tenant, rest = string(rest[:n]), rest[n:]
	var ok bool
	if f.pending, rest, ok = lengthPrefixed(rest); !ok {
		return f, false
	}
	if f.payload, rest, ok = lengthPrefixed(rest); !ok {
		return f, false
	}
	if len(rest) != expiresAtLength {
		return f, false
	}
	f.expiresAt = time.Unix(0, int64(binary.BigEndian.Uint64(rest)))
	return f, true
}

func lengthPrefixed(b []byte) ([]byte, []byte, bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	b = b[4:]
	if uint64(len(b)) < uint64(n) {
		return nil, nil, false
	}
	return b[:n], b[n:], true
}
