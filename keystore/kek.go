package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// KEK is a deployment Key-Encryption-Key used to envelope-encrypt tenant signing secrets at
// rest. Every secret a Store persists is sealed with the KEK (AES-256-GCM) so a database dump
// alone never yields usable signing material — the attacker also needs the KEK, which lives in
// the deployment's secret manager, not the database.
//
// The KEK is REQUIRED and fail-fast validated: NewKEK rejects any key that is not exactly 32
// bytes (AES-256), and NewManager rejects a nil KEK. There is no "no encryption" mode.
//
// # Sealed format
//
// Seal binds a SecretContext — the tenant, the subsystem, and the row the secret belongs to — into
// the AEAD as associated data, so a ciphertext is only openable in the place it was sealed for. The
// blob it writes is versioned:
//
//	v1: 0x01 || nonce(12) || ciphertext || tag        (associated data = SecretContext)
//
// Open also accepts the LEGACY format written before context binding existed:
//
//	legacy: nonce(12) || ciphertext || tag            (no associated data)
//
// so secrets already at rest keep working across the upgrade. See SecretContext for the migration
// path and WithoutLegacySealedFormat for closing it once every row has been re-sealed.
type KEK struct {
	aead cipher.AEAD
	// allowLegacy, when false, makes Open refuse the pre-context sealed format.
	allowLegacy bool
}

// KEKKeyLength is the required KEK length in bytes (AES-256).
const KEKKeyLength = 32

// sealedFormatV1 prefixes every blob written with a SecretContext bound as associated data. A
// legacy blob starts with the first byte of its random nonce, so it can collide with this prefix by
// chance (1 in 256); Open therefore treats the prefix as a hint and falls back to the legacy parse,
// with the GCM tag as the authority on which interpretation is correct.
const sealedFormatV1 byte = 0x01

// aadPrefix domain-separates the associated data from any other use of these fields.
const aadPrefix = "egauth/keystore/kek/v1\x00"

// Errors returned by the KEK.
var (
	// ErrInvalidKEK is returned by NewKEK when the supplied key is not exactly KEKKeyLength bytes.
	ErrInvalidKEK = errors.New("keystore: KEK must be exactly 32 bytes (AES-256)")

	// ErrKEKRequired is returned by NewManager when no KEK is configured.
	ErrKEKRequired = errors.New("keystore: a KEK is required (envelope encryption is mandatory)")

	// ErrCiphertextCorrupt is returned by Open when the sealed blob is too short, fails the GCM
	// authentication tag, or was sealed for a DIFFERENT SecretContext — tamper, wrong-KEK, and
	// wrong-place detection.
	ErrCiphertextCorrupt = errors.New("keystore: sealed secret is corrupt, was sealed with a different KEK, or does not belong to this context")

	// ErrSecretContextIncomplete is returned by Seal and Open when the SecretContext carries no
	// Purpose. A purpose label is the minimum binding that keeps two subsystems' ciphertexts from
	// being interchangeable, so an unlabelled context is refused rather than silently accepted.
	ErrSecretContextIncomplete = errors.New("keystore: sealed-secret context requires a Purpose")
)

// Purpose labels for SecretContext. Each names one subsystem's secret so a ciphertext from one can
// never be opened as another (a signing key pasted over a TOTP secret, or the reverse). Callers
// outside this repository may define their own labels; keep them stable, because the label is part
// of the associated data and changing it makes existing blobs un-openable.
const (
	// PurposeSigningKey labels a tenant's JWT signing key material (keystore).
	PurposeSigningKey = "keystore/signing-key"
	// PurposeTOTPSecret labels a user's TOTP shared secret (mfa).
	PurposeTOTPSecret = "mfa/totp-secret"
	// PurposeOAuthClientSecret labels a tenant's OIDC client_secret (oauth).
	PurposeOAuthClientSecret = "oauth/client-secret"
)

// SecretContext identifies WHERE a sealed secret belongs. It is bound into the AEAD as associated
// data, so the ciphertext authenticates not just its bytes but its position: a blob sealed for one
// tenant, subsystem or row cannot be opened as another, which closes the confused-deputy path where
// an attacker who can write a row pastes a ciphertext from somewhere else and has the application
// decrypt and use it.
//
// TenantID is the owning tenant ("" is the legitimate single-tenant partition). Purpose is a
// subsystem label (see the Purpose* constants) and is REQUIRED. RowID is the record's own identity
// within the subsystem — a key id, a user id, a provider name — and should be supplied whenever the
// storage layer has one; leaving it empty binds the blob to the tenant and purpose only.
//
// # Migration
//
// Blobs written before context binding existed carry no associated data. Open accepts them under any
// context (there is nothing to check), and everything newly written is bound, so an upgrade needs no
// data migration to keep working. To finish the transition an operator re-seals each row — read it
// (the legacy blob still opens), Seal the plaintext with the row's context, write it back — and then
// constructs the KEK with WithoutLegacySealedFormat so the unbound format is refused from then on.
type SecretContext struct {
	TenantID string
	Purpose  string
	RowID    string
}

// aad renders the context as unambiguous associated data. Each field is length-prefixed so no two
// distinct contexts can produce the same bytes (e.g. tenant "a"+row "bc" vs tenant "ab"+row "c").
func (sc SecretContext) aad() []byte {
	out := make([]byte, 0, len(aadPrefix)+len(sc.TenantID)+len(sc.Purpose)+len(sc.RowID)+12)
	out = append(out, aadPrefix...)
	out = appendLenPrefixed(out, sc.TenantID)
	out = appendLenPrefixed(out, sc.Purpose)
	return appendLenPrefixed(out, sc.RowID)
}

func appendLenPrefixed(dst []byte, s string) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s))) //#nosec G115 -- s is a tenant ID/purpose/row ID, never large enough to overflow uint32
	dst = append(dst, n[:]...)
	return append(dst, s...)
}

// KEKOption configures a KEK.
type KEKOption func(*KEK)

// WithoutLegacySealedFormat makes Open refuse the pre-context sealed format (an unversioned blob
// with no associated data), accepting only blobs bound to a SecretContext. Set it once every row in
// the deployment has been re-sealed: until then it locks out every secret written by an earlier
// release. See SecretContext for the migration path.
func WithoutLegacySealedFormat() KEKOption {
	return func(k *KEK) { k.allowLegacy = false }
}

// NewKEK builds a KEK from a 32-byte key. It fails fast on any other length so a misconfigured
// deployment cannot start with a weak or wrong-sized key. By default it opens both the
// context-bound and the legacy sealed format; pass WithoutLegacySealedFormat to accept only the
// former.
func NewKEK(key []byte, opts ...KEKOption) (*KEK, error) {
	if len(key) != KEKKeyLength {
		return nil, ErrInvalidKEK
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Join(errors.New("keystore: building AES cipher"), err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Join(errors.New("keystore: building GCM"), err)
	}
	k := &KEK{aead: aead, allowLegacy: true}
	for _, opt := range opts {
		opt(k)
	}
	return k, nil
}

// Seal encrypts plaintext with a fresh random nonce, binding sc as associated data, and returns the
// versioned blob 0x01||nonce||ciphertext||tag. The result is safe to store in the database and can
// only be opened again by presenting the same SecretContext.
func (k *KEK) Seal(sc SecretContext, plaintext []byte) ([]byte, error) {
	if sc.Purpose == "" {
		return nil, ErrSecretContextIncomplete
	}
	ns := k.aead.NonceSize()
	// The version byte prefixes the blob, so lay it out first and let Seal append to it: the
	// nonce must be written after the prefix and passed to Seal unprefixed. The capacity covers
	// the whole result so the nonce is not copied out from under the slice by a reallocation.
	blob := make([]byte, 1+ns, 1+ns+len(plaintext)+k.aead.Overhead())
	blob[0] = sealedFormatV1
	nonce := blob[1:]
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.Join(errors.New("keystore: generating nonce"), err)
	}
	return k.aead.Seal(blob, nonce, plaintext, sc.aad()), nil //#nosec G407 -- nonce is filled by rand.Read above, not hardcoded; gosec misreads the make-then-slice-then-fill idiom
}

// Open reverses Seal. It returns ErrCiphertextCorrupt if the blob is too short, its authentication
// tag does not verify (wrong KEK or tampering), or it was sealed for a different SecretContext.
//
// It accepts both sealed formats: the versioned, context-bound blob Seal writes, and the legacy
// unversioned blob written before context binding existed (unless the KEK was built with
// WithoutLegacySealedFormat). A legacy blob has no binding to verify, so it opens under any context
// — that is exactly the compatibility this transition buys, and the reason to finish the migration.
func (k *KEK) Open(sc SecretContext, sealed []byte) ([]byte, error) {
	if sc.Purpose == "" {
		return nil, ErrSecretContextIncomplete
	}
	ns := k.aead.NonceSize()
	if len(sealed) >= 1+ns && sealed[0] == sealedFormatV1 {
		if pt, err := k.aead.Open(nil, sealed[1:1+ns], sealed[1+ns:], sc.aad()); err == nil {
			return pt, nil
		}
	}
	if !k.allowLegacy || len(sealed) < ns {
		return nil, ErrCiphertextCorrupt
	}
	pt, err := k.aead.Open(nil, sealed[:ns], sealed[ns:], nil)
	if err != nil {
		return nil, ErrCiphertextCorrupt
	}
	return pt, nil
}
