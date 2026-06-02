package argon2

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/JLugagne/egauth/passwords"
	"golang.org/x/crypto/argon2"
)

// NewHasher creates a new Argon2id hasher.
//
// With no options it uses sensible, backward-compatible defaults:
// m=64MB (65536 KiB), t=1, p=4, keyLen=32, saltLen=16. These follow the
// OWASP (2021) guidance for highly concurrent workloads, balanced for
// general use. The configured cost also doubles as the minimum acceptable
// cost reported by NeedsRehash: any stored hash weaker than this hasher's
// parameters is flagged for rehash on next successful login (SEC-10).
//
// Use WithTime, WithMemory and WithThreads to raise (or otherwise tune) the
// cost; raising them upgrades existing users transparently via NeedsRehash.
func NewHasher(opts ...Option) *Hasher {
	h := &Hasher{
		time:    1,
		memory:  64 * 1024,
		threads: 4,
		keyLen:  32,
		saltLen: 16,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Option configures a Hasher's Argon2id cost parameters.
type Option func(*Hasher)

// WithTime sets the number of Argon2id iterations (the t parameter).
// Values below 1 are ignored to keep the hasher in a valid state.
func WithTime(time uint32) Option {
	return func(h *Hasher) {
		if time >= 1 {
			h.time = time
		}
	}
}

// WithMemory sets the Argon2id memory cost in KiB (the m parameter).
func WithMemory(memory uint32) Option {
	return func(h *Hasher) {
		if memory >= 1 {
			h.memory = memory
		}
	}
}

// WithThreads sets the Argon2id degree of parallelism (the p parameter).
// Values below 1 are ignored to keep the hasher in a valid state.
func WithThreads(threads uint8) Option {
	return func(h *Hasher) {
		if threads >= 1 {
			h.threads = threads
		}
	}
}

// NeedsRehash reports whether a stored PHC-formatted Argon2id hash should be
// re-hashed at this hasher's current target cost.
//
// It returns true when any stored cost parameter (memory, time, threads or the
// derived key length) is below this hasher's configured target, OR when the
// hash is malformed, uses a different algorithm/version, or is otherwise
// unparseable. A corrupt or foreign-format hash is deliberately flagged so it
// is upgraded to the canonical Argon2id format on the next successful login.
//
// This is the standard "rehash on login" primitive: after a SUCCESSFUL Compare,
// a caller invokes NeedsRehash and, if it returns true, re-Hashes the plaintext
// and persists the new hash. NeedsRehash performs no key derivation and so is
// cheap; it never mutates state.
//
// NeedsRehash is a concrete method on *Hasher and is intentionally not part of
// the passwords.Hasher interface (which has other implementers); consumers that
// want rehash-on-login type-assert to *argon2.Hasher or hold the concrete type.
func (h *Hasher) NeedsRehash(hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return true
	}
	if parts[1] != "argon2id" {
		return true
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return true
	}
	if version != argon2.Version {
		return true
	}

	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return true
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return true
	}
	keyLen := uint32(len(decodedHash))

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return true
	}
	saltLen := uint32(len(salt))

	// Any stored parameter weaker than this hasher's target means the hash was
	// produced under a lower cost (an imported/migrated row, or a pre-upgrade
	// default) and must be strengthened.
	if memory < h.memory ||
		time < h.time ||
		threads < h.threads ||
		keyLen < h.keyLen ||
		saltLen < h.saltLen {
		return true
	}

	return false
}

// Ensure *Hasher satisfies the passwords.Hasher interface at compile time.
var _ passwords.Hasher = (*Hasher)(nil)

// Hasher implements the passwords.Hasher interface using Argon2id.
type Hasher struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
	saltLen uint32
}

// Hash securely hashes the password using Argon2id and returns the PHC string format.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if password == "" {
		return "", passwords.ErrHashFailed
	}
	// Bound attacker-controlled input before running the (deliberately expensive) KDF, to
	// prevent a pre-auth CPU/memory amplification DoS. See passwords.MaxPasswordLength.
	if len(password) > passwords.MaxPasswordLength {
		return "", passwords.ErrPasswordTooLong
	}
	// Honor cancellation before running the deliberately expensive KDF, so a cancelled or
	// timed-out request cannot still cost a full Argon2id pass (memory + CPU). argon2.IDKey is
	// not itself interruptible, so this pre-call check is the only available cancellation point.
	if err := ctx.Err(); err != nil {
		return "", err
	}

	salt := make([]byte, h.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("%w: %v", passwords.ErrHashFailed, err)
	}

	hash := argon2.IDKey([]byte(password), salt, h.time, h.memory, h.threads, h.keyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
	phc := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.memory, h.time, h.threads, b64Salt, b64Hash)

	return phc, nil
}

// Compare checks a plaintext password against a PHC formatted Argon2id hash.
func (h *Hasher) Compare(ctx context.Context, hash, password string) error {
	// Refuse to run the KDF on oversized candidate input (pre-auth DoS guard). A stored hash
	// can only have come from an in-bounds password, so an oversized candidate cannot match;
	// report it as an ordinary mismatch to avoid leaking a distinct signal.
	if len(password) > passwords.MaxPasswordLength {
		return passwords.ErrInvalidPassword
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return passwords.ErrInvalidPassword
	}
	if parts[1] != "argon2id" {
		return passwords.ErrInvalidPassword
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return passwords.ErrInvalidPassword
	}
	if version != argon2.Version {
		return passwords.ErrInvalidPassword
	}

	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return passwords.ErrInvalidPassword
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return passwords.ErrInvalidPassword
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return passwords.ErrInvalidPassword
	}
	keyLen := uint32(len(decodedHash))

	// Validate the parsed cost parameters before handing them to argon2.IDKey. They come from
	// a stored PHC string that may have been populated by a consumer (import, migration, or a
	// hand-edited DB row), so they are untrusted input on the verify path. golang.org/x/crypto
	// v0.52.0 argon2.deriveKey PANICS on time<1 ("number of rounds too small") and threads<1
	// ("parallelism degree too low"), and a zero-length final hash segment (keyLen==0) triggers
	// a nil-pointer panic in extractKey -> blake2bHash, where blake2b.New(0, nil) returns a nil
	// hash whose Write is then called. A single malformed row must never crash the verify path,
	// so we treat any such hash as a non-match. We reuse the opaque ErrInvalidPassword returned
	// throughout Compare so a corrupt or forged stored hash is indistinguishable from an
	// ordinary password mismatch (no distinct signal to an attacker).
	if time < 1 || threads < 1 || keyLen == 0 {
		return passwords.ErrInvalidPassword
	}
	// deriveKey internally clamps memory up to a per-thread minimum of 8*threads KiB
	// (2*syncPoints*threads, syncPoints==4). A stored memory below that floor could not have
	// produced this hash (IDKey would have re-derived with the clamped value), so the hash is
	// corrupt; reject it rather than silently verify against a different cost than was recorded.
	if memory < 8*uint32(threads) {
		return passwords.ErrInvalidPassword
	}

	// Honor cancellation before the deliberately expensive KDF (same rationale as Hash): a
	// cancelled or timed-out verification must not still cost a full Argon2id pass.
	if err := ctx.Err(); err != nil {
		return err
	}

	comparisonHash := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)

	if subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1 {
		return nil
	}

	return passwords.ErrInvalidPassword
}
