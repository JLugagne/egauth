package argon2

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/JLugagne/egauth/passwords"
	"golang.org/x/crypto/argon2"
)

// NewHasher creates an Argon2id hasher with the defaults m=64MB (65536 KiB), t=1, p=4, keyLen=32,
// saltLen=16, following the OWASP (2021) guidance for highly concurrent workloads. The configured
// cost doubles as the minimum acceptable cost reported by NeedsRehash: a stored hash weaker than
// this hasher's parameters is flagged for rehash on the next successful login (SEC-10).
func NewHasher() *Hasher {
	return NewTunedHasher(Params{})
}

// Params tunes the Argon2id cost of a Hasher. A zero field selects the default of NewHasher.
// Other values are clamped into the range Compare accepts ([MinTime, MaxTime],
// [MinMemoryKiB, MaxMemoryKiB], at least MinThreads), so every accepted configuration both hashes
// and verifies. Raising the cost upgrades existing users transparently through NeedsRehash.
type Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// NewTunedHasher creates an Argon2id hasher with the cost of p; see Params for the clamping.
func NewTunedHasher(p Params) *Hasher {
	h := &Hasher{
		time:    1,
		memory:  64 * 1024,
		threads: 4,
		keyLen:  32,
		saltLen: 16,
	}
	if p.Time != 0 {
		h.time = min(max(p.Time, MinTime), MaxTime)
	}
	if p.MemoryKiB != 0 {
		h.memory = min(max(p.MemoryKiB, MinMemoryKiB), MaxMemoryKiB)
	}
	if p.Threads != 0 {
		h.threads = max(p.Threads, MinThreads)
	}
	return h
}

// Minimum acceptable Argon2id cost parameters. Any value passed to the
// corresponding Params field below this floor is silently clamped UP to it, so a
// caller tuning the cost down cannot drop the hasher below a safe Argon2id
// configuration. The defaults baked into NewHasher (m=65536 KiB, t=1, p=4)
// sit at or above every floor and are therefore never affected.
//
// MinMemoryKiB follows the OWASP Password Storage Cheat Sheet (2021) minimum
// of 19 MiB (19456 KiB) for Argon2id; MinTime and MinThreads are the lowest
// values the algorithm accepts (golang.org/x/crypto/argon2 panics below them).
const (
	// MinMemoryKiB is the minimum Argon2id memory cost in KiB (OWASP 2021: 19 MiB).
	MinMemoryKiB uint32 = 19456
	// MaxMemoryKiB is the upper bound on the memory parameter enforced on both paths: Hash
	// (through NewTunedHasher's clamp) never emits a larger value, and Compare rejects a stored m
	// above it.
	// Any stored PHC hash carrying a memory value above this ceiling is rejected as
	// ErrInvalidPassword before the KDF is invoked, preventing an OOM DoS via a
	// tampered or corrupt stored hash row. 512 MiB (524288 KiB) is far above any
	// legitimate operational cost while remaining easy to reason about.
	MaxMemoryKiB uint32 = 524288
	// MinTime is the minimum number of Argon2id iterations (the t parameter).
	MinTime uint32 = 1
	// MaxTime is the upper bound on the iteration count (t) enforced on both paths: Hash (through
	// NewTunedHasher's clamp) never emits a larger value, and Compare rejects a stored t above it. It
	// is the CPU counterpart of MaxMemoryKiB.
	//
	// A stored PHC string is untrusted on the verify path: it may have been imported, migrated, or
	// hand-edited, and the parser reads t into a uint32, so t=4294967295 is representable. argon2.IDKey
	// takes no context and cannot be cancelled, so an unbounded t pins a core for as long as the value
	// says — projected at years for one login attempt — and both Compare callers (login and password
	// change) are reachable, meaning a single poisoned row locks the account out of its own
	// remediation. Any legitimate cost is orders of magnitude below this ceiling; a hash that exceeds
	// it is corrupt or tampered and is treated like any other mismatch.
	MaxTime uint32 = 16
	// MinThreads is the minimum Argon2id degree of parallelism (the p parameter).
	MinThreads uint8 = 1
)

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

var idKey = argon2.IDKey

var derivations = make(chan struct{}, max(2, runtime.GOMAXPROCS(0)))

func derive(ctx context.Context, password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) ([]byte, error) {
	select {
	case derivations <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-derivations }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return idKey(password, salt, time, memory, threads, keyLen), nil
}

// Hasher implements the passwords.Hasher interface using Argon2id. Every Hasher of the process
// shares a budget of max(2, GOMAXPROCS) concurrent derivations, so concurrent logins cannot
// exhaust memory; Hash and Compare wait for a slot and return ctx.Err() when ctx ends first.
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
		return "", errors.Join(passwords.ErrHashFailed, err)
	}

	hash, err := derive(ctx, []byte(password), salt, h.time, h.memory, h.threads, h.keyLen)
	if err != nil {
		return "", err
	}

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
	phc := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.memory, h.time, h.threads, b64Salt, b64Hash)

	return phc, nil
}

// Compare checks a plaintext password against a PHC formatted Argon2id hash.
func (h *Hasher) Compare(ctx context.Context, phc passwords.PHC, password string) error {
	hash := string(phc)
	// Reject empty candidates immediately, mirroring Hash() which also short-circuits before
	// the KDF on empty input. No stored hash can ever correspond to "": Hash rejects empty
	// passwords, so the round-trip is impossible. Returning here restores timing symmetry with
	// the decoy path (decoyHash -> Hash("") also returns instantly), preventing an
	// empty-password timing oracle that would otherwise reveal which accounts have a stored
	// password hash. See TASK-065 / SECURITY.md enumeration-defence contract.
	if password == "" {
		return passwords.ErrInvalidPassword
	}

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
	// Upper bound on the iteration count, mirroring the MaxMemoryKiB ceiling below: t is the one
	// cost parameter the parser accepts without an upper limit, and argon2.IDKey is uninterruptible.
	if time > MaxTime {
		return passwords.ErrInvalidPassword
	}
	// deriveKey internally clamps memory up to a per-thread minimum of 8*threads KiB
	// (2*syncPoints*threads, syncPoints==4). A stored memory below that floor could not have
	// produced this hash (IDKey would have re-derived with the clamped value), so the hash is
	// corrupt; reject it rather than silently verify against a different cost than was recorded.
	if memory < 8*uint32(threads) {
		return passwords.ErrInvalidPassword
	}
	// Reject an unreasonably large memory parameter before handing it to argon2.IDKey.
	// argon2.IDKey allocates memory*1024 bytes; a uint32 goes up to ~4 TiB. A tampered or
	// corrupt stored hash row with e.g. m=4000000000 would OOM-kill the process on the
	// victim's next login. MaxMemoryKiB (512 MiB) is far above any legitimate operational
	// cost and ensures a single bad row cannot trigger a multi-GiB allocation.
	if memory > MaxMemoryKiB {
		return passwords.ErrInvalidPassword
	}

	// Honor cancellation before the deliberately expensive KDF (same rationale as Hash): a
	// cancelled or timed-out verification must not still cost a full Argon2id pass.
	if err := ctx.Err(); err != nil {
		return err
	}

	comparisonHash, err := derive(ctx, []byte(password), salt, time, memory, threads, keyLen)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1 {
		return nil
	}

	return passwords.ErrInvalidPassword
}
