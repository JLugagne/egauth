package passwords

import (
	"context"
)

// MaxPasswordLength is the hard upper bound (in bytes) on a password accepted by a Hasher.
//
// Password-based KDFs such as Argon2id are deliberately expensive (the default hasher uses
// 64MB of memory). Running one over unbounded, attacker-controlled input is a
// pre-authentication CPU/memory amplification DoS, reachable even for non-existent accounts
// via the constant-time decoy-hashing path. Hashers MUST reject input longer than this
// before invoking the KDF. The bound is generous (well above the NIST SP 800-63B minimum of
// 64 characters) so it never constrains a legitimate password or passphrase.
const MaxPasswordLength = 1024

// Hasher defines the contract for securely hashing and verifying passwords.
type Hasher interface {
	// Hash takes a plaintext password and returns its securely hashed representation.
	Hash(ctx context.Context, password string) (string, error)

	// Compare checks if a plaintext password matches the given hashed password.
	// It returns nil if they match, or an error (e.g., ErrInvalidPassword) if they don't.
	Compare(ctx context.Context, hash, password string) error
}
