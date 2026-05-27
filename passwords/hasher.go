package passwords

import (
	"context"
)

// Hasher defines the contract for securely hashing and verifying passwords.
type Hasher interface {
	// Hash takes a plaintext password and returns its securely hashed representation.
	Hash(ctx context.Context, password string) (string, error)

	// Compare checks if a plaintext password matches the given hashed password.
	// It returns nil if they match, or an error (e.g., ErrInvalidPassword) if they don't.
	Compare(ctx context.Context, hash, password string) error
}
