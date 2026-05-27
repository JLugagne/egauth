package hashertest

import (
	"context"
	"testing"

	"github.com/JLugagne/libauth/passwords"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockHasher is a function-based mock implementation of the passwords.Hasher interface.
// It allows flexible testing by injecting custom behavior for each method.
type MockHasher struct {
	HashFunc    func(ctx context.Context, password string) (string, error)
	CompareFunc func(ctx context.Context, hash, password string) error
}

var _ passwords.Hasher = (*MockHasher)(nil)

func (m *MockHasher) Hash(ctx context.Context, password string) (string, error) {
	if m.HashFunc == nil {
		panic("called not defined HashFunc")
	}
	return m.HashFunc(ctx, password)
}

func (m *MockHasher) Compare(ctx context.Context, hash, password string) error {
	if m.CompareFunc == nil {
		panic("called not defined CompareFunc")
	}
	return m.CompareFunc(ctx, hash, password)
}

// HasherContractTesting runs all contract tests for a passwords.Hasher implementation.
// Use this function to verify that an implementation adheres to the Hasher contract.
func HasherContractTesting(t *testing.T, hasher passwords.Hasher) {
	ctx := context.Background()

	t.Run("Contract: Hash and Compare success", func(t *testing.T) {
		password := "SuperSecretPassword123!"

		hash, err := hasher.Hash(ctx, password)
		require.NoError(t, err, "Hash should succeed for a valid password")
		require.NotEmpty(t, hash, "Hash must not be empty")

		err = hasher.Compare(ctx, hash, password)
		require.NoError(t, err, "Compare should succeed for the correct password")
	})

	t.Run("Contract: Compare fails for incorrect password", func(t *testing.T) {
		password := "SuperSecretPassword123!"
		wrongPassword := "WrongPassword123!"

		hash, err := hasher.Hash(ctx, password)
		require.NoError(t, err, "Hash should succeed")

		err = hasher.Compare(ctx, hash, wrongPassword)
		assert.Error(t, err, "Compare should fail for an incorrect password")
		assert.ErrorIs(t, err, passwords.ErrInvalidPassword, "Compare should return ErrInvalidPassword")
	})

	t.Run("Contract: Compare fails for tampered hash", func(t *testing.T) {
		password := "SuperSecretPassword123!"

		hash, err := hasher.Hash(ctx, password)
		require.NoError(t, err, "Hash should succeed")

		// Modify the hash slightly
		tamperedHash := hash + "tampered"

		err = hasher.Compare(ctx, tamperedHash, password)
		assert.Error(t, err, "Compare should fail for a tampered hash")
	})
}
