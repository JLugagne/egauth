package hashertest

import (
	"context"
	"errors"
	"testing"

	"github.com/JLugagne/egauth/passwords"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockHasher is a function-based mock of passwords.Hasher. T is required: a call whose function
// field is nil fails T, so an unexpected call never lets a test pass silently, and returns
// ErrUndefined. It is safe to call from any goroutine.
type MockHasher struct {
	T           testing.TB
	HashFunc    func(ctx context.Context, password string) (string, error)
	CompareFunc func(ctx context.Context, hash passwords.PHC, password string) error
}

var _ passwords.Hasher = (*MockHasher)(nil)

// ErrUndefined is returned by a MockHasher method whose function field is nil, after failing T.
var ErrUndefined = errors.New("hashertest: mock function is not defined")

// Hash calls HashFunc.
func (m *MockHasher) Hash(ctx context.Context, password string) (string, error) {
	if m.HashFunc == nil {
		m.T.Errorf("hashertest: MockHasher.Hash called but HashFunc is not defined")
		return "", ErrUndefined
	}
	return m.HashFunc(ctx, password)
}

// Compare calls CompareFunc.
func (m *MockHasher) Compare(ctx context.Context, hash passwords.PHC, password string) error {
	if m.CompareFunc == nil {
		m.T.Errorf("hashertest: MockHasher.Compare called but CompareFunc is not defined")
		return ErrUndefined
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

		err = hasher.Compare(ctx, passwords.PHC(hash), password)
		require.NoError(t, err, "Compare should succeed for the correct password")
	})

	t.Run("Contract: Compare fails for incorrect password", func(t *testing.T) {
		password := "SuperSecretPassword123!"
		wrongPassword := "WrongPassword123!"

		hash, err := hasher.Hash(ctx, password)
		require.NoError(t, err, "Hash should succeed")

		err = hasher.Compare(ctx, passwords.PHC(hash), wrongPassword)
		assert.Error(t, err, "Compare should fail for an incorrect password")
		assert.ErrorIs(t, err, passwords.ErrInvalidPassword, "Compare should return ErrInvalidPassword")
	})

	t.Run("Contract: Compare fails for tampered hash", func(t *testing.T) {
		password := "SuperSecretPassword123!"

		hash, err := hasher.Hash(ctx, password)
		require.NoError(t, err, "Hash should succeed")

		tamperedHash := hash + "tampered"

		err = hasher.Compare(ctx, passwords.PHC(tamperedHash), password)
		assert.Error(t, err, "Compare should fail for a tampered hash")
	})
}
