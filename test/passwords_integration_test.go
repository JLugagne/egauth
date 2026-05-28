package internal_test

import (
	"context"
	"testing"

	"github.com/JLugagne/libauth/passwords"
	argon2hasher "github.com/JLugagne/libauth/passwords/argon2"
	"github.com/JLugagne/libauth/passwords/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordLifecycleIntegration(t *testing.T) {
	ctx := context.Background()

	// Instantiate implementations
	p := policy.NewDefaultPolicy()
	h := argon2hasher.NewHasher()

	t.Run("Scenario: Valid password creation and verification", func(t *testing.T) {
		password := "StrongPassword123!"

		// 1. Verify policy
		err := p.Verify(ctx, password)
		require.NoError(t, err, "Password should pass policy")

		// 2. Hash password
		hash, err := h.Hash(ctx, password)
		require.NoError(t, err, "Password should be hashed successfully")
		require.NotEmpty(t, hash)

		// 3. Verify hash against password
		err = h.Compare(ctx, hash, password)
		require.NoError(t, err, "Compare should succeed for the correct password")
	})

	t.Run("Scenario: Invalid password fails policy check", func(t *testing.T) {
		weakPassword := "weak"

		// 1. Verify policy
		err := p.Verify(ctx, weakPassword)
		assert.Error(t, err, "Weak password should fail policy")
		assert.ErrorIs(t, err, passwords.ErrPasswordTooShort)
	})

	t.Run("Scenario: Compare fails for incorrect password", func(t *testing.T) {
		password := "StrongPassword123!"
		wrongPassword := "WrongPassword123!"

		// 1. Verify policy and hash
		err := p.Verify(ctx, password)
		require.NoError(t, err)

		hash, err := h.Hash(ctx, password)
		require.NoError(t, err)

		// 2. Compare against wrong password
		err = h.Compare(ctx, hash, wrongPassword)
		assert.Error(t, err, "Compare should fail for incorrect password")
		assert.ErrorIs(t, err, passwords.ErrInvalidPassword)
	})
}
