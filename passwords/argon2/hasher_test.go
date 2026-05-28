package argon2_test

import (
	"context"
	"strings"
	"testing"

	"github.com/JLugagne/libauth/passwords"
	"github.com/JLugagne/libauth/passwords/hashertest"
	argon2hasher "github.com/JLugagne/libauth/passwords/argon2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArgon2Hasher_Contract(t *testing.T) {
	hasher := argon2hasher.NewHasher()
	hashertest.HasherContractTesting(t, hasher)
}

func TestArgon2Hasher_Format(t *testing.T) {
	ctx := context.Background()
	hasher := argon2hasher.NewHasher()
	password := "TestPassword123!"

	hash, err := hasher.Hash(ctx, password)
	require.NoError(t, err)

	parts := strings.Split(hash, "$")
	assert.Equal(t, 6, len(parts), "PHC string should have 6 parts separated by $")
	assert.Equal(t, "", parts[0], "First part should be empty")
	assert.Equal(t, "argon2id", parts[1], "Algorithm should be argon2id")
	assert.True(t, strings.HasPrefix(parts[2], "v="), "Version part should start with v=")
	assert.True(t, strings.HasPrefix(parts[3], "m="), "Params part should start with m=")
}

func TestArgon2Hasher_EdgeCases(t *testing.T) {
	ctx := context.Background()
	hasher := argon2hasher.NewHasher()

	t.Run("Empty password hash fails", func(t *testing.T) {
		_, err := hasher.Hash(ctx, "")
		assert.ErrorIs(t, err, passwords.ErrHashFailed)
	})

	t.Run("Invalid PHC format", func(t *testing.T) {
		err := hasher.Compare(ctx, "invalidhash", "password")
		assert.ErrorIs(t, err, passwords.ErrInvalidPassword)

		err = hasher.Compare(ctx, "$argon2id$v=19$m=65536,t=1,p=4$invalid_base64$hash", "password")
		assert.ErrorIs(t, err, passwords.ErrInvalidPassword)
	})

	t.Run("Unsupported algorithm", func(t *testing.T) {
		err := hasher.Compare(ctx, "$bcrypt$v=2b$10$salt$hash", "password")
		assert.ErrorIs(t, err, passwords.ErrInvalidPassword)
	})
}
