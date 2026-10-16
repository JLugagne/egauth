package argon2_test

import (
	"context"
	"fmt"
	"github.com/JLugagne/egauth/passwords"
	"strings"
	"testing"

	argon2hasher "github.com/JLugagne/egauth/passwords/argon2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestArgon2Hasher_NewHasherDefaultsUnchanged confirms that NewHasher() with no
// options still produces hashes with the historical default cost parameters
// (m=65536, t=1, p=4) so the SEC-10 floor work is backward compatible.
func TestArgon2Hasher_NewHasherDefaultsUnchanged(t *testing.T) {
	ctx := context.Background()
	hasher := argon2hasher.NewHasher()

	hash, err := hasher.Hash(ctx, "TestPassword123!")
	require.NoError(t, err)

	parts := strings.Split(hash, "$")
	require.Len(t, parts, 6)
	assert.Equal(t, "m=65536,t=1,p=4", parts[3], "NewHasher() must keep historical defaults")
}

// TestArgon2Hasher_WithParams confirms the functional options override the
// cost parameters baked into the produced hash.
func TestArgon2Hasher_WithParams(t *testing.T) {
	ctx := context.Background()
	hasher := argon2hasher.NewTunedHasher(argon2hasher.Params{MemoryKiB: 128 * 1024, Time: 3, Threads: 2})

	hash, err := hasher.Hash(ctx, "TestPassword123!")
	require.NoError(t, err)

	parts := strings.Split(hash, "$")
	require.Len(t, parts, 6)
	assert.Equal(t, "m=131072,t=3,p=2", parts[3], "Params must be honored")
}

// TestArgon2Hasher_NeedsRehash_WeakHash verifies that a hash produced with
// deliberately weak cost is flagged for rehash by a hasher configured at the
// stronger default target, while a hash produced at the target is not.
func TestArgon2Hasher_NeedsRehash_WeakHash(t *testing.T) {
	ctx := context.Background()

	weak := argon2hasher.NewTunedHasher(argon2hasher.Params{MemoryKiB: 8 * 1024, Time: 1, Threads: 1})
	target := argon2hasher.NewHasher()

	weakHash, err := weak.Hash(ctx, "TestPassword123!")
	require.NoError(t, err)
	// Sanity: the weak hash must still verify.
	require.NoError(t, target.Compare(ctx, passwords.PHC(weakHash), "TestPassword123!"))

	assert.True(t, target.NeedsRehash(weakHash), "a weak imported hash must need rehash")

	strongHash, err := target.Hash(ctx, "TestPassword123!")
	require.NoError(t, err)
	assert.False(t, target.NeedsRehash(strongHash), "a hash at target cost must not need rehash")
}

// TestArgon2Hasher_NeedsRehash_Malformed verifies that a malformed or
// foreign-format hash is flagged for rehash on next successful login.
func TestArgon2Hasher_NeedsRehash_Malformed(t *testing.T) {
	target := argon2hasher.NewHasher()

	cases := []string{
		"",
		"not-a-phc-string",
		"$argon2id$v=19$m=65536,t=1,p=4$onlyfourfields",
		"$bcrypt$v=19$m=65536,t=1,p=4$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		"$argon2id$v=19$m=bad,t=1,p=4$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
	}
	for i, h := range cases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			assert.True(t, target.NeedsRehash(h), "malformed/foreign hash must be flagged for rehash")
		})
	}
}

// TestArgon2Hasher_RehashRoundTrip exercises the standard rehash-on-login flow:
// verify, detect weakness, re-hash, and confirm the new hash no longer needs it.
func TestArgon2Hasher_RehashRoundTrip(t *testing.T) {
	ctx := context.Background()
	target := argon2hasher.NewHasher()
	password := "TestPassword123!"

	// 1. A hash made at target verifies and does not need rehash.
	strong, err := target.Hash(ctx, password)
	require.NoError(t, err)
	require.NoError(t, target.Compare(ctx, passwords.PHC(strong), password))
	assert.False(t, target.NeedsRehash(strong))

	// 2. A weak hash verifies but needs rehash.
	weak := argon2hasher.NewTunedHasher(argon2hasher.Params{MemoryKiB: 8 * 1024})
	weakHash, err := weak.Hash(ctx, password)
	require.NoError(t, err)
	require.NoError(t, target.Compare(ctx, passwords.PHC(weakHash), password))
	require.True(t, target.NeedsRehash(weakHash))

	// 3. Re-hash with the target, then it no longer needs rehash.
	rehashed, err := target.Hash(ctx, password)
	require.NoError(t, err)
	require.NoError(t, target.Compare(ctx, passwords.PHC(rehashed), password))
	assert.False(t, target.NeedsRehash(rehashed))
}

func TestNewTunedHasherZeroFieldsKeepTheDefaults(t *testing.T) {
	ctx := context.Background()
	phc, err := argon2hasher.NewTunedHasher(argon2hasher.Params{Time: 2}).Hash(ctx, "TestPassword123!")
	require.NoError(t, err)
	assert.Equal(t, "m=65536,t=2,p=4", strings.Split(phc, "$")[3])
}
