package argon2_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/passwords"
	argon2hasher "github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArgon2Hasher_Contract(t *testing.T) {
	hasher := argon2hasher.NewHasher()
	hashertest.HasherContractTesting(t, hasher)
}

// TestArgon2CostFloors proves that WithMemory/WithTime/WithThreads clamp a
// too-low cost UP to the documented safe floor (OWASP 2021) instead of
// producing a dangerously weak hasher. The floors are exported constants,
// referenced here at compile time.
func TestArgon2CostFloors(t *testing.T) {
	// Compile-time confirmation that the floors are exported and have the
	// documented values (CRYPTO-1 / OWASP 2021).
	require.Equal(t, uint32(19456), argon2hasher.MinMemoryKiB)
	require.Equal(t, uint32(1), argon2hasher.MinTime)
	require.Equal(t, uint8(1), argon2hasher.MinThreads)

	// Drive every option below its floor in one hasher; each parameter in the
	// produced PHC string must be at or above the floor.
	hasher := argon2hasher.NewHasher(
		argon2hasher.WithMemory(1),
		argon2hasher.WithTime(0),
		argon2hasher.WithThreads(0),
	)

	mem, tm, par := costParams(t, hasher)
	assert.GreaterOrEqual(t, mem, argon2hasher.MinMemoryKiB, "WithMemory(1) must clamp up to MinMemoryKiB")
	assert.GreaterOrEqual(t, tm, argon2hasher.MinTime, "WithTime(0) must clamp up to MinTime")
	assert.GreaterOrEqual(t, par, uint32(argon2hasher.MinThreads), "WithThreads(0) must clamp up to MinThreads")

	// Specifically, a sub-floor memory value lands exactly on the floor.
	assert.Equal(t, argon2hasher.MinMemoryKiB, mem, "sub-floor memory must clamp to the floor value")
}

// costParams hashes a fixed password and extracts the Argon2id m/t/p cost
// parameters from the PHC-formatted hash, mirroring how the other tests in
// this package inspect a hasher's effective cost (the struct fields are
// unexported).
func costParams(t *testing.T, hasher *argon2hasher.Hasher) (memory, time, threads uint32) {
	t.Helper()
	hash, err := hasher.Hash(context.Background(), "TestPassword123!")
	require.NoError(t, err)

	parts := strings.Split(hash, "$")
	require.Len(t, parts, 6)
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	require.NoError(t, err)
	return memory, time, threads
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

// TestArgon2Hasher_RejectsOversizedPassword guards against a pre-authentication
// CPU/memory amplification DoS: an unbounded attacker-controlled password must never reach
// argon2.IDKey (64MB, 4 threads). The hasher must reject it cheaply on both the Hash
// (registration / decoy) and Compare (login) paths.
func TestArgon2Hasher_RejectsOversizedPassword(t *testing.T) {
	ctx := context.Background()
	hasher := argon2hasher.NewHasher()

	oversized := strings.Repeat("a", 1<<20) // 1 MiB

	_, err := hasher.Hash(ctx, oversized)
	assert.ErrorIs(t, err, passwords.ErrPasswordTooLong)

	// Compare must also refuse to run the KDF on an oversized candidate. A stored hash can
	// only have come from an in-bounds password, so an oversized candidate cannot match; it
	// is reported as an ordinary credential mismatch (no enumeration signal).
	valid, err := hasher.Hash(ctx, "TestPassword123!")
	require.NoError(t, err)
	err = hasher.Compare(ctx, valid, oversized)
	assert.ErrorIs(t, err, passwords.ErrInvalidPassword)
}

// TestArgon2Hasher_HonorsContextCancellation confirms the (deliberately expensive) KDF is not
// run once the request's context is already cancelled: Hash/Compare must short-circuit with the
// context error before reaching argon2.IDKey, so a cancelled pre-auth request cannot still cost
// 64MB+CPU per attempt.
func TestArgon2Hasher_HonorsContextCancellation(t *testing.T) {
	hasher := argon2hasher.NewHasher()

	// A valid stored hash, produced before cancellation, so Compare reaches its guard.
	valid, err := hasher.Hash(context.Background(), "TestPassword123!")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = hasher.Hash(ctx, "TestPassword123!")
	assert.ErrorIs(t, err, context.Canceled)

	err = hasher.Compare(ctx, valid, "TestPassword123!")
	assert.ErrorIs(t, err, context.Canceled)
}

// TestArgon2Hasher_MalformedParamsDoNotPanic verifies that a stored PHC hash carrying
// out-of-range Argon2id parameters is rejected as an ordinary mismatch
// (passwords.ErrInvalidPassword) instead of crashing the process.
//
// golang.org/x/crypto v0.52.0 argon2.deriveKey panics on time<1
// ("argon2: number of rounds too small") and threads<1 ("argon2: parallelism degree
// too low"), and a keyLen==0 (empty final hash segment) triggers a nil-pointer panic
// inside extractKey/blake2bHash (blake2b.New(0,nil) returns a nil hash whose Write is
// then called). A memory below the per-thread minimum (8*threads KiB) is silently bumped
// by deriveKey, so the stored value cannot match what produced the hash — a corrupt row.
// All of these are reachable via a consumer-populated Identity.PasswordHash.
//
// Each valid-looking case below uses well-formed base64 salt/hash segments so the ONLY
// defect is the parameter under test (proving it is the bound check firing, not an
// earlier parse error). The empty-hash case legitimately has an empty segment.
func TestArgon2Hasher_MalformedParamsDoNotPanic(t *testing.T) {
	ctx := context.Background()
	hasher := argon2hasher.NewHasher()

	const (
		validSalt = "AAECAwQFBgcICQoLDA0ODw"                      // 16 bytes, RawStdEncoding
		validHash = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" // 32 bytes, RawStdEncoding
	)

	cases := []struct {
		name string
		hash string
	}{
		{
			name: "zero time would panic in deriveKey",
			hash: "$argon2id$v=19$m=65536,t=0,p=4$" + validSalt + "$" + validHash,
		},
		{
			name: "zero threads would panic in deriveKey",
			hash: "$argon2id$v=19$m=65536,t=1,p=0$" + validSalt + "$" + validHash,
		},
		{
			name: "empty final hash segment (keyLen==0) would panic in extractKey",
			hash: "$argon2id$v=19$m=65536,t=1,p=4$" + validSalt + "$",
		},
		{
			name: "memory below per-thread minimum is a corrupt hash",
			hash: "$argon2id$v=19$m=16,t=1,p=4$" + validSalt + "$" + validHash,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				err := hasher.Compare(ctx, tc.hash, "password")
				assert.ErrorIs(t, err, passwords.ErrInvalidPassword)
			})
		})
	}

	t.Run("well-formed hash from Hash still verifies", func(t *testing.T) {
		password := "TestPassword123!"
		good, err := hasher.Hash(ctx, password)
		require.NoError(t, err)
		require.NoError(t, hasher.Compare(ctx, good, password))
	})
}
