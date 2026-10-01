package argon2_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/JLugagne/egauth/passwords"
	argon2hasher "github.com/JLugagne/egauth/passwords/argon2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// F-PWD-001 regression: Hash and Compare must agree on the acceptable cost-parameter range.
// The generation path accepted cost options above MaxTime/MaxMemoryKiB and emitted PHC
// strings the same hasher could never verify, a silent and persistent account lockout that
// even a configuration rollback could not heal (the unusable parameters are stored in the
// hash). The options now clamp to the verify-path ceilings, so every accepted configuration
// round-trips.
func TestHashOutputMustVerifyAboveCeilings(t *testing.T) {
	ctx := context.Background()
	const password = "CorrectHorseBatteryStaple-2026!"

	cases := []struct {
		name      string
		h         *argon2hasher.Hasher
		wantParam string
	}{
		{
			name: "iterations above MaxTime",
			h: argon2hasher.NewHasher(
				argon2hasher.WithTime(argon2hasher.MaxTime+1),
				argon2hasher.WithMemory(argon2hasher.MinMemoryKiB),
				argon2hasher.WithThreads(1),
			),
			wantParam: fmt.Sprintf("t=%d", argon2hasher.MaxTime),
		},
		{
			name: "memory above MaxMemoryKiB",
			h: argon2hasher.NewHasher(
				argon2hasher.WithMemory(argon2hasher.MaxMemoryKiB+1),
				argon2hasher.WithTime(1),
				argon2hasher.WithThreads(1),
			),
			wantParam: fmt.Sprintf("m=%d", argon2hasher.MaxMemoryKiB),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			phc, err := tc.h.Hash(ctx, password)
			require.NoError(t, err, "Hash must succeed for a valid password")

			assert.Contains(t, phc, tc.wantParam,
				"the generation path must clamp the over-ceiling option to the verify-path ceiling")

			assert.NoError(t, tc.h.Compare(ctx, phc, password),
				"Hash produced a PHC string the same hasher cannot verify; stored hash: %s", phc)
			assert.NotErrorIs(t, tc.h.Compare(ctx, phc, password), passwords.ErrInvalidPassword,
				"Compare must not report its own Hash output as an invalid password")
		})
	}
}

// TestHashAboveCeilingSurvivesConfigRevert demonstrates the persistence the fix removes: a
// hash minted under an over-ceiling option must still verify against a hasher restored to
// the default range, because it is now minted within the verifiable range.
func TestHashAboveCeilingSurvivesConfigRevert(t *testing.T) {
	ctx := context.Background()
	const password = "CorrectHorseBatteryStaple-2026!"

	overCeiling := argon2hasher.NewHasher(
		argon2hasher.WithTime(argon2hasher.MaxTime+1),
		argon2hasher.WithMemory(argon2hasher.MinMemoryKiB),
		argon2hasher.WithThreads(1),
	)
	phc, err := overCeiling.Hash(ctx, password)
	require.NoError(t, err)

	reverted := argon2hasher.NewHasher()
	assert.NoError(t, reverted.Compare(ctx, phc, password),
		"reverting the hasher configuration must recover hashes minted above the ceiling")
}
