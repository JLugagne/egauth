package argon2_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/passwords"
	argon2hasher "github.com/JLugagne/egauth/passwords/argon2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestArgon2Hasher_EmptyPasswordSymmetry is a regression test for the timing-oracle
// finding (TASK-065): Hash() short-circuits on empty password but Compare() did not,
// creating a measurable timing difference that leaks account existence.
func TestArgon2Hasher_EmptyPasswordSymmetry(t *testing.T) {
	ctx := context.Background()

	// Build a hasher with minimal cost so the non-empty path runs quickly.
	hasher := argon2hasher.NewHasher(
		argon2hasher.WithMemory(8*4), // minimum: 8*threads KiB (threads=4 default)
		argon2hasher.WithTime(1),
	)

	// Produce a valid stored hash for a non-empty password.
	storedHash, err := hasher.Hash(ctx, "correct-horse-battery-staple")
	require.NoError(t, err)

	// Regression: TASK-065 — empty-password probe defeats decoy-hash enumeration defence.
	//
	// Hash() short-circuits on empty password (returns ErrHashFailed before any KDF work).
	// Before the fix, Compare() had no equivalent guard: it parsed the PHC string, checked
	// ctx.Err(), then called argon2.IDKey even when password=="".
	//
	// The deterministic probe: pass a pre-cancelled context together with password="".
	//   Without the fix: Compare parses params → ctx.Err() check fires → returns context.Canceled.
	//   With the fix:    empty-password guard fires first → returns ErrInvalidPassword immediately.
	//
	// assert.ErrorIs(t, err, passwords.ErrInvalidPassword) therefore FAILS before the fix
	// (got context.Canceled, not ErrInvalidPassword) and PASSES after.
	t.Run("empty password guard fires before context check (TASK-065 regression)", func(t *testing.T) {
		cancelledCtx, cancel := context.WithCancel(context.Background())
		cancel() // pre-cancel so ctx.Err() == context.Canceled from the start

		err := hasher.Compare(cancelledCtx, storedHash, "")
		// Must be ErrInvalidPassword: the empty-password guard must fire BEFORE ctx.Err() is
		// checked and BEFORE argon2 is invoked. Any other error means the guard is missing.
		assert.ErrorIs(t, err, passwords.ErrInvalidPassword,
			"Compare(\"\", ...) must return ErrInvalidPassword immediately; "+
				"got a different error, which means the empty-password guard is absent "+
				"and Compare fell through to the context-cancellation check or argon2")
	})

	t.Run("Hash also rejects empty password", func(t *testing.T) {
		_, err := hasher.Hash(ctx, "")
		assert.Error(t, err, "Hash must reject empty password")
	})

	t.Run("non-empty wrong password still fails normally through argon2", func(t *testing.T) {
		err := hasher.Compare(ctx, storedHash, "wrong-password")
		assert.ErrorIs(t, err, passwords.ErrInvalidPassword,
			"a wrong non-empty password must still fail with ErrInvalidPassword")
	})
}
