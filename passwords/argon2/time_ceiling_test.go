package argon2_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/passwords"
	argon2hasher "github.com/JLugagne/egauth/passwords/argon2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompare_RejectsUnboundedIterationCount pins the CPU half of the verify-path threat model. A
// stored PHC string is untrusted (imports, migrations and hand-edited rows all reach Compare), and
// the parser reads the iteration count into a uint32, so a row carrying t=4294967295 would otherwise
// hand argon2.IDKey a value it cannot be interrupted out of. The memory parameter has had a ceiling
// for this exact reason; the iteration count had none.
func TestCompare_RejectsUnboundedIterationCount(t *testing.T) {
	h := argon2hasher.NewHasher()
	const salt = "AAECAwQFBgcICQoLDA0ODw"                      // 16 bytes
	const hash = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" // 32 bytes

	for _, iterations := range []string{"17", "100", "4294967295"} {
		crafted := "$argon2id$v=19$m=65536,t=" + iterations + ",p=1$" + salt + "$" + hash
		start := time.Now()
		err := h.Compare(context.Background(), crafted, "anypassword")
		elapsed := time.Since(start)

		assert.ErrorIs(t, err, passwords.ErrInvalidPassword,
			"t=%s must be refused as an opaque mismatch", iterations)
		assert.Less(t, elapsed, 2*time.Second,
			"t=%s must be refused BEFORE the KDF runs: an unbounded value would pin a core", iterations)
	}
}

// TestCompare_AcceptsCostsAtOrBelowTheCeiling is the control: the ceiling must not reject a hash a
// deployment could legitimately have stored.
func TestCompare_AcceptsCostsAtOrBelowTheCeiling(t *testing.T) {
	h := argon2hasher.NewHasher(argon2hasher.WithMemory(8 * 1024))
	// A genuinely hashed password at a low cost, so the round trip is exercised end to end.
	phc, err := h.Hash(context.Background(), "correct horse battery staple")
	require.NoError(t, err)

	require.NoError(t, h.Compare(context.Background(), phc, "correct horse battery staple"))
	assert.ErrorIs(t, h.Compare(context.Background(), phc, "wrong"), passwords.ErrInvalidPassword)
}

// TestMaxTimeIsAboveAnyLegitimateCost documents the bound's intent: it sits far above real
// parameters, so it only ever rejects a corrupt or hostile row.
func TestMaxTimeIsAboveAnyLegitimateCost(t *testing.T) {
	assert.GreaterOrEqual(t, argon2hasher.MaxTime, uint32(4),
		"the ceiling must clear ordinary parameter choices")
	assert.LessOrEqual(t, argon2hasher.MaxTime, uint32(64),
		"the ceiling must still bound the work a single request can be made to do")
}
