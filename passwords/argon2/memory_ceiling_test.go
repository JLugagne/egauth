package argon2_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/passwords"
	argon2hasher "github.com/JLugagne/egauth/passwords/argon2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestArgon2Hasher_CompareRejectsOversizedMemory is the regression test for the
// OOM DoS finding: Compare must reject a PHC string whose memory parameter
// exceeds MaxMemoryKiB before ever calling argon2.IDKey, so a tampered or
// corrupt stored hash cannot trigger a multi-GiB/TiB allocation.
//
// The crafted PHC string below is syntactically valid (correct argon2id
// identifier, version, well-formed base64 salt and hash segments) — the only
// defect is memory=999999999 (~953 GiB), which is far above any legitimate
// cost configuration. The expected return is ErrInvalidPassword (not a panic,
// not an OOM kill).
func TestArgon2Hasher_CompareRejectsOversizedMemory(t *testing.T) {
	ctx := context.Background()
	hasher := argon2hasher.NewHasher()

	const (
		validSalt = "AAECAwQFBgcICQoLDA0ODw"                      // 16 bytes, RawStdEncoding
		validHash = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" // 32 bytes, RawStdEncoding
	)

	// 999999999 KiB ≈ 953 GiB — well above MaxMemoryKiB; must be rejected before KDF.
	crafted := "$argon2id$v=19$m=999999999,t=1,p=1$" + validSalt + "$" + validHash

	require.NotPanics(t, func() {
		err := hasher.Compare(ctx, crafted, "anypassword")
		assert.ErrorIs(t, err, passwords.ErrInvalidPassword,
			"Compare must reject memory=999999999 as ErrInvalidPassword, not attempt argon2.IDKey")
	})

	// Sanity: the exported ceiling constant must be reachable by callers.
	assert.Greater(t, argon2hasher.MaxMemoryKiB, argon2hasher.MinMemoryKiB,
		"MaxMemoryKiB must be greater than MinMemoryKiB")
}
