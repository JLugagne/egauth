package argon2_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/JLugagne/egauth/passwords"
	argon2hasher "github.com/JLugagne/egauth/passwords/argon2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

// phc builds a GENUINE PHC string for the given cost parameters, so a test can assert that a
// parameter set is still ACCEPTED (Compare returns nil) and not merely rejected as a mismatch.
func phc(password string, memory, iterations uint32, threads uint8, saltLen, keyLen uint32) string {
	salt := make([]byte, saltLen)
	for i := range salt {
		salt[i] = byte(i)
	}
	sum := argon2.IDKey([]byte(password), salt, iterations, memory, threads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, iterations, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum))
}

// tamperedPHC keeps the salt/hash segments of a cheap genuine hash but rewrites the cost line, so
// the string is structurally valid and only its ATTACKER-INFLUENCED parameters are out of range.
func tamperedPHC(memory, iterations uint32, threads uint8) string {
	const (
		salt = "AAECAwQFBgcICQoLDA0ODw"                      // 16 bytes
		hash = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" // 32 bytes
	)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, iterations, threads, salt, hash)
}

// TestCompare_RejectsUnboundedIterationCount is the proof of the finding: the verify path capped
// the MEMORY parameter read from a stored hash but not the ITERATION count, so a single tampered
// row (or a hostile import) turned every login attempt for that account into an arbitrarily long
// Argon2id run. The rejection must happen before the KDF, which is what the deadline measures:
// m=19456,t=200000 is minutes of CPU, so a Compare that still reaches argon2.IDKey cannot return
// inside the budget.
func TestCompare_RejectsUnboundedIterationCount(t *testing.T) {
	ctx := context.Background()
	hasher := argon2hasher.NewHasher()
	crafted := tamperedPHC(argon2hasher.MinMemoryKiB, 200000, 1)

	done := make(chan error, 1)
	go func() { done <- hasher.Compare(ctx, crafted, "anypassword") }()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, passwords.ErrInvalidPassword,
			"an out-of-range iteration count must be reported as an ordinary mismatch")
	case <-time.After(3 * time.Second):
		t.Fatal("Compare ran the KDF with a tampered iteration count: it must reject t out of range before argon2.IDKey")
	}
}

func TestCompare_TamperedCostParameters(t *testing.T) {
	ctx := context.Background()
	hasher := argon2hasher.NewHasher()

	cases := []struct {
		name    string
		hash    string
		wantErr bool
	}{
		{"iterations above the ceiling", tamperedPHC(argon2hasher.MinMemoryKiB, argon2hasher.MaxTime+1, 1), true},
		{"iterations at uint32 max", tamperedPHC(argon2hasher.MinMemoryKiB, ^uint32(0), 1), true},
		{"threads above the ceiling", tamperedPHC(argon2hasher.MaxMemoryKiB, 1, argon2hasher.MaxThreads+1), true},
		{"memory above the ceiling", tamperedPHC(argon2hasher.MaxMemoryKiB+1, 1, 1), true},
		{"zero iterations", tamperedPHC(argon2hasher.MinMemoryKiB, 0, 1), true},
		{"zero threads", tamperedPHC(argon2hasher.MinMemoryKiB, 1, 0), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				err := hasher.Compare(ctx, tc.hash, "anypassword")
				if tc.wantErr {
					assert.ErrorIs(t, err, passwords.ErrInvalidPassword)
				}
			})
		})
	}
}

// TestCompare_AcceptsParametersAtTheCeiling proves the caps do not lock legitimate stored hashes
// out: a genuine hash minted exactly at each ceiling still verifies. The memory parameter is kept
// small here on purpose — this test is about the newly capped parameters, not about allocating the
// 512 MiB the memory ceiling allows.
func TestCompare_AcceptsParametersAtTheCeiling(t *testing.T) {
	ctx := context.Background()
	hasher := argon2hasher.NewHasher()
	const pw = "correct-horse-battery-staple"

	cases := []struct {
		name string
		hash string
	}{
		{"iterations at the ceiling", phc(pw, argon2hasher.MinMemoryKiB, argon2hasher.MaxTime, 1, 16, 32)},
		{"threads at the ceiling", phc(pw, argon2hasher.MinMemoryKiB, 1, argon2hasher.MaxThreads, 16, 32)},
		{"key length at the ceiling", phc(pw, argon2hasher.MinMemoryKiB, 1, 1, 16, argon2hasher.MaxKeyLen)},
		{"salt length at the ceiling", phc(pw, argon2hasher.MinMemoryKiB, 1, 1, argon2hasher.MaxSaltLen, 32)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, hasher.Compare(ctx, tc.hash, pw), "a genuine hash at the ceiling must still verify")
			assert.ErrorIs(t, hasher.Compare(ctx, tc.hash, "wrong-password"), passwords.ErrInvalidPassword)
		})
	}
}

// TestCompare_RejectsOversizedDerivedSegments covers the two length parameters that are also read
// from the stored row: an oversized final hash segment (keyLen) and an oversized salt both scale
// the KDF's work and allocation.
func TestCompare_RejectsOversizedDerivedSegments(t *testing.T) {
	ctx := context.Background()
	hasher := argon2hasher.NewHasher()
	const pw = "correct-horse-battery-staple"

	oversizedKey := phc(pw, argon2hasher.MinMemoryKiB, 1, 1, 16, argon2hasher.MaxKeyLen+1)
	assert.ErrorIs(t, hasher.Compare(ctx, oversizedKey, pw), passwords.ErrInvalidPassword,
		"a stored hash whose derived-key segment exceeds MaxKeyLen must be rejected")

	oversizedSalt := phc(pw, argon2hasher.MinMemoryKiB, 1, 1, argon2hasher.MaxSaltLen+1, 32)
	assert.ErrorIs(t, hasher.Compare(ctx, oversizedSalt, pw), passwords.ErrInvalidPassword,
		"a stored hash whose salt segment exceeds MaxSaltLen must be rejected")
}
