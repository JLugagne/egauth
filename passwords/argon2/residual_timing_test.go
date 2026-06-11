// Regression coverage for TASK-081: residual enumeration timing channel.
//
// The decoy path used by the identity service hashes an unknown account's
// candidate password at the hasher's CURRENT configured cost (Hash uses
// h.memory/h.time/h.threads). The real verify path (Compare) runs Argon2id at
// the cost recorded IN THE STORED HASH. After an operator raises the cost,
// every not-yet-rehashed account verifies at the OLD (faster) cost while a
// non-existent account is decoy-hashed at the NEW (slower) cost, leaving a
// measurable timing gap that partially distinguishes "registered before the
// cost bump" from "unknown". This is a documented residual of rehash-on-login;
// the tests below pin the structural cause and assert the SECURITY.md contract
// describes it so operators know to rehash the fleet (or accept degraded
// enumeration-resistance) after raising cost.

package argon2_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	argon2hasher "github.com/JLugagne/egauth/passwords/argon2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResidualTiming_DecoyUsesCurrentCostNotStored reproduces the structural
// cause of the finding: a hash produced at the OLD (lower) cost still verifies,
// but the decoy path (Hash at the NEW target cost) bakes in the NEW parameters.
// The PHC cost segment of a fresh Hash therefore differs from the stored hash's
// cost segment, which is exactly the asymmetry that leaks timing.
func TestResidualTiming_DecoyUsesCurrentCostNotStored(t *testing.T) {
	ctx := context.Background()
	password := "TestPassword123!"

	// Account hashed before the operator raised cost.
	old := argon2hasher.NewHasher(
		argon2hasher.WithMemory(argon2hasher.MinMemoryKiB),
		argon2hasher.WithTime(1),
		argon2hasher.WithThreads(1),
	)
	oldHash, err := old.Hash(ctx, password)
	require.NoError(t, err)

	// Operator raises the configured cost (the documented upgrade).
	target := argon2hasher.NewHasher(
		argon2hasher.WithMemory(64*1024),
		argon2hasher.WithTime(3),
		argon2hasher.WithThreads(4),
	)

	// The old hash still verifies — Compare honours the STORED (lower) cost.
	require.NoError(t, target.Compare(ctx, oldHash, password))

	// The decoy path is Hash at the CURRENT target cost. Its cost segment is the
	// NEW (higher) parameters, not the stored hash's. This divergence is the
	// timing channel.
	decoyHash, err := target.Hash(ctx, password)
	require.NoError(t, err)

	oldCost := strings.Split(oldHash, "$")[3]
	decoyCost := strings.Split(decoyHash, "$")[3]
	assert.Equal(t, "m=19456,t=1,p=1", oldCost, "stored hash keeps its original (lower) cost")
	assert.Equal(t, "m=65536,t=3,p=4", decoyCost, "decoy hashes at the current (higher) cost")
	assert.NotEqual(t, oldCost, decoyCost,
		"decoy cost diverges from a pre-rehash stored hash's cost — this is the residual timing channel that must be documented")
}

// TestResidualTiming_DocumentedInSecurityMD asserts SECURITY.md explicitly
// documents the residual enumeration timing channel and the operator guidance
// (rehash the fleet after raising cost). This is the primary deliverable of
// TASK-081 and fails before the documentation is added.
func TestResidualTiming_DocumentedInSecurityMD(t *testing.T) {
	// Walk up from the package dir to the repository root (where SECURITY.md lives).
	wd, err := os.Getwd()
	require.NoError(t, err)
	root := wd
	var data []byte
	for {
		candidate := filepath.Join(root, "SECURITY.md")
		if b, readErr := os.ReadFile(candidate); readErr == nil {
			data = b
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatalf("SECURITY.md not found walking up from %s", wd)
		}
		root = parent
	}
	doc := strings.ToLower(string(data))

	// Must acknowledge that not-yet-rehashed accounts verify at the old cost
	// while the decoy hashes at the current cost (the asymmetry).
	assert.Contains(t, doc, "rehash",
		"SECURITY.md must mention rehash in the context of the residual timing channel")
	assert.Contains(t, doc, "decoy",
		"SECURITY.md must reference the decoy path when describing the residual channel")

	// Must contain a recognisable description of the residual enumeration timing
	// channel tied to a cost upgrade.
	hasResidual := strings.Contains(doc, "residual") &&
		(strings.Contains(doc, "enumeration") || strings.Contains(doc, "timing"))
	assert.True(t, hasResidual,
		"SECURITY.md must describe the residual enumeration/timing channel from raising Argon2id cost")

	// Must give the operator guidance to rehash the fleet (or accept degraded
	// resistance) after raising cost.
	hasGuidance := strings.Contains(doc, "raise") || strings.Contains(doc, "raising") || strings.Contains(doc, "increase")
	assert.True(t, hasGuidance,
		"SECURITY.md must advise operators about raising/increasing cost and rehashing the fleet")
}
