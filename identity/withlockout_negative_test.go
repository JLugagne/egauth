package identity_test

// Regression test for CLUSTER 2 / DEFECT 1: WithLockout with a NEGATIVE threshold must NOT
// disable brute-force lockout. SECURITY.md and the WithLockout godoc both claim a non-positive
// threshold falls back to the safe default; only WithNoLockout may disable the gate.
//
// Prior to the fix, NewService's normalization switch mapped ANY negative threshold (not just
// the WithNoLockout sentinel) to the internal "disabled" value, so WithLockout(-1, ...) silently
// turned off lockout.

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWithLockout_NegativeThreshold_UsesDefault verifies that WithLockout(-1, duration) does NOT
// disable lockout — it must fall back to the safe DefaultLockThreshold, matching the documented
// contract in SECURITY.md and the WithLockout godoc.
func TestWithLockout_NegativeThreshold_UsesDefault(t *testing.T) {
	svc, email, _ := buildLockoutService(identity.WithLockout(-1, time.Hour))
	ctx := context.Background()

	for range identity.DefaultLockThreshold {
		_, err := svc.Authenticate(ctx, "", "password", email, "wrong")
		require.ErrorIs(t, err, identity.ErrInvalidCredentials)
	}

	_, err := svc.Authenticate(ctx, "", "password", email, "wrong")
	assert.ErrorIs(t, err, identity.ErrAccountLocked,
		"WithLockout(-1, ...) must not disable lockout; account must be locked after DefaultLockThreshold failures")
}
