package passkey_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSECURITY_NamesRealChallengeStorePackages pins mfa/SF-4's documentation half: SECURITY.md
// pointed operators at a "passkey/pgx" package that has never existed, so the only implementation
// they could actually wire was the per-process in-memory one.
func TestSECURITY_NamesRealChallengeStorePackages(t *testing.T) {
	raw, err := os.ReadFile("../SECURITY.md")
	require.NoError(t, err)
	doc := string(raw)

	assert.False(t, strings.Contains(doc, "passkey/pgx`") || strings.Contains(doc, "`passkey/pgx"),
		"SECURITY.md must not point at the non-existent passkey/pgx package")
	assert.Contains(t, doc, "adapters/pgx/passkey",
		"SECURITY.md must name the package that actually provides the shared ChallengeStore")
}
