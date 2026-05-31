package offline_test

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/breach/offline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sha1Upper(s string) string {
	sum := sha1.Sum([]byte(s))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func TestLoadPasswords(t *testing.T) {
	src := "password\nletmein\n  hunter2  \n\n# not-a-comment-here\n"
	c, err := offline.LoadPasswords(strings.NewReader(src))
	require.NoError(t, err)

	ctx := context.Background()
	for _, breached := range []string{"password", "letmein", "hunter2"} {
		got, err := c.IsBreached(ctx, breached)
		require.NoError(t, err)
		assert.True(t, got, "%q was loaded and must be reported breached", breached)
	}
	got, err := c.IsBreached(ctx, "a-password-not-in-the-list")
	require.NoError(t, err)
	assert.False(t, got)
}

func TestLoadHashes_PlainAndWithCount(t *testing.T) {
	// HIBP offline format is "<SHA1 hex>:<count>"; bare hashes must also load.
	breachedPw := "correct horse battery staple"
	otherPw := "letmein"
	src := strings.Join([]string{
		sha1Upper(breachedPw) + ":1234",
		strings.ToLower(sha1Upper(otherPw)), // bare, lowercase — must normalize
	}, "\n")

	c, err := offline.LoadHashes(strings.NewReader(src))
	require.NoError(t, err)

	ctx := context.Background()
	for _, pw := range []string{breachedPw, otherPw} {
		got, err := c.IsBreached(ctx, pw)
		require.NoError(t, err)
		assert.True(t, got, "%q must be reported breached", pw)
	}
	got, err := c.IsBreached(ctx, "totally-different-secret")
	require.NoError(t, err)
	assert.False(t, got)
}

func TestLoadHashes_Threshold(t *testing.T) {
	pw := "seen-thrice"
	src := sha1Upper(pw) + ":3"
	c, err := offline.LoadHashes(strings.NewReader(src), offline.WithThreshold(5))
	require.NoError(t, err)

	got, err := c.IsBreached(context.Background(), pw)
	require.NoError(t, err)
	assert.False(t, got, "count 3 is below threshold 5, so a bare/under-threshold hash is not loaded as breached")
}

func TestLoadHashes_RejectsMalformed(t *testing.T) {
	_, err := offline.LoadHashes(strings.NewReader("not-a-valid-sha1-hash\n"))
	require.Error(t, err)
}

var _ passwords.BreachChecker = (*offline.Checker)(nil)
