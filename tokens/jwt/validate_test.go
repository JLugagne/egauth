package jwt_test

import (
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_PanicsOnEmptySecretKey(t *testing.T) {
	assert.Panics(t, func() {
		jwt.New[struct{}](jwt.Config[struct{}]{
			SecretKey:  "",
			Issuer:     "x",
			AccessTTL:  time.Minute,
			RefreshTTL: time.Hour,
		})
	}, "constructing with an empty HMAC signing key must fail fast")
}

// TestNew_PanicsOnWeakTokenLength is the regression test for TASK-089.
// jwt.New must panic when RefreshLength or APIKeyLength is set below
// MinTokenLength, mirroring the existing MinSecretKeyLength enforcement.
func TestNew_PanicsOnWeakTokenLength(t *testing.T) {
	base := jwt.Config[struct{}]{
		SecretKey:            "0123456789abcdef0123456789abcdef", // 32 bytes
		Issuer:               "x",
		AccessTTL:            time.Minute,
		RefreshTTL:           time.Hour,
		InsecureAllowWeakKey: true,
	}

	t.Run("RefreshLength=8 panics", func(t *testing.T) {
		cfg := base
		cfg.RefreshLength = 8
		assert.Panics(t, func() { jwt.New[struct{}](cfg) },
			"jwt.New must panic when RefreshLength < MinTokenLength")
	})

	t.Run("APIKeyLength=8 panics", func(t *testing.T) {
		cfg := base
		cfg.APIKeyLength = 8
		assert.Panics(t, func() { jwt.New[struct{}](cfg) },
			"jwt.New must panic when APIKeyLength < MinTokenLength")
	})
}

func TestConfig_Validate(t *testing.T) {
	good := jwt.Config[struct{}]{
		SecretKey:  "0123456789abcdef0123456789abcdef", // 32 bytes
		Issuer:     "egauth",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	}
	require.NoError(t, good.Validate())

	mut := func(f func(*jwt.Config[struct{}])) jwt.Config[struct{}] {
		c := good
		f(&c)
		return c
	}

	assert.Error(t, mut(func(c *jwt.Config[struct{}]) { c.SecretKey = "" }).Validate(), "empty key")
	assert.Error(t, mut(func(c *jwt.Config[struct{}]) { c.SecretKey = "short" }).Validate(), "short key")
	assert.Error(t, mut(func(c *jwt.Config[struct{}]) { c.AccessTTL = 0 }).Validate(), "zero access TTL")
	assert.Error(t, mut(func(c *jwt.Config[struct{}]) { c.RefreshTTL = -1 }).Validate(), "non-positive refresh TTL")
	assert.Error(t, mut(func(c *jwt.Config[struct{}]) { c.Issuer = "" }).Validate(), "empty issuer")

	// TASK-089: RefreshLength and APIKeyLength must be validated for minimum entropy.
	assert.Error(t, mut(func(c *jwt.Config[struct{}]) { c.RefreshLength = 8 }).Validate(), "RefreshLength=8 must be rejected (< MinTokenLength)")
	assert.Error(t, mut(func(c *jwt.Config[struct{}]) { c.APIKeyLength = 8 }).Validate(), "APIKeyLength=8 must be rejected (< MinTokenLength)")
}
