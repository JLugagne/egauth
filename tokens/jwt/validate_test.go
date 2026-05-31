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
}
