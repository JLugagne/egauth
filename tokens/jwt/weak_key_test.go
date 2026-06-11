// Package jwt_test contains regression tests for TASK-067.
// jwt.New must panic on a SecretKey or SigningKeys[].Secret shorter than
// MinSecretKeyLength (32 bytes), not only on an empty key.

package jwt_test

import (
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/stretchr/testify/assert"
)

// TestNew_PanicsOnWeakSecretKey is the regression test for TASK-067.
// Before the fix, jwt.New silently accepted any non-empty key regardless of
// length; only Config.Validate (an opt-in call) enforced MinSecretKeyLength.
func TestNew_PanicsOnWeakSecretKey(t *testing.T) {
	t.Run("single-key mode short SecretKey panics", func(t *testing.T) {
		assert.Panics(t, func() {
			jwt.New[struct{}](jwt.Config[struct{}]{
				SecretKey:  "too-short", // well under MinSecretKeyLength (32)
				Issuer:     "x",
				AccessTTL:  time.Minute,
				RefreshTTL: time.Hour,
			})
		}, "jwt.New must panic on a SecretKey shorter than MinSecretKeyLength")
	})

	t.Run("keyset mode short Secret panics", func(t *testing.T) {
		assert.Panics(t, func() {
			jwt.New[struct{}](jwt.Config[struct{}]{
				SigningKeys: []jwt.SigningKey{{KeyID: "k1", Secret: "tooshort"}},
				ActiveKeyID: "k1",
				Issuer:      "x",
				AccessTTL:   time.Minute,
				RefreshTTL:  time.Hour,
			})
		}, "jwt.New must panic on a SigningKeys entry with a Secret shorter than MinSecretKeyLength")
	})

	t.Run("InsecureAllowWeakKey bypasses the check", func(t *testing.T) {
		assert.NotPanics(t, func() {
			jwt.New[struct{}](jwt.Config[struct{}]{
				SecretKey:            "weak",
				Issuer:               "x",
				AccessTTL:            time.Minute,
				RefreshTTL:           time.Hour,
				InsecureAllowWeakKey: true,
			})
		}, "InsecureAllowWeakKey must suppress the weak-key panic for test code")
	})
}
