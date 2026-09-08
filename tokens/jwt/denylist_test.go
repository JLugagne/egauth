// Regression tests for SECRETS-01 (issue #104): the HS256 keys published in this
// repo's examples and SDK docs are publicly known on GitHub, yet both satisfy
// MinSecretKeyLength. The issuer must therefore reject them outright so a
// copy-pasted deployment fails fast instead of minting forgeable tokens.

package jwt_test

import (
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// publishedKeys are the exact literals that were published in the repo (the
// fullstack example and the SDK docs). Both pass the MinSecretKeyLength gate,
// which is why a dedicated denylist is required to reject them.
var publishedKeys = []string{
	"replace-with-a-32-byte-minimum-secret-in-production!",
	"super-secret-32-byte-key-here!!!",
	"a-high-entropy-secret-kept-out-of-source-control",
	"super-secret-key-change-me-in-production",
}

func TestNew_PanicsOnPublishedExampleKey(t *testing.T) {
	for _, key := range publishedKeys {
		t.Run("SecretKey", func(t *testing.T) {
			assert.Panics(t, func() {
				jwt.New[struct{}](jwt.Config[struct{}]{
					Store:      memory.NewStore[struct{}](),
					SecretKey:  key,
					Issuer:     "x",
					AccessTTL:  time.Minute,
					RefreshTTL: time.Hour,
				})
			}, "jwt.New must panic on the published example key")
		})

		t.Run("SigningKeys", func(t *testing.T) {
			assert.Panics(t, func() {
				jwt.New[struct{}](jwt.Config[struct{}]{
					Store:       memory.NewStore[struct{}](),
					SigningKeys: []jwt.SigningKey{{KeyID: "k1", Secret: key}},
					ActiveKeyID: "k1",
					Issuer:      "x",
					AccessTTL:   time.Minute,
					RefreshTTL:  time.Hour,
				})
			}, "jwt.New must panic on a published example key in SigningKeys")
		})

		t.Run("InsecureAllowWeakKey does not bypass the denylist", func(t *testing.T) {
			assert.Panics(t, func() {
				jwt.New[struct{}](jwt.Config[struct{}]{
					Store:                memory.NewStore[struct{}](),
					SecretKey:            key,
					Issuer:               "x",
					AccessTTL:            time.Minute,
					RefreshTTL:           time.Hour,
					InsecureAllowWeakKey: true,
				})
			}, "InsecureAllowWeakKey must not re-accept a published example key")
		})
	}
}

func TestNewHMACSigner_RejectsPublishedExampleKey(t *testing.T) {
	for _, key := range publishedKeys {
		_, err := jwt.NewHMACSigner("k1", []byte(key))
		require.Error(t, err, "NewHMACSigner must reject the published example key")
		assert.Contains(t, err.Error(), "published")
	}
}

func TestConfig_ValidateRejectsPublishedExampleKey(t *testing.T) {
	for _, key := range publishedKeys {
		err := jwt.Config[struct{}]{
			Store:      memory.NewStore[struct{}](),
			SecretKey:  key,
			Issuer:     "x",
			AccessTTL:  time.Minute,
			RefreshTTL: time.Hour,
		}.Validate()
		require.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "published"),
			"Validate should call out the published example key, got: %v", err)
	}
}
