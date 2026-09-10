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

// triviallyKnownKeys are keys an attacker knows without stealing anything: all-zero bytes and a
// single byte value repeated for the whole key. Both satisfy MinSecretKeyLength, so the length
// gate alone cannot reject them.
var triviallyKnownKeys = map[string]string{
	"all zero":             string(make([]byte, jwt.MinSecretKeyLength)),
	"repeated single byte": strings.Repeat("A", jwt.MinSecretKeyLength),
}

func TestNew_PanicsOnAllZeroOrRepeatedKey(t *testing.T) {
	for name, key := range triviallyKnownKeys {
		t.Run(name+"/SecretKey", func(t *testing.T) {
			assert.Panics(t, func() {
				jwt.New[struct{}](jwt.Config[struct{}]{
					Store:      memory.NewStore[struct{}](),
					SecretKey:  key,
					Issuer:     "x",
					AccessTTL:  time.Minute,
					RefreshTTL: time.Hour,
				})
			}, "jwt.New must panic on a trivially known SecretKey")
		})

		t.Run(name+"/SigningKeys", func(t *testing.T) {
			assert.Panics(t, func() {
				jwt.New[struct{}](jwt.Config[struct{}]{
					Store:       memory.NewStore[struct{}](),
					SigningKeys: []jwt.SigningKey{{KeyID: "k1", Secret: key}},
					ActiveKeyID: "k1",
					Issuer:      "x",
					AccessTTL:   time.Minute,
					RefreshTTL:  time.Hour,
				})
			}, "jwt.New must panic on a trivially known SigningKeys secret")
		})
	}
}

// InsecureAllowWeakKey exists for test code with short keys. It must not re-accept an all-zero or
// repeated-byte key: trivially known material is attacker-forgeable regardless of length.
func TestNew_InsecureAllowWeakKeyDoesNotBypassAllZeroOrRepeatedKey(t *testing.T) {
	for name, key := range map[string]string{
		"all zero short":      string(make([]byte, 8)),
		"repeated byte short": strings.Repeat("z", 8),
		"repeated byte 32":    strings.Repeat("z", jwt.MinSecretKeyLength),
		"all zero 32":         string(make([]byte, jwt.MinSecretKeyLength)),
	} {
		t.Run(name, func(t *testing.T) {
			assert.Panics(t, func() {
				jwt.New[struct{}](jwt.Config[struct{}]{
					Store:                memory.NewStore[struct{}](),
					SecretKey:            key,
					Issuer:               "x",
					AccessTTL:            time.Minute,
					RefreshTTL:           time.Hour,
					InsecureAllowWeakKey: true,
				})
			}, "InsecureAllowWeakKey must not bypass the trivially-known-key rejection")
		})
	}
}

func TestNewHMACSigner_RejectsAllZeroOrRepeatedKey(t *testing.T) {
	for name, key := range triviallyKnownKeys {
		_, err := jwt.NewHMACSigner("k1", []byte(key))
		require.Errorf(t, err, "NewHMACSigner must reject the %s key", name)
		assert.Contains(t, err.Error(), "secret")
	}
}

func TestConfig_ValidateRejectsAllZeroOrRepeatedKey(t *testing.T) {
	t.Run("SecretKey", func(t *testing.T) {
		for name, key := range triviallyKnownKeys {
			err := jwt.Config[struct{}]{
				Store:      memory.NewStore[struct{}](),
				SecretKey:  key,
				Issuer:     "x",
				AccessTTL:  time.Minute,
				RefreshTTL: time.Hour,
			}.Validate()
			require.Errorf(t, err, "Validate must reject the %s SecretKey", name)
		}
	})

	t.Run("SigningKeys", func(t *testing.T) {
		for name, key := range triviallyKnownKeys {
			err := jwt.Config[struct{}]{
				Store:       memory.NewStore[struct{}](),
				SigningKeys: []jwt.SigningKey{{KeyID: "k1", Secret: key}},
				ActiveKeyID: "k1",
				Issuer:      "x",
				AccessTTL:   time.Minute,
				RefreshTTL:  time.Hour,
			}.Validate()
			require.Errorf(t, err, "Validate must reject the %s SigningKeys secret", name)
		}
	})
}
