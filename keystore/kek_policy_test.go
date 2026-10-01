package keystore_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/JLugagne/egauth/internal/secretpolicy"
	"github.com/JLugagne/egauth/keystore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// F-KS-001 regression: NewKEK is the only gate for the Key-Encryption-Key, so it must apply
// the shared credential policy and refuse trivially-known keys, published example literals
// and near-copies carrying a published-example marker. Accepting any of them voids envelope
// encryption: whoever reads a sealed row rebuilds the KEK from the public string and
// recovers every tenant signing secret.
func TestNewKEK_RejectsTrivialPublishedAndNearCopyKeys(t *testing.T) {
	cases := []struct {
		name       string
		key        []byte
		trivial    bool
		underlying error
	}{
		{"all zero", make([]byte, keystore.KEKKeyLength), true, nil},
		{"repeated byte", bytes.Repeat([]byte{0xAB}, keystore.KEKKeyLength), true, nil},
		{"published HS256 literal", []byte("super-secret-32-byte-key-here!!!"), false, secretpolicy.ErrPublished},
		{"published passkey literal", []byte("very-secure-32-byte-secret-key!!"), false, secretpolicy.ErrPublished},
		{"repo KEK fixture literal", []byte("kek-fixture-0123456789abcdefghij"), false, secretpolicy.ErrPublished},
		{"marker near-copy", []byte("minimum-hs256-signing-secret!!!!"), false, secretpolicy.ErrNearCopy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Len(t, tc.key, keystore.KEKKeyLength, "fixture must clear the length gate")

			kek, err := keystore.NewKEK(tc.key)
			require.Error(t, err, "NewKEK accepted attacker-known key material")
			require.Nil(t, kek)

			if tc.trivial {
				assert.ErrorIs(t, err, keystore.ErrTrivialKEK)
				assert.ErrorIs(t, err, secretpolicy.ErrTrivial)
				return
			}
			assert.ErrorIs(t, err, keystore.ErrPublishedKEK)
			assert.ErrorIs(t, err, tc.underlying)
		})
	}
}

// TestNewKEK_AcceptsRandomKeyAndRoundTrips is the control: a crypto/rand 32-byte key is
// accepted and Seal/Open still functions end to end.
func TestNewKEK_AcceptsRandomKeyAndRoundTrips(t *testing.T) {
	key := make([]byte, keystore.KEKKeyLength)
	_, err := rand.Read(key)
	require.NoError(t, err)

	kek, err := keystore.NewKEK(key)
	require.NoError(t, err)

	sealed, err := kek.Seal([]byte("tenant-signing-secret"), []byte("tenant-a"))
	require.NoError(t, err)
	opened, err := kek.Open(sealed, []byte("tenant-a"))
	require.NoError(t, err)
	assert.Equal(t, "tenant-signing-secret", string(opened))
}
