package keystore_test

import (
	"bytes"
	"testing"

	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/keystore/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewKEK_RejectsTrivialKey pins the key-quality gate. The KEK exists so that a leaked database
// dump is not enough to recover signing material — the attacker also needs the key. An all-zero or
// repeated-byte key passes the length gate, encryption still succeeds, and everything appears to
// work, which is exactly what makes the mistake survive to production. make([]byte, 32) from a
// forgotten crypto/rand read is the shape this catches.
func TestNewKEK_RejectsTrivialKey(t *testing.T) {
	trivial := map[string][]byte{
		"all zero":           make([]byte, keystore.KEKKeyLength),
		"repeated 0xff":      bytes.Repeat([]byte{0xff}, keystore.KEKKeyLength),
		"repeated ASCII 'k'": bytes.Repeat([]byte("k"), keystore.KEKKeyLength),
	}
	for name, key := range trivial {
		t.Run(name, func(t *testing.T) {
			kek, err := keystore.NewKEK(key)
			assert.Nil(t, kek)
			assert.ErrorIs(t, err, keystore.ErrTrivialKEK,
				"a trivially-known KEK must be refused, not silently accepted")
		})
	}
}

// TestNewKEK_AcceptingARealKey is the control: a key with real entropy still works, and the
// envelope round trip still functions.
func TestNewKEK_AcceptingARealKey(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	kek, err := keystore.NewKEK(key)
	require.NoError(t, err)
	require.NotNil(t, kek)

	sealed, err := kek.Seal([]byte("tenant-signing-secret"), []byte("tenant-a"))
	require.NoError(t, err)
	opened, err := kek.Open(sealed, []byte("tenant-a"))
	require.NoError(t, err)
	assert.Equal(t, "tenant-signing-secret", string(opened))
}

// TestTrivialKeyIsNotMerelyAWeakKey documents the boundary: a key that is one byte away from a
// trivial one is accepted (it is a weak key an operator should replace, but detecting that is not
// this gate's job), while the fully-constant shapes are refused.
func TestTrivialKeyIsNotMerelyAWeakKey(t *testing.T) {
	nearly := bytes.Repeat([]byte("k"), keystore.KEKKeyLength)
	nearly[len(nearly)-1] = 'x'
	_, err := keystore.NewKEK(nearly)
	assert.NoError(t, err, "only fully-constant keys are refused; near-constant ones are an operator concern")
}

// TestNewManagerStillRefusesANilKEK keeps the existing requirement visible next to the new one.
func TestNewManagerStillRefusesANilKEK(t *testing.T) {
	_, err := keystore.NewManager(memory.New(), nil)
	assert.ErrorIs(t, err, keystore.ErrKEKRequired)
}
