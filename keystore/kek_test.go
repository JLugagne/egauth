package keystore_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/JLugagne/egauth/keystore"
)

func validKEK(t *testing.T) *keystore.KEK {
	t.Helper()
	k, err := keystore.NewKEK(bytes.Repeat([]byte("k"), keystore.KEKKeyLength))
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	return k
}

func TestNewKEK_RejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		if _, err := keystore.NewKEK(bytes.Repeat([]byte("k"), n)); !errors.Is(err, keystore.ErrInvalidKEK) {
			t.Fatalf("len %d: want ErrInvalidKEK, got %v", n, err)
		}
	}
}

// testSecretContext is the context these round-trip tests seal and open under. Seal/Open now bind a
// SecretContext as AEAD associated data, so every call site names where the secret belongs.
var testSecretContext = keystore.SecretContext{
	TenantID: "acme",
	Purpose:  keystore.PurposeSigningKey,
	RowID:    "kid-1",
}

func TestKEK_SealOpenRoundTrip(t *testing.T) {
	k := validKEK(t)
	plaintext := []byte("super-secret-signing-material-32")
	sealed, err := k.Seal(testSecretContext, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(sealed, plaintext) {
		t.Fatal("sealed blob must differ from plaintext")
	}
	opened, err := k.Open(testSecretContext, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("round trip mismatch: got %q", opened)
	}
}

func TestKEK_SealIsNonDeterministic(t *testing.T) {
	k := validKEK(t)
	pt := []byte("same plaintext")
	a, _ := k.Seal(testSecretContext, pt)
	b, _ := k.Seal(testSecretContext, pt)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext must differ (random nonce)")
	}
}

func TestKEK_OpenRejectsTamperAndWrongKey(t *testing.T) {
	k := validKEK(t)
	sealed, _ := k.Seal(testSecretContext, []byte("payload"))

	// Tamper.
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := k.Open(testSecretContext, tampered); !errors.Is(err, keystore.ErrCiphertextCorrupt) {
		t.Fatalf("tampered: want ErrCiphertextCorrupt, got %v", err)
	}

	// Too short.
	if _, err := k.Open(testSecretContext, []byte{1, 2, 3}); !errors.Is(err, keystore.ErrCiphertextCorrupt) {
		t.Fatalf("short: want ErrCiphertextCorrupt, got %v", err)
	}

	// Wrong KEK.
	other, _ := keystore.NewKEK(bytes.Repeat([]byte("z"), keystore.KEKKeyLength))
	if _, err := other.Open(testSecretContext, sealed); !errors.Is(err, keystore.ErrCiphertextCorrupt) {
		t.Fatalf("wrong KEK: want ErrCiphertextCorrupt, got %v", err)
	}
}
