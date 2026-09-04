package keystore_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/keystore/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestKEK_SealOpenRoundTrip(t *testing.T) {
	k := validKEK(t)
	plaintext := []byte("super-secret-signing-material-32")
	sealed, err := k.Seal(plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(sealed, plaintext) {
		t.Fatal("sealed blob must differ from plaintext")
	}
	opened, err := k.Open(sealed)
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
	a, _ := k.Seal(pt)
	b, _ := k.Seal(pt)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext must differ (random nonce)")
	}
}

func TestKEK_OpenRejectsTamperAndWrongKey(t *testing.T) {
	k := validKEK(t)
	sealed, _ := k.Seal([]byte("payload"))

	// Tamper.
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := k.Open(tampered); !errors.Is(err, keystore.ErrCiphertextCorrupt) {
		t.Fatalf("tampered: want ErrCiphertextCorrupt, got %v", err)
	}

	// Too short.
	if _, err := k.Open([]byte{1, 2, 3}); !errors.Is(err, keystore.ErrCiphertextCorrupt) {
		t.Fatalf("short: want ErrCiphertextCorrupt, got %v", err)
	}

	// Wrong KEK.
	other, _ := keystore.NewKEK(bytes.Repeat([]byte("z"), keystore.KEKKeyLength))
	if _, err := other.Open(sealed); !errors.Is(err, keystore.ErrCiphertextCorrupt) {
		t.Fatalf("wrong KEK: want ErrCiphertextCorrupt, got %v", err)
	}
}

// TestKEK_MissingAAD_CrossTenantKeyTransposition confirms SEC-TOK-01 (CVSS 8.3).
//
// Security invariant:
// In a KEK-encrypted multi-tenant environment, a secret sealed for Tenant A
// MUST be cryptographically bound to its tenant via Authenticated Associated Data (AAD).
// Any attempt to open or resolve that secret under the identity of Tenant B
// MUST fail with an integrity error (ErrCiphertextCorrupt), preventing
// any key substitution or cross-tenant privilege escalation.
//
// Current vulnerable behaviour:
// KEK.Seal and KEK.Open call aead.Seal and aead.Open with a nil AAD.
// Because the ciphertext is bound to neither tenantID nor keyID, an attacker who can substitute
// Tenant A's ciphertext into Tenant B's record sees that secret successfully decrypted
// by Tenant B's Manager. Tenant B thereby obtains Tenant A's signing key
// and can forge tokens on behalf of Tenant A.
func TestKEK_MissingAAD_CrossTenantKeyTransposition(t *testing.T) {
	ctx := context.Background()
	k := validKEK(t)
	memStore := memory.New()
	mgr, err := keystore.NewManager(memStore, k)
	require.NoError(t, err)

	// 1. Provision Tenant A and retrieve its active key
	err = mgr.ProvisionTenant(ctx, "tenant-a")
	require.NoError(t, err)

	keyA, err := mgr.ActiveSigningKey(ctx, "tenant-a")
	require.NoError(t, err)

	// 2. Retrieve the sealed ciphertext stored for Tenant A
	keysA, err := memStore.VerificationKeys(ctx, "tenant-a")
	require.NoError(t, err)
	sealedCiphertextA := keysA[keyA.KeyID].Secret

	// 3. Simulate the malicious transposition of Tenant A's ciphertext into Tenant B's record
	err = memStore.CreateTenant(ctx, "tenant-b", keystore.SigningKey{
		KeyID:    "transposed-key-b",
		TenantID: "tenant-b",
		Alg:      keystore.AlgHS256,
		Secret:   sealedCiphertextA,
	})
	require.NoError(t, err)

	// 4. SECURITY INVARIANT VIOLATED:
	// Resolving the key for Tenant B must fail because the ciphertext does not belong to Tenant B
	keyB, err := mgr.ActiveSigningKey(ctx, "tenant-b")
	require.ErrorIs(t, err, keystore.ErrCiphertextCorrupt,
		"SEC-TOK-01: KEK decryption of a secret sealed under a different tenant must fail due to AAD mismatch")
	assert.Nil(t, keyB.Secret, "no secret must be disclosed in case of cross-tenant transposition")
}
