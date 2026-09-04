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
// Invariant de sécurité :
// Dans un environnement multi-tenant chiffré par KEK, un secret scellé pour le Tenant A
// DOIT être cryptographiquement lié à son tenant via des données associées authentifiées (AAD).
// Une tentative d'ouverture ou de résolution de ce secret sous l'identité d'un Tenant B
// DOIT impérativement échouer avec une erreur d'intégrité (ErrCiphertextCorrupt), interdisant
// toute substitution de clé ou élévation de privilèges inter-tenant.
//
// Comportement vulnérable actuel :
// KEK.Seal et KEK.Open appellent aead.Seal et aead.Open avec un AAD nul (nil).
// Le ciphertext n'étant lié ni au tenantID ni au keyID, un attaquant capable de substituer
// le ciphertext du Tenant A dans le profil du Tenant B voit ce secret déchiffré avec succès
// par le Manager du Tenant B. Le Tenant B obtient ainsi la clé de signature du Tenant A
// et peut forger des jetons au nom du Tenant A.
func TestKEK_MissingAAD_CrossTenantKeyTransposition(t *testing.T) {
	ctx := context.Background()
	k := validKEK(t)
	memStore := memory.New()
	mgr, err := keystore.NewManager(memStore, k)
	require.NoError(t, err)

	// 1. Provisionner le Tenant A et récupérer sa clé active
	err = mgr.ProvisionTenant(ctx, "tenant-a")
	require.NoError(t, err)

	keyA, err := mgr.ActiveSigningKey(ctx, "tenant-a")
	require.NoError(t, err)

	// 2. Récupérer le ciphertext scellé stocké pour Tenant A
	keysA, err := memStore.VerificationKeys(ctx, "tenant-a")
	require.NoError(t, err)
	sealedCiphertextA := keysA[keyA.KeyID].Secret

	// 3. Simuler la transposition malveillante du ciphertext du Tenant A vers le Tenant B
	err = memStore.CreateTenant(ctx, "tenant-b", keystore.SigningKey{
		KeyID:    "transposed-key-b",
		TenantID: "tenant-b",
		Alg:      keystore.AlgHS256,
		Secret:   sealedCiphertextA,
	})
	require.NoError(t, err)

	// 4. INVARIANT DE SÉCURITÉ VIOLE :
	// Résoudre la clé pour Tenant B doit échouer car le ciphertext n'appartient pas à Tenant B
	keyB, err := mgr.ActiveSigningKey(ctx, "tenant-b")
	require.ErrorIs(t, err, keystore.ErrCiphertextCorrupt,
		"SEC-TOK-01: le déchiffrement KEK d'un secret scellé sous un autre tenant doit échouer en raison de l'invalidation de l'AAD")
	assert.Nil(t, keyB.Secret, "aucun secret ne doit être divulgué en cas de transposition inter-tenant")
}
