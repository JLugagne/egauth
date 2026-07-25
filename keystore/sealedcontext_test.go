package keystore_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/keystore/memory"
)

var sealedContextKEKKey = bytes.Repeat([]byte("k"), keystore.KEKKeyLength)

// TestSealedSecretIsNotPortableAcrossTenants is the confused-deputy proof for the sealed-blob
// format: a signing-key ciphertext lifted out of one tenant's row and pasted into another's must
// NOT open. Without context bound as AEAD associated data the KEK authenticates the bytes but not
// where they belong, so anyone able to write a row (a SQL injection, a restore of a foreign dump, a
// misrouted migration) makes the victim's key the attacker tenant's active signer.
func TestSealedSecretIsNotPortableAcrossTenants(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	kek, err := keystore.NewKEK(sealedContextKEKKey)
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	mgr, err := keystore.NewManager(store, kek)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.ProvisionTenant(ctx, "victim"); err != nil {
		t.Fatalf("provision victim: %v", err)
	}
	if err := mgr.ProvisionTenant(ctx, "attacker"); err != nil {
		t.Fatalf("provision attacker: %v", err)
	}

	victimRow, err := store.ActiveSigningKey(ctx, "victim")
	if err != nil {
		t.Fatalf("reading the victim's sealed row: %v", err)
	}
	victimPlaintext, err := mgr.ActiveSigningKey(ctx, "victim")
	if err != nil {
		t.Fatalf("opening the victim's key: %v", err)
	}

	// Paste the victim's SEALED secret into the attacker's own row, keeping the attacker's key id.
	attackerRow, err := store.ActiveSigningKey(ctx, "attacker")
	if err != nil {
		t.Fatalf("reading the attacker's row: %v", err)
	}
	attackerRow.Secret = victimRow.Secret
	if err := store.PutSigningKey(ctx, "attacker", attackerRow); err != nil {
		t.Fatalf("PutSigningKey: %v", err)
	}

	got, err := mgr.ActiveSigningKey(ctx, "attacker")
	if err == nil && bytes.Equal(got.Secret, victimPlaintext.Secret) {
		t.Fatal("a sealed secret was portable between tenants: the attacker tenant now signs with the victim's key material")
	}
	if !errors.Is(err, keystore.ErrCiphertextCorrupt) {
		t.Fatalf("want ErrCiphertextCorrupt for a foreign-tenant ciphertext, got %v", err)
	}
}

// TestSealedSecretIsNotPortableAcrossRows is the same argument within one tenant: a retired key's
// ciphertext must not be openable under a different key id.
func TestSealedSecretIsNotPortableAcrossRows(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	kek, err := keystore.NewKEK(sealedContextKEKKey)
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	mgr, err := keystore.NewManager(store, kek)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.ProvisionTenant(ctx, "acme", func(o *keystore.ProvisionOptions) { o.KeyID = "kid-a" }); err != nil {
		t.Fatalf("provision: %v", err)
	}
	rowA, err := store.ActiveSigningKey(ctx, "acme")
	if err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}

	moved := rowA
	moved.KeyID = "kid-b"
	if err := store.PutSigningKey(ctx, "acme", moved); err != nil {
		t.Fatalf("PutSigningKey: %v", err)
	}
	keys, err := mgr.VerificationKeys(ctx, "acme")
	if err != nil {
		t.Fatalf("VerificationKeys: %v", err)
	}
	if _, ok := keys["kid-b"]; ok {
		t.Fatal("a sealed secret opened under a key id it was not sealed for")
	}
}

// TestKEK_SealBindsContext pins the primitive: the same KEK must refuse a blob presented under any
// other tenant, purpose or row identity.
func TestKEK_SealBindsContext(t *testing.T) {
	kek, err := keystore.NewKEK(sealedContextKEKKey)
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	sc := keystore.SecretContext{TenantID: "acme", Purpose: keystore.PurposeSigningKey, RowID: "kid-1"}
	plaintext := []byte("super-secret-signing-material-32")
	sealed, err := kek.Seal(sc, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	opened, err := kek.Open(sc, sealed)
	if err != nil {
		t.Fatalf("Open with the sealing context: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("round trip mismatch: got %q", opened)
	}

	for _, other := range []keystore.SecretContext{
		{TenantID: "other", Purpose: keystore.PurposeSigningKey, RowID: "kid-1"},
		{TenantID: "", Purpose: keystore.PurposeSigningKey, RowID: "kid-1"},
		{TenantID: "acme", Purpose: keystore.PurposeTOTPSecret, RowID: "kid-1"},
		{TenantID: "acme", Purpose: keystore.PurposeOAuthClientSecret, RowID: "kid-1"},
		{TenantID: "acme", Purpose: keystore.PurposeSigningKey, RowID: "kid-2"},
		{TenantID: "acme", Purpose: keystore.PurposeSigningKey},
	} {
		if _, err := kek.Open(other, sealed); !errors.Is(err, keystore.ErrCiphertextCorrupt) {
			t.Fatalf("context %+v: want ErrCiphertextCorrupt, got %v", other, err)
		}
	}
}

// TestKEK_SealRequiresPurpose keeps an unlabelled (and therefore unbound) context from being usable.
func TestKEK_SealRequiresPurpose(t *testing.T) {
	kek, err := keystore.NewKEK(sealedContextKEKKey)
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	if _, err := kek.Seal(keystore.SecretContext{TenantID: "acme"}, []byte("x")); !errors.Is(err, keystore.ErrSecretContextIncomplete) {
		t.Fatalf("Seal with no Purpose: want ErrSecretContextIncomplete, got %v", err)
	}
	if _, err := kek.Open(keystore.SecretContext{TenantID: "acme"}, []byte("x")); !errors.Is(err, keystore.ErrSecretContextIncomplete) {
		t.Fatalf("Open with no Purpose: want ErrSecretContextIncomplete, got %v", err)
	}
}

// legacySeal reproduces the PRE-AAD sealed format exactly as the previous implementation wrote it:
// a raw 12-byte nonce followed by the GCM ciphertext, with no version prefix and no associated
// data. It stands in for a blob already sitting in a production database.
func legacySeal(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil)
}

// TestKEK_OpenAcceptsLegacyBlob is the migration guarantee: adding associated data must not orphan
// the secrets already at rest. Open accepts the legacy format under ANY context, because a legacy
// blob carries no binding to check.
func TestKEK_OpenAcceptsLegacyBlob(t *testing.T) {
	kek, err := keystore.NewKEK(sealedContextKEKKey)
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	plaintext := []byte("a secret sealed before the format change")
	legacy := legacySeal(t, sealedContextKEKKey, plaintext)

	opened, err := kek.Open(keystore.SecretContext{TenantID: "acme", Purpose: keystore.PurposeSigningKey, RowID: "kid-1"}, legacy)
	if err != nil {
		t.Fatalf("a legacy blob must still open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("legacy round trip mismatch: got %q", opened)
	}
}

// TestKEK_WithoutLegacySealedFormat is the end state of the migration: once an operator has
// re-sealed every row they can refuse the unbound format outright.
func TestKEK_WithoutLegacySealedFormat(t *testing.T) {
	strict, err := keystore.NewKEK(sealedContextKEKKey, keystore.WithoutLegacySealedFormat())
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	sc := keystore.SecretContext{TenantID: "acme", Purpose: keystore.PurposeSigningKey, RowID: "kid-1"}

	legacy := legacySeal(t, sealedContextKEKKey, []byte("old"))
	if _, err := strict.Open(sc, legacy); !errors.Is(err, keystore.ErrCiphertextCorrupt) {
		t.Fatalf("a strict KEK must refuse the legacy format, got %v", err)
	}

	sealed, err := strict.Seal(sc, []byte("new"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	opened, err := strict.Open(sc, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(opened) != "new" {
		t.Fatalf("round trip mismatch: got %q", opened)
	}
}

// TestManagerReSealsLegacyRows documents the operator migration path: read a row (legacy accepted),
// re-seal it in the bound format, write it back, and the strict KEK now accepts it.
func TestManagerReSealsLegacyRows(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	kek, err := keystore.NewKEK(sealedContextKEKKey)
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	mgr, err := keystore.NewManager(store, kek)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// A row written by an older release: legacy-sealed material under a known key id.
	material := bytes.Repeat([]byte("s"), 32)
	if err := store.PutSigningKey(ctx, "acme", keystore.SigningKey{
		KeyID:     "legacy-kid",
		TenantID:  "acme",
		Alg:       keystore.AlgHS256,
		Secret:    legacySeal(t, sealedContextKEKKey, material),
		CreatedAt: time.Unix(1_700_000_000, 0),
	}); err != nil {
		t.Fatalf("PutSigningKey: %v", err)
	}

	opened, err := mgr.ActiveSigningKey(ctx, "acme")
	if err != nil {
		t.Fatalf("a legacy row must keep working: %v", err)
	}
	if !bytes.Equal(opened.Secret, material) {
		t.Fatal("legacy row opened to the wrong material")
	}

	// Re-seal: the plaintext just read goes back sealed WITH its context.
	resealed, err := mgr.SealSecret(keystore.SecretContext{
		TenantID: "acme", Purpose: keystore.PurposeSigningKey, RowID: "legacy-kid",
	}, opened.Secret)
	if err != nil {
		t.Fatalf("SealSecret: %v", err)
	}
	row, err := store.ActiveSigningKey(ctx, "acme")
	if err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}
	row.Secret = resealed
	if err := store.PutSigningKey(ctx, "acme", row); err != nil {
		t.Fatalf("PutSigningKey: %v", err)
	}

	strictKEK, err := keystore.NewKEK(sealedContextKEKKey, keystore.WithoutLegacySealedFormat())
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	strictMgr, err := keystore.NewManager(store, strictKEK)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	again, err := strictMgr.ActiveSigningKey(ctx, "acme")
	if err != nil {
		t.Fatalf("a re-sealed row must open under a strict KEK: %v", err)
	}
	if !bytes.Equal(again.Secret, material) {
		t.Fatal("re-sealed row opened to the wrong material")
	}
}
