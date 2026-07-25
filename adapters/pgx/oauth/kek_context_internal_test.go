package pgx

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/keystore"
)

// TestClientSecretIsSealedWithItsRowContext pins the binding for the OIDC client_secret at rest: it
// must be sealed and opened under (tenant, oauth/client-secret, provider name), so a ciphertext
// lifted from another tenant's provider row cannot be decrypted here.
func TestClientSecretIsSealedWithItsRowContext(t *testing.T) {
	ctx := context.Background()
	kek := &countingKEK{}
	store := NewStore(&countingQuerier{}, kek)

	if _, err := store.GetProvider(ctx, "tenant-1", "my-sso"); err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	want := keystore.SecretContext{
		TenantID: "tenant-1",
		Purpose:  keystore.PurposeOAuthClientSecret,
		RowID:    "my-sso",
	}
	if kek.lastOpenContext != want {
		t.Fatalf("GetProvider opened with %+v, want %+v", kek.lastOpenContext, want)
	}

	if err := store.UpsertProvider(ctx, "tenant-2", "other-sso", OIDCProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		AuthURL:      "https://sso.example.com/auth",
		TokenURL:     "https://sso.example.com/token",
		Issuer:       "https://sso.example.com",
	}); err != nil {
		t.Fatalf("UpsertProvider: %v", err)
	}
	wantSeal := keystore.SecretContext{
		TenantID: "tenant-2",
		Purpose:  keystore.PurposeOAuthClientSecret,
		RowID:    "other-sso",
	}
	if kek.lastSealContext != wantSeal {
		t.Fatalf("UpsertProvider sealed with %+v, want %+v", kek.lastSealContext, wantSeal)
	}
}

// TestClientSecretContextIsExportedForReSealing keeps the operator migration path honest: the
// context a row is sealed under must be reproducible from outside the package.
func TestClientSecretContextIsExportedForReSealing(t *testing.T) {
	got := ClientSecretContext("acme", "my-sso")
	want := keystore.SecretContext{TenantID: "acme", Purpose: keystore.PurposeOAuthClientSecret, RowID: "my-sso"}
	if got != want {
		t.Fatalf("ClientSecretContext = %+v, want %+v", got, want)
	}
}
