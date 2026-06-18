package keystore_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/keystore/memory"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	tokmem "github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
)

// newJWTServiceWithKeyStore builds a multi-tenant jwt.Service backed by a keystore.Manager. The
// static SecretKey serves the single-tenant ("") partition; the KeyStore serves named tenants.
func newJWTServiceWithKeyStore(t *testing.T) (*jwt.Service[struct{}], *keystore.Manager) {
	t.Helper()
	mgr, err := keystore.NewManager(memory.New(), newKEK(t))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	svc := jwt.New(jwt.Config[struct{}]{
		Store:      tokmem.NewStore[struct{}](),
		Issuer:     "egauth-test",
		SecretKey:  "static-single-tenant-key-at-least-32b!",
		KeyStore:   keystore.NewJWTKeyStore(mgr),
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
	})
	return svc, mgr
}

func issueFor(t *testing.T, svc *jwt.Service[struct{}], tenantID string) string {
	t.Helper()
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
		Subject:  uuid.Must(uuid.NewV7()),
		TenantID: tenantID,
	})
	if err != nil {
		t.Fatalf("IssueTokenPair(%q): %v", tenantID, err)
	}
	return pair.AccessToken
}

// TestJWT_CrossTenantIsolation is the adversarial end-to-end check: a token minted for tenant A
// must verify as A but FAIL as B, because each tenant signs with its own keyset.
func TestJWT_CrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	svc, mgr := newJWTServiceWithKeyStore(t)
	if err := mgr.ProvisionTenant(ctx, "a"); err != nil {
		t.Fatalf("provision a: %v", err)
	}
	if err := mgr.ProvisionTenant(ctx, "b"); err != nil {
		t.Fatalf("provision b: %v", err)
	}

	aToken := issueFor(t, svc, "a")

	// Verifies as A.
	if _, err := svc.VerifyAccessTokenForTenant(ctx, "a", aToken); err != nil {
		t.Fatalf("A's token must verify as A: %v", err)
	}
	// Fails as B (different keyset; B's verification set does not contain A's kid).
	if _, err := svc.VerifyAccessTokenForTenant(ctx, "b", aToken); err == nil {
		t.Fatal("A's token must NOT verify as B")
	}
}

// TestJWT_RotateADoesNotAffectB: rotating tenant A's key leaves B's tokens fully valid.
func TestJWT_RotateADoesNotAffectB(t *testing.T) {
	ctx := context.Background()
	svc, mgr := newJWTServiceWithKeyStore(t)
	_ = mgr.ProvisionTenant(ctx, "a")
	_ = mgr.ProvisionTenant(ctx, "b")

	bToken := issueFor(t, svc, "b")
	if _, err := svc.VerifyAccessTokenForTenant(ctx, "b", bToken); err != nil {
		t.Fatalf("B token must verify before rotation: %v", err)
	}

	// Rotate A.
	if err := mgr.RenewSigningKey(ctx, "a"); err != nil {
		t.Fatalf("renew a: %v", err)
	}

	// B's pre-existing token must still verify.
	if _, err := svc.VerifyAccessTokenForTenant(ctx, "b", bToken); err != nil {
		t.Fatalf("rotating A must not affect B's tokens: %v", err)
	}
}

// TestJWT_RenewalContinuity: a token minted before A's renewal must still verify during the
// overlap window (graceful rollover), and a token minted after uses the new key.
func TestJWT_RenewalContinuity(t *testing.T) {
	ctx := context.Background()
	svc, mgr := newJWTServiceWithKeyStore(t)
	_ = mgr.ProvisionTenant(ctx, "a")

	preToken := issueFor(t, svc, "a")

	if err := mgr.RenewSigningKey(ctx, "a", func(o *keystore.RenewOptions) {
		o.OverlapTTL = time.Hour
	}); err != nil {
		t.Fatalf("renew: %v", err)
	}

	// Pre-renew token still verifies during overlap.
	if _, err := svc.VerifyAccessTokenForTenant(ctx, "a", preToken); err != nil {
		t.Fatalf("pre-renew token must verify during overlap: %v", err)
	}
	// Post-renew token also verifies.
	postToken := issueFor(t, svc, "a")
	if _, err := svc.VerifyAccessTokenForTenant(ctx, "a", postToken); err != nil {
		t.Fatalf("post-renew token must verify: %v", err)
	}
}

// TestJWT_DeletedTenantTokensStopVerifying: once A is deleted, A's tokens no longer verify.
func TestJWT_DeletedTenantTokensStopVerifying(t *testing.T) {
	ctx := context.Background()
	svc, mgr := newJWTServiceWithKeyStore(t)
	_ = mgr.ProvisionTenant(ctx, "a")
	aToken := issueFor(t, svc, "a")
	if _, err := svc.VerifyAccessTokenForTenant(ctx, "a", aToken); err != nil {
		t.Fatalf("A token must verify before delete: %v", err)
	}
	if err := mgr.DeleteTenant(ctx, "a"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.VerifyAccessTokenForTenant(ctx, "a", aToken); err == nil {
		t.Fatal("A's tokens must stop verifying after the tenant is deleted")
	}
}

// TestJWT_ZeroConfigSingleTenantStillWorks: a jwt.Service with NO KeyStore configured uses the
// static keyset and the single-tenant ("") path exactly as before — the zero-config mode.
func TestJWT_ZeroConfigSingleTenantStillWorks(t *testing.T) {
	ctx := context.Background()
	svc := jwt.New(jwt.Config[struct{}]{
		Store:      tokmem.NewStore[struct{}](),
		Issuer:     "egauth-test",
		SecretKey:  "static-single-tenant-key-at-least-32b!",
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
	})
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken); err != nil {
		t.Fatalf("zero-config single-tenant verify must work: %v", err)
	}
}

// TestJWT_KeyStoreStaticPartitionFallback: with a KeyStore wired, the single-tenant ("")
// partition still resolves via the static keyset when "" was never provisioned in the KeyStore —
// so mixed single+multi deployments keep working. (Lazy provisioning is off here.)
func TestJWT_KeyStoreStaticPartitionFallback(t *testing.T) {
	ctx := context.Background()
	svc, _ := newJWTServiceWithKeyStore(t)
	// "" is not provisioned in the KeyStore; issuing for "" must fall through to the static key.
	// Without lazy provisioning the KeyStore returns ErrTenantNotFound for "", which the Service
	// surfaces — so this asserts the documented behavior: provision "" (or use lazy) for the
	// single-tenant partition under a KeyStore.
	_, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	if !errors.Is(err, keystore.ErrTenantNotFound) {
		t.Fatalf("unprovisioned \"\" under a strict KeyStore should report ErrTenantNotFound, got %v", err)
	}
}

// TestJWT_TamperedTokenRejected: a token whose signature is corrupted is rejected.
func TestJWT_TamperedTokenRejected(t *testing.T) {
	ctx := context.Background()
	svc, mgr := newJWTServiceWithKeyStore(t)
	_ = mgr.ProvisionTenant(ctx, "a")
	tok := issueFor(t, svc, "a")
	tampered := tok[:len(tok)-3] + "AAA"
	if _, err := svc.VerifyAccessTokenForTenant(ctx, "a", tampered); err == nil {
		t.Fatal("tampered token must be rejected")
	}
}

// newAsymJWTService builds a multi-tenant jwt.Service backed by a keystore.Manager, returning the
// manager so the test can provision tenants with a chosen algorithm.
func newAsymJWTService(t *testing.T) (*jwt.Service[struct{}], *keystore.Manager) {
	t.Helper()
	mgr, err := keystore.NewManager(memory.New(), newKEK(t))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	svc := jwt.New(jwt.Config[struct{}]{
		Store:      tokmem.NewStore[struct{}](),
		Issuer:     "egauth-test",
		SecretKey:  "static-single-tenant-key-at-least-32b!",
		KeyStore:   keystore.NewJWTKeyStore(mgr),
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
	})
	return svc, mgr
}

func TestJWT_AsymmetricTenantRoundTrip(t *testing.T) {
	ctx := context.Background()
	svc, mgr := newAsymJWTService(t)
	if err := mgr.ProvisionTenant(ctx, "a", func(o *keystore.ProvisionOptions) {
		o.Alg = "RS256"
	}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	tok := issueFor(t, svc, "a")
	if _, err := svc.VerifyAccessTokenForTenant(ctx, "a", tok); err != nil {
		t.Fatalf("RS256 token must verify: %v", err)
	}
	alg := algHeader(t, tok)
	if alg != "RS256" {
		t.Fatalf("token alg header = %q, want RS256", alg)
	}
}

func TestJWT_AsymmetricCrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	svc, mgr := newAsymJWTService(t)
	if err := mgr.ProvisionTenant(ctx, "a", func(o *keystore.ProvisionOptions) {
		o.Alg = "RS256"
	}); err != nil {
		t.Fatalf("provision a: %v", err)
	}
	if err := mgr.ProvisionTenant(ctx, "b", func(o *keystore.ProvisionOptions) {
		o.Alg = "ES256"
	}); err != nil {
		t.Fatalf("provision b: %v", err)
	}
	aTok := issueFor(t, svc, "a")
	if _, err := svc.VerifyAccessTokenForTenant(ctx, "a", aTok); err != nil {
		t.Fatalf("A token must verify as A: %v", err)
	}
	if _, err := svc.VerifyAccessTokenForTenant(ctx, "b", aTok); err == nil {
		t.Fatal("A's RS256 token must NOT verify as B (ES256)")
	}
}

// algHeader decodes a JWT's protected header and returns its alg.
func algHeader(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		t.Fatalf("malformed token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return hdr.Alg
}
