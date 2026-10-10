package egauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/federationsvc"
	internalkeys "github.com/JLugagne/egauth/internal/keys"
	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
	storefed "github.com/JLugagne/egauth/store/federation"
	"github.com/JLugagne/egauth/store/keys"
)

// Tenants administers one tenant: its erasure, its signing keys and its runtime OAuth providers.
// Every method needs a System caller minted for that tenant, or a session caller of that tenant
// allowed by Config.Admin, fresh within SessionPolicy.ReauthWindow and multi-factor when its
// subject enrolled a second factor; ImportKey alone needs a System caller. Any other tenant returns
// ErrTenantMismatch: cross-tenant work mints one System caller per tenant.
type Tenants struct {
	f *facade
}

// Tenants returns the tenant administration facade.
func (a *Auth[C]) Tenants() *Tenants {
	return &Tenants{f: a.facade()}
}

// RenewKeysRequest generates a signing key for Tenant and makes it the signer. Alg is one of the
// signing.Alg* constants, EdDSA when empty. Lifetime bounds the new key and Overlap is how long the
// previous signer keeps verifying, at most 30 days; NeverExpire is refused for Overlap and the zero
// Expiry for both.
type RenewKeysRequest struct {
	Tenant   principal.TenantID
	Alg      string
	Lifetime keys.Expiry
	Overlap  keys.Expiry
}

// ImportKeyRequest installs caller-supplied key material as Tenant's signer, under the rules of
// RenewKeysRequest. Material is what the signing constructor of Alg accepts (a PKCS#8 private key,
// an Ed25519 seed or raw P-256 scalar, or an HS256 secret of at least 32 bytes). It is stored only
// sealed with the deployment KEK under the tenant and key id as associated data; the key manager
// holds the opened signer in memory to sign. The request renders it as REDACTED.
type ImportKeyRequest struct {
	Tenant   principal.TenantID
	KeyID    string
	Alg      string
	Material []byte
	Lifetime keys.Expiry
	Overlap  keys.Expiry
}

func (r ImportKeyRequest) String() string {
	return "egauth.ImportKeyRequest{Tenant: " + r.Tenant.String() + ", KeyID: " + r.KeyID + ", Alg: " + r.Alg + ", Material: REDACTED}"
}

func (r ImportKeyRequest) GoString() string { return r.String() }

func (r ImportKeyRequest) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, r.String()) }

func (r ImportKeyRequest) LogValue() slog.Value {
	return slog.GroupValue(slog.String("tenant", r.Tenant.String()), slog.String("kid", r.KeyID), slog.String("alg", r.Alg),
		slog.String("material", "REDACTED"))
}

func (r ImportKeyRequest) MarshalJSON() ([]byte, error) {
	return []byte(`{"material":"REDACTED"}`), nil
}

// SetProviderRequest registers or replaces the OAuth or OIDC provider Provider.Name of Tenant. A
// generic OIDC spec is discovered now, through the tenant outbound scope that only
// Insecure.TenantOutboundPrivateNetwork widens. Its EmailVerification is capped at ClaimBased and
// becomes Never without Domains, which only a System caller may set.
type SetProviderRequest struct {
	Tenant   principal.TenantID
	Provider federation.Provider
}

// RemoveProviderRequest removes the runtime provider Name of Tenant.
type RemoveProviderRequest struct {
	Tenant principal.TenantID
	Name   string
}

// Erase removes every record of tenant: keys first, so the tenant is tombstoned before anything else
// goes, then sessions, API keys, ceremonies, factors, links and Hooks.TenantErased, and the accounts
// last. Every step is idempotent: on error, call it again.
func (t *Tenants) Erase(ctx context.Context, by principal.Caller, tenant principal.TenantID) error {
	if _, err := t.f.authorize(ctx, by, "Tenants.Erase", tenant, core.Subject{}, scopeAdmin); err != nil {
		return err
	}
	if err := t.f.o.dispatcher.EraseTenant(ctx, tenant); err != nil {
		return err
	}
	if present(t.f.storage.Limiter) {
		return t.f.storage.Limiter.EraseTenant(ctx, tenant)
	}
	return nil
}

// RenewKeys installs a generated signer for req.Tenant. It returns ErrFacadeUnavailable unless the
// session backend uses TenantKeys, ErrInvalidRequest for an algorithm, lifetime or overlap the key
// manager refuses, and keys.ErrTenantTombstoned for an erased tenant.
func (t *Tenants) RenewKeys(ctx context.Context, by principal.Caller, req RenewKeysRequest) error {
	if err := t.keyAccess(ctx, by, "Tenants.RenewKeys", req.Tenant, scopeAdmin); err != nil {
		return err
	}
	return keyProblem(t.f.o.keys.Renew(ctx, internalkeys.RenewRequest{Tenant: req.Tenant, Alg: req.Alg, Lifetime: req.Lifetime, Overlap: req.Overlap}))
}

// ImportKey installs req.Material as the signer of req.Tenant, like RenewKeys; it also returns
// ErrInvalidRequest for material or a key id the signing package refuses. It is the only way to
// bring external key material in: nothing else seals a signing key. Whoever knows the material can
// sign any claims for the tenant, so a session caller gets ErrForbidden: only a System caller,
// outside any request, may import.
func (t *Tenants) ImportKey(ctx context.Context, by principal.Caller, req ImportKeyRequest) error {
	if err := t.keyAccess(ctx, by, "Tenants.ImportKey", req.Tenant, scopeSystem); err != nil {
		return err
	}
	return keyProblem(t.f.o.keys.Import(ctx, internalkeys.ImportRequest{
		Tenant: req.Tenant, KeyID: req.KeyID, Alg: req.Alg, Material: req.Material, Lifetime: req.Lifetime, Overlap: req.Overlap,
	}))
}

// RevokeKeys deletes every signing key of tenant at once, for a key compromise: every token they
// signed stops verifying here at once and on other instances within the revocation poll bound, and
// the tenant cannot sign again before RenewKeys or ImportKey.
func (t *Tenants) RevokeKeys(ctx context.Context, by principal.Caller, tenant principal.TenantID) error {
	if err := t.keyAccess(ctx, by, "Tenants.RevokeKeys", tenant, scopeAdmin); err != nil {
		return err
	}
	return keyProblem(t.f.o.keys.RevokeAll(ctx, tenant))
}

// SetOAuthProvider registers req.Provider for req.Tenant. It returns ErrFacadeUnavailable unless
// OAuthModule.PerTenant is set, ErrInvalidRequest for a name taken by a static provider or a spec
// that is invalid or incomplete after discovery, and federation.ErrDomainsSystemOnly when a session
// caller sets Domains.
func (t *Tenants) SetOAuthProvider(ctx context.Context, by principal.Caller, req SetProviderRequest) error {
	if err := t.providerAccess(ctx, by, "Tenants.SetOAuthProvider", req.Tenant, req.Provider.Name); err != nil {
		return err
	}
	p, err := federation.ForRuntime(req.Provider, by)
	if err != nil {
		return errors.Join(ErrInvalidRequest, err)
	}
	if p.NeedsDiscovery() {
		if p, err = federationsvc.Discover(ctx, t.f.o.outbound.Tenant(), p); err != nil {
			return errors.Join(ErrInvalidRequest, err)
		}
	}
	if err := p.Complete(); err != nil {
		return errors.Join(ErrInvalidRequest, err)
	}
	var sealed []byte
	if !p.ClientSecret.IsZero() {
		ref, err := sealing.OAuthClientSecret(req.Tenant, p.Name)
		if err != nil {
			return errors.Join(ErrInvalidRequest, err)
		}
		if sealed, err = sealing.Seal(ctx, t.f.kek, ref, []byte(p.ClientSecret.Reveal())); err != nil {
			return err
		}
	}
	return t.f.storage.Federation.PutProvider(ctx, storefed.ProviderSpec{
		Tenant: req.Tenant, Name: p.Name, ClientID: p.ClientID, SealedSecret: sealed, AADVersion: storefed.AADVersionCurrent,
		AuthURL: p.AuthURL, TokenURL: p.TokenURL, UserInfoURL: p.UserInfoURL, Scopes: p.Scopes, Issuer: p.Issuer, JWKSURL: p.JWKSURL,
		Domains: p.Domains, EmailVerification: p.EmailVerification, UpdatedAt: t.f.o.clock.Now().UTC(),
	})
}

// RemoveOAuthProvider removes the runtime provider req.Name of req.Tenant; sign-ins through it fail
// at once. Identities already linked to it stay linked. Removing an unknown provider is a no-op.
func (t *Tenants) RemoveOAuthProvider(ctx context.Context, by principal.Caller, req RemoveProviderRequest) error {
	if err := t.providerAccess(ctx, by, "Tenants.RemoveOAuthProvider", req.Tenant, req.Name); err != nil {
		return err
	}
	return t.f.storage.Federation.DeleteProvider(ctx, req.Tenant, req.Name)
}

func (t *Tenants) keyAccess(ctx context.Context, by principal.Caller, method string, tenant principal.TenantID, sc scope) error {
	if _, err := t.f.authorize(ctx, by, method, tenant, core.Subject{}, sc); err != nil {
		return err
	}
	if t.f.keys.kind != keysTenant || t.f.o.keys == nil {
		return errors.Join(ErrFacadeUnavailable, errors.New("egauth: "+method+" needs JWT(TenantKeys())"))
	}
	return nil
}

func (t *Tenants) providerAccess(ctx context.Context, by principal.Caller, method string, tenant principal.TenantID, name string) error {
	if _, err := t.f.authorize(ctx, by, method, tenant, core.Subject{}, scopeAdmin); err != nil {
		return err
	}
	if t.f.oauth == nil || !t.f.oauth.PerTenant || !present(t.f.storage.Federation) {
		return errors.Join(ErrFacadeUnavailable, errors.New("egauth: "+method+" needs OAuthModule.PerTenant"))
	}
	for _, p := range t.f.oauth.Providers {
		if p.Name == name {
			return errors.Join(ErrInvalidRequest, errors.New("egauth: provider "+name+" is a static provider"))
		}
	}
	return nil
}

func keyProblem(err error) error {
	for _, invalid := range []error{
		internalkeys.ErrUnsupportedAlgorithm, internalkeys.ErrOverlapTooLong, keys.ErrInvalidExpiry, keys.ErrUnboundedOverlap,
		signing.ErrInvalidKey, signing.ErrInvalidKeyID,
	} {
		if errors.Is(err, invalid) {
			return errors.Join(ErrInvalidRequest, err)
		}
	}
	return err
}
