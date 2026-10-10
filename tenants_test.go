package egauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	storefed "github.com/JLugagne/egauth/store/federation"
	"github.com/JLugagne/egauth/store/keys"
)

func tenantKeys(c *egauth.Config[gateClaims]) {
	c.Sessions = egauth.JWT(egauth.TenantKeys())
	c.Audiences = nil
}

func TestTenantsEraseRemovesOnlyTheCallersTenant(t *testing.T) {
	var mu sync.Mutex
	var erased []principal.TenantID
	w := newFacadeWorld(t, perRequestTenancy, func(c *egauth.Config[gateClaims]) {
		c.Hooks.TenantErased = func(_ context.Context, _ uuid.UUID, tn principal.TenantID) error {
			mu.Lock()
			defer mu.Unlock()
			erased = append(erased, tn)
			return nil
		}
	})
	w.tenant = "globex"
	survivor, _, theirs := w.user("carol@globex.example")
	w.tenant = "acme"
	_, admin, _ := w.admin("root@acme.example")
	bob := w.seedUser("bob@acme.example", false)
	ctx := context.Background()

	require.ErrorIs(t, w.a.Tenants().Erase(ctx, admin, survivor.Tenant), egauth.ErrTenantMismatch)
	require.NoError(t, w.a.Tenants().Erase(ctx, admin, bob.Tenant))
	_, err := w.st.Identity.GetUser(ctx, bob)
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = w.st.Identity.GetUser(ctx, survivor)
	require.NoError(t, err)
	mu.Lock()
	require.Equal(t, []principal.TenantID{bob.Tenant}, erased)
	mu.Unlock()
	w.tenant = "globex"
	require.Equal(t, http.StatusOK, w.status(theirs))
	require.NoError(t, w.a.Tenants().Erase(ctx, w.system("retention"), survivor.Tenant), "a system caller of that tenant may")
}

func TestTenantsKeysAreRenewedRevokedAndImported(t *testing.T) {
	w := newFacadeWorld(t, tenantKeys)
	w.seedUser("alice@example.com", false)
	ctx := context.Background()
	sys := w.system("provisioning")
	tn := principal.TenantID{}

	require.NotEqual(t, http.StatusOK, w.login(w.h, "alice@example.com", false).code, "the tenant has no signer yet")
	require.NoError(t, w.a.Tenants().RenewKeys(ctx, sys, egauth.RenewKeysRequest{Tenant: tn, Lifetime: defaultExpiry(), Overlap: defaultExpiry()}))
	_, admin, session := w.admin("root@example.com")

	require.NoError(t, w.a.Tenants().RevokeKeys(ctx, admin, tn))
	require.NotEqual(t, http.StatusOK, w.status(session), "tokens signed by a revoked key stop verifying")

	seed := sha256.Sum256([]byte("imported tenant key"))
	material := append([]byte(nil), seed[:]...)
	require.NoError(t, w.a.Tenants().ImportKey(ctx, sys, egauth.ImportKeyRequest{
		Tenant: tn, KeyID: "imported-1", Alg: "EdDSA", Material: material, Lifetime: keys.NeverExpire(), Overlap: defaultExpiry(),
	}))
	require.Equal(t, seed[:], material, "the caller's material is left untouched")
	active, err := w.st.Keys.ActiveKey(ctx, tn)
	require.NoError(t, err)
	require.Equal(t, "imported-1", active.KeyID)
	require.Equal(t, keys.AADVersionCurrent, active.AADVersion)
	ref, err := sealing.SigningKey(tn, "imported-1")
	require.NoError(t, err)
	opened, err := sealing.Open(ctx, w.cfg.KEK, ref, active.Sealed)
	require.NoError(t, err)
	require.Equal(t, seed[:], opened.Plaintext)
	_, err = w.cfg.KEK.Open(ctx, active.Sealed, nil)
	require.Error(t, err, "an imported key is never sealed without associated data (X-03)")
	other, err := sealing.SigningKey(tn, "imported-2")
	require.NoError(t, err)
	_, err = sealing.Open(ctx, w.cfg.KEK, other, active.Sealed)
	require.Error(t, err, "the key id is bound into the associated data")
	require.Equal(t, http.StatusOK, w.login(w.h, "alice@example.com", false).code, "the imported key signs sessions")
}

func TestTenantsKeyRequestsAreBounded(t *testing.T) {
	w := newFacadeWorld(t, tenantKeys)
	sys := w.system("provisioning")
	ctx := context.Background()
	huge, err := keys.ExpireAfter(math.MaxInt64)
	require.NoError(t, err)
	for name, req := range map[string]egauth.RenewKeysRequest{
		"zero lifetime":      {Overlap: defaultExpiry()},
		"zero overlap":       {Lifetime: defaultExpiry()},
		"unbounded overlap":  {Lifetime: defaultExpiry(), Overlap: keys.NeverExpire()},
		"saturated overlap":  {Lifetime: defaultExpiry(), Overlap: huge},
		"unknown algorithm":  {Alg: "none", Lifetime: defaultExpiry(), Overlap: defaultExpiry()},
		"already over (0 d)": {Lifetime: zeroAfter(t), Overlap: defaultExpiry()},
	} {
		require.ErrorIs(t, w.a.Tenants().RenewKeys(ctx, sys, req), egauth.ErrInvalidRequest, name)
	}
	require.ErrorIs(t, w.a.Tenants().ImportKey(ctx, sys, egauth.ImportKeyRequest{
		KeyID: "bad", Alg: "EdDSA", Material: []byte("short"), Lifetime: defaultExpiry(), Overlap: defaultExpiry(),
	}), egauth.ErrInvalidRequest)
	_, err = w.st.Keys.ActiveKey(ctx, principal.TenantID{})
	require.Error(t, err, "no refused request installed a key")

	static := newFacadeWorld(t)
	require.ErrorIs(t, static.a.Tenants().RenewKeys(ctx, static.system("provisioning"),
		egauth.RenewKeysRequest{Lifetime: defaultExpiry(), Overlap: defaultExpiry()}), egauth.ErrFacadeUnavailable)
}

func TestTenantsImportKeyRequestIsRedacted(t *testing.T) {
	req := egauth.ImportKeyRequest{KeyID: "k", Alg: "HS256", Material: []byte("super-secret-hmac-material-0123456789")}
	for _, out := range []string{req.String(), req.GoString(), fmt.Sprintf("%v %+v %#v %s", req, req, req, req), string(mustJSON(t, req))} {
		require.NotContains(t, out, "super-secret")
	}
}

func TestTenantsHaveNoUnboundSealingMethod(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeFor[*egauth.Tenants](), reflect.TypeFor[*egauth.Auth[gateClaims]]()} {
		for i := range typ.NumMethod() {
			require.NotContains(t, typ.Method(i).Name, "Seal", "%s: secrets enter only through ImportKey and SetOAuthProvider (X-03)", typ)
		}
	}
}

func oauthWorld(t *testing.T, tenantAllowance bool) (*facadeWorld, *egauthtest.IdP) {
	t.Helper()
	var idp *egauthtest.IdP
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	w := newFacadeWorldWithIdP(t, func(clk *egauthtest.Clock) *egauthtest.IdP {
		idp = egauthtest.NewIdP(t, clk)
		return idp
	}, func(c *egauth.Config[gateClaims], _ *egauthtest.IdP) {
		c.Modules.OAuth = &egauth.OAuthModule{Providers: []federation.Provider{provider("static")}, PerTenant: true}
		c.Insecure.OutboundPrivateNetwork = &egauth.OutboundAllowance{Prefixes: loopback, Ack: egauth.Acknowledge("fake idp")}
		if tenantAllowance {
			c.Insecure.TenantOutboundPrivateNetwork = &egauth.OutboundAllowance{Prefixes: loopback, Ack: egauth.Acknowledge("fake idp")}
		}
	})
	return w, idp
}

func runtimeSpec(idp *egauthtest.IdP, name string) federation.Provider {
	return federation.Provider{
		Name: name, ClientID: idp.ClientID(), ClientSecret: federation.NewSecret(idp.ClientSecret()), Issuer: idp.Issuer(),
		Scopes: []string{"openid", "email"}, EmailVerification: federation.Always,
	}
}

func TestTenantsSetOAuthProviderDiscoversThroughTheTenantScopeOnly(t *testing.T) {
	w, idp := oauthWorld(t, false)
	err := w.a.Tenants().SetOAuthProvider(context.Background(), w.system("sso"), egauth.SetProviderRequest{Provider: runtimeSpec(idp, "corp")})
	require.ErrorIs(t, err, egauth.ErrInvalidRequest, "the static allowance never widens runtime providers")
	_, err = w.st.Federation.GetProvider(context.Background(), principal.TenantID{}, "corp")
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestTenantsSetOAuthProviderCapsEmailTrustAndSealsTheSecret(t *testing.T) {
	w, idp := oauthWorld(t, true)
	_, admin, _ := w.admin("root@example.com")
	ctx := context.Background()
	tn := principal.TenantID{}

	require.NoError(t, w.a.Tenants().SetOAuthProvider(ctx, admin, egauth.SetProviderRequest{Tenant: tn, Provider: runtimeSpec(idp, "corp")}))
	spec, err := w.st.Federation.GetProvider(ctx, tn, "corp")
	require.NoError(t, err)
	require.Equal(t, federation.Never, spec.EmailVerification, "Always without Domains is capped to Never")
	require.Equal(t, idp.Issuer()+"/authorize", spec.AuthURL, "discovered")
	require.Equal(t, storefed.AADVersionCurrent, spec.AADVersion)
	require.NotContains(t, string(spec.SealedSecret), idp.ClientSecret())
	ref, err := sealing.OAuthClientSecret(tn, "corp")
	require.NoError(t, err)
	opened, err := sealing.Open(ctx, w.cfg.KEK, ref, spec.SealedSecret)
	require.NoError(t, err)
	require.Equal(t, idp.ClientSecret(), string(opened.Plaintext))
	other, err := sealing.OAuthClientSecret(tn, "other")
	require.NoError(t, err)
	_, err = sealing.Open(ctx, w.cfg.KEK, other, spec.SealedSecret)
	require.Error(t, err)

	withDomains := runtimeSpec(idp, "corp")
	withDomains.Domains = []string{"example.com"}
	err = w.a.Tenants().SetOAuthProvider(ctx, admin, egauth.SetProviderRequest{Tenant: tn, Provider: withDomains})
	require.ErrorIs(t, err, federation.ErrDomainsSystemOnly)
	require.NoError(t, w.a.Tenants().SetOAuthProvider(ctx, w.system("sso"), egauth.SetProviderRequest{Tenant: tn, Provider: withDomains}))
	spec, err = w.st.Federation.GetProvider(ctx, tn, "corp")
	require.NoError(t, err)
	require.Equal(t, federation.ClaimBased, spec.EmailVerification, "Always is capped to ClaimBased at runtime")
	require.Equal(t, []string{"example.com"}, spec.Domains)

	rec := w.request(w.h, http.MethodGet, "/auth/oauth/corp/begin", credentials{}, func(r *http.Request) { r.Header.Set("Accept", "application/json") })
	require.Less(t, rec.Code, 400, rec.Body.String())
	require.True(t, strings.Contains(rec.Body.String(), idp.Issuer()) || strings.Contains(rec.Header().Get("Location"), idp.Issuer()),
		"the registered provider serves sign-ins")

	err = w.a.Tenants().SetOAuthProvider(ctx, admin, egauth.SetProviderRequest{Tenant: tn, Provider: runtimeSpec(idp, "static")})
	require.ErrorIs(t, err, egauth.ErrInvalidRequest, "a static provider name cannot be shadowed")

	require.NoError(t, w.a.Tenants().RemoveOAuthProvider(ctx, admin, egauth.RemoveProviderRequest{Tenant: tn, Name: "corp"}))
	_, err = w.st.Federation.GetProvider(ctx, tn, "corp")
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestTenantsOAuthProvidersNeedPerTenant(t *testing.T) {
	w := newFacadeWorld(t)
	err := w.a.Tenants().SetOAuthProvider(context.Background(), w.system("sso"), egauth.SetProviderRequest{Provider: provider("corp")})
	require.ErrorIs(t, err, egauth.ErrFacadeUnavailable)
}

func zeroAfter(t *testing.T) keys.Expiry {
	t.Helper()
	e, err := keys.ExpireAfter(0)
	require.NoError(t, err)
	return e
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
