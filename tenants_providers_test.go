package egauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/federationsvc"
	"github.com/JLugagne/egauth/principal"
	storefed "github.com/JLugagne/egauth/store/federation"
)

func (w *facadeWorld) oauthSignIn(idp *egauthtest.IdP, provider string) *http.Response {
	w.t.Helper()
	begin := w.request(w.h, http.MethodGet, "/auth/oauth/"+provider+"/begin", credentials{})
	require.Equal(w.t, http.StatusSeeOther, begin.Code, begin.Body.String())
	res, err := idp.HTTPClient().Get(begin.Header().Get("Location"))
	require.NoError(w.t, err)
	require.NoError(w.t, res.Body.Close())
	back, err := url.Parse(res.Header.Get("Location"))
	require.NoError(w.t, err)
	return w.request(w.h, http.MethodGet, back.RequestURI(), credentials{cookies: begin.Result().Cookies()}).Result()
}

func trustedSpec(idp *egauthtest.IdP, name string) federation.Provider {
	p := idp.Provider(name)
	p.Domains = []string{"idp.example"}
	return p
}

func TestTenantsSetOAuthProviderRefusesToRebindLinkedIdentities(t *testing.T) {
	w, idp := oauthWorld(t, true)
	_, admin, _ := w.admin("root@example.com")
	ctx := context.Background()
	tn := principal.TenantID{}
	set := func(by principal.Caller, p federation.Provider) error {
		return w.a.Tenants().SetOAuthProvider(ctx, by, egauth.SetProviderRequest{Tenant: tn, Provider: p})
	}

	require.NoError(t, set(w.system("sso"), trustedSpec(idp, "corp")))
	res := w.oauthSignIn(idp, "corp")
	require.Less(t, res.StatusCode, 400)
	victim, err := w.st.Federation.FindLinked(ctx, tn, storefed.LinkKey{Provider: "corp", ProviderSubject: "idp-user-1"})
	require.NoError(t, err, "the sign-in created a linked account")

	swapped := idp.Provider("corp")
	swapped.JWKSURL = idp.Issuer() + "/attacker-jwks"
	swapped.TokenURL = idp.Issuer() + "/attacker-token"
	err = set(admin, swapped)
	require.ErrorIs(t, err, egauth.ErrInvalidRequest, "a provider with linked identities cannot be re-pointed")
	require.ErrorIs(t, err, egauth.ErrProviderLinked)
	spec, err := w.st.Federation.GetProvider(ctx, tn, "corp")
	require.NoError(t, err)
	require.Equal(t, idp.Issuer()+"/jwks", spec.JWKSURL)

	require.NoError(t, w.a.Tenants().RemoveOAuthProvider(ctx, admin, egauth.RemoveProviderRequest{Tenant: tn, Name: "corp"}))
	require.ErrorIs(t, set(admin, swapped), egauth.ErrProviderLinked, "removing the provider does not free its links")

	rotated := trustedSpec(idp, "corp")
	rotated.Scopes = []string{"openid", "email"}
	require.NoError(t, set(w.system("sso"), rotated), "the same identity configuration is accepted again")
	res = w.oauthSignIn(idp, "corp")
	require.Less(t, res.StatusCode, 400)
	again, err := w.st.Federation.FindLinked(ctx, tn, storefed.LinkKey{Provider: "corp", ProviderSubject: "idp-user-1"})
	require.NoError(t, err)
	require.Equal(t, victim.Subject, again.Subject)

	require.NoError(t, set(admin, func() federation.Provider { p := idp.Provider("other"); p.JWKSURL += "?v=2"; return p }()),
		"a provider name without links takes any configuration")
}

func TestTenantsSetOAuthProviderHidesDiscoveryNetworkDetails(t *testing.T) {
	w, idp := oauthWorld(t, false)
	_, admin, _ := w.admin("root@example.com")
	ctx := context.Background()
	for _, issuer := range []string{"https://localhost:8443", "https://127.0.0.1:8443", "https://does-not-exist.invalid"} {
		err := w.a.Tenants().SetOAuthProvider(ctx, admin, egauth.SetProviderRequest{Provider: federation.Provider{
			Name: "probe", ClientID: idp.ClientID(), Issuer: issuer, Scopes: []string{"openid"},
		}})
		require.ErrorIs(t, err, egauth.ErrInvalidRequest, issuer)
		require.ErrorIs(t, err, federationsvc.ErrDiscovery, issuer)
		require.NotRegexp(t, `127\.0\.0\.1|::1|dial|lookup|no such host|SSRF`, err.Error(), issuer)
	}
	rejected := w.sink.of(event.OAuthProviderRejected)
	require.Len(t, rejected, 3, "the operator still sees every rejected discovery")
	require.Contains(t, rejected[1].Err.Text(), "127.0.0.1", "the detailed cause goes to the PII-classified event field only")
	require.Equal(t, "discovery", rejected[0].Reason)
}

type unreachableFederation struct {
	storefed.Store
}

func (unreachableFederation) HasLinksOutside(context.Context, storefed.ProviderSpec) (bool, error) {
	return false, errors.New("failed to connect to `user=egauth_svc database=egauth_prod`: 10.0.0.5:5432: dial error")
}

func TestTenantsSetOAuthProviderNeverReturnsAStoreFailureVerbatim(t *testing.T) {
	var idp *egauthtest.IdP
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	w := newFacadeWorldWithIdP(t, func(clk *egauthtest.Clock) *egauthtest.IdP {
		idp = egauthtest.NewIdP(t, clk)
		return idp
	}, func(c *egauth.Config[gateClaims], _ *egauthtest.IdP) {
		c.Modules.OAuth = &egauth.OAuthModule{Providers: []federation.Provider{provider("static")}, PerTenant: true}
		c.Insecure.OutboundPrivateNetwork = &egauth.OutboundAllowance{Prefixes: loopback, Ack: egauth.Acknowledge("fake idp")}
		c.Insecure.TenantOutboundPrivateNetwork = &egauth.OutboundAllowance{Prefixes: loopback, Ack: egauth.Acknowledge("fake idp")}
		c.Storage.Federation = unreachableFederation{c.Storage.Federation}
	})
	err := w.a.Tenants().SetOAuthProvider(context.Background(), w.system("sso"), egauth.SetProviderRequest{Provider: trustedSpec(idp, "corp")})
	require.ErrorIs(t, err, egauth.ErrStorageUnavailable)
	require.NotRegexp(t, `egauth_svc|egauth_prod|10\.0\.0\.5|dial`, err.Error(), "a store failure reached the tenant admin verbatim")
	rejected := w.sink.of(event.OAuthProviderRejected)
	require.NotEmpty(t, rejected, "the operator still sees the cause")
	require.Contains(t, rejected[len(rejected)-1].Err.Text(), "10.0.0.5")
}
