package providers_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/oauth"
	"github.com/JLugagne/egauth/oauth/providers"
)

func authorizeURL(t *testing.T, p *oauth.Provider) *url.URL {
	t.Helper()
	raw := p.AuthCodeURL("state", "https://app.example.com/cb", "challenge")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("unparseable authorize URL %q: %v", raw, err)
	}
	return u
}

func TestOkta_OrgAndCustomServerEndpoints(t *testing.T) {
	org := providers.Okta("example.okta.com", "id", "secret")
	u := authorizeURL(t, org)
	if u.Host != "example.okta.com" || u.Path != "/oauth2/v1/authorize" {
		t.Errorf("org authorize = %s%s, want example.okta.com/oauth2/v1/authorize", u.Host, u.Path)
	}
	if got, want := providers.OktaIssuer("example.okta.com"), "https://example.okta.com"; got != want {
		t.Errorf("OktaIssuer = %q, want %q", got, want)
	}
	if got, want := providers.OktaJWKSURL("https://example.okta.com/"), "https://example.okta.com/oauth2/v1/keys"; got != want {
		t.Errorf("OktaJWKSURL = %q, want %q", got, want)
	}

	custom := providers.OktaCustom("example.okta.com", "default", "id", "secret")
	cu := authorizeURL(t, custom)
	if cu.Path != "/oauth2/default/v1/authorize" {
		t.Errorf("custom authorize path = %q, want /oauth2/default/v1/authorize", cu.Path)
	}
	if got, want := providers.OktaCustomIssuer("example.okta.com", "default"), "https://example.okta.com/oauth2/default"; got != want {
		t.Errorf("OktaCustomIssuer = %q, want %q", got, want)
	}
}

func TestAuth0_EndpointsAndTrailingSlashIssuer(t *testing.T) {
	p := providers.Auth0("tenant.us.auth0.com", "id", "secret")
	u := authorizeURL(t, p)
	if u.Host != "tenant.us.auth0.com" || u.Path != "/authorize" {
		t.Errorf("authorize = %s%s, want tenant.us.auth0.com/authorize", u.Host, u.Path)
	}
	// Auth0's iss carries a trailing slash; the helper must preserve it so id_token validation
	// matches.
	if got, want := providers.Auth0Issuer("tenant.us.auth0.com"), "https://tenant.us.auth0.com/"; got != want {
		t.Errorf("Auth0Issuer = %q, want %q (trailing slash required)", got, want)
	}
	// JWKS host must match the issuer host (the verifier enforces this).
	iss, _ := url.Parse(providers.Auth0Issuer("tenant.us.auth0.com"))
	jwks, _ := url.Parse(providers.Auth0JWKSURL("tenant.us.auth0.com"))
	if iss.Host != jwks.Host {
		t.Errorf("issuer host %q != jwks host %q", iss.Host, jwks.Host)
	}
}

func TestKeycloak_RealmEndpoints(t *testing.T) {
	p := providers.Keycloak("https://sso.example.com", "myrealm", "id", "secret")
	u := authorizeURL(t, p)
	wantPath := "/realms/myrealm/protocol/openid-connect/auth"
	if u.Host != "sso.example.com" || u.Path != wantPath {
		t.Errorf("authorize = %s%s, want sso.example.com%s", u.Host, u.Path, wantPath)
	}
	if got, want := providers.KeycloakIssuer("https://sso.example.com", "myrealm"), "https://sso.example.com/realms/myrealm"; got != want {
		t.Errorf("KeycloakIssuer = %q, want %q", got, want)
	}
}

func TestCognito_CrossHostIssuerAndJWKS(t *testing.T) {
	p := providers.Cognito("myapp.auth.us-east-1.amazoncognito.com", "us-east-1", "us-east-1_AbCdEf", "id", "secret")
	u := authorizeURL(t, p)
	if u.Host != "myapp.auth.us-east-1.amazoncognito.com" || u.Path != "/oauth2/authorize" {
		t.Errorf("authorize = %s%s, want hosted-UI domain /oauth2/authorize", u.Host, u.Path)
	}
	// Issuer and JWKS live on the cognito-idp host, NOT the hosted-UI domain.
	iss := providers.CognitoIssuer("us-east-1", "us-east-1_AbCdEf")
	if want := "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf"; iss != want {
		t.Errorf("CognitoIssuer = %q, want %q", iss, want)
	}
	jwks := providers.CognitoJWKSURL("us-east-1", "us-east-1_AbCdEf")
	if !strings.HasSuffix(jwks, "/.well-known/jwks.json") || !strings.HasPrefix(jwks, iss) {
		t.Errorf("CognitoJWKSURL = %q, want issuer + /.well-known/jwks.json", jwks)
	}
}

// TestOIDC_DiscoversEndpoints stands up a fake issuer serving an OIDC discovery document and
// verifies the generic constructor wires the discovered authorize endpoint onto the Provider.
func TestOIDC_DiscoversEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"issuer": "`+issuer+`",
			"authorization_endpoint": "`+issuer+`/auth",
			"token_endpoint": "`+issuer+`/token",
			"userinfo_endpoint": "`+issuer+`/userinfo",
			"jwks_uri": "`+issuer+`/jwks"
		}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL

	p := providers.OIDC(context.Background(), issuer, "id", "secret", nil,
		providers.WithDiscoveryHTTPClient(srv.Client()),
		providers.WithProviderName("fake-idp"),
		providers.WithInsecureDiscoveryURLs(), // test server is http; opt-in required
	)
	if p.Name() != "fake-idp" {
		t.Errorf("Name() = %q, want \"fake-idp\"", p.Name())
	}
	u := authorizeURL(t, p)
	if got, want := u.String(), issuer+"/auth"; !strings.HasPrefix(got, want) {
		t.Errorf("authorize URL = %q, want prefix %q (discovered endpoint)", got, want)
	}
}

// TestOIDC_DiscoveryFailureDefersError verifies that a discovery failure does not panic and is
// surfaced as a deferred error at AuthCodeURL/Exchange time (empty endpoints → configErr).
func TestOIDC_DiscoveryFailureDefersError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	var p *oauth.Provider
	done := func() {
		p = providers.OIDC(context.Background(), srv.URL, "id", "secret", nil,
			providers.WithDiscoveryHTTPClient(srv.Client()),
			providers.WithInsecureDiscoveryURLs(), // test server is http; opt-in required
		)
	}
	done() // must not panic
	if p == nil {
		t.Fatal("expected a non-nil provider even on discovery failure")
	}
	// The deferred endpoint-validation error surfaces here.
	if _, err := p.Exchange(context.Background(), "code", "https://app/cb", "verifier"); err == nil {
		t.Error("expected a deferred error from a failed discovery, got nil")
	}
}

// TestOIDC_RejectsInternalIssuerBeforeGET verifies that fetchOIDCDiscovery returns an error for
// internal/non-https issuers WITHOUT issuing any HTTP request. This is the primary regression
// test for the TASK-028 hardening: the trusted-path constructor must gate on
// oauth.ValidateOIDCEndpointURL before touching the network.
func TestOIDC_RejectsInternalIssuerBeforeGET(t *testing.T) {
	cases := []struct {
		name   string
		issuer string
	}{
		{"link-local IMDS", "http://169.254.169.254/latest/meta-data"},
		{"loopback without opt-in", "http://127.0.0.1:8080"},
		{"plain http external without opt-in", "http://example.com"},
		{"empty issuer", ""},
		{"no scheme", "example.com/oidc"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A RoundTripper that fails the test if it is ever called — the issuer validation
			// must reject the URL before any network I/O occurs.
			blockRT := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				t.Errorf("HTTP request was issued to %q — expected rejection before network I/O", r.URL)
				return nil, nil
			})
			client := &http.Client{Transport: blockRT}

			p := providers.OIDC(context.Background(), tc.issuer, "id", "secret", nil,
				providers.WithDiscoveryHTTPClient(client),
				// No WithInsecureDiscoveryURLs — secure-by-default behaviour under test.
			)
			if p == nil {
				t.Fatal("OIDC returned nil provider")
			}
			// The validation error must be deferred; Exchange surfaces it.
			_, err := p.Exchange(context.Background(), "code", "https://app/cb", "verifier")
			if err == nil {
				t.Errorf("issuer %q: expected an error (rejected before GET), got nil", tc.issuer)
			}
		})
	}
}

// TestOIDC_InsecureOptInAllowsLoopback verifies that WithInsecureDiscoveryURLs permits a
// loopback http issuer (local-dev scenario) and that discovery succeeds for a valid document.
func TestOIDC_InsecureOptInAllowsLoopback(t *testing.T) {
	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"issuer": "`+issuer+`",
			"authorization_endpoint": "`+issuer+`/auth",
			"token_endpoint": "`+issuer+`/token",
			"userinfo_endpoint": "`+issuer+`/userinfo",
			"jwks_uri": "`+issuer+`/jwks"
		}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL // http://127.0.0.1:<port>

	p := providers.OIDC(context.Background(), issuer, "id", "secret", nil,
		providers.WithDiscoveryHTTPClient(srv.Client()),
		providers.WithInsecureDiscoveryURLs(), // loopback http opt-in
	)
	u := authorizeURL(t, p)
	if !strings.HasPrefix(u.String(), issuer+"/auth") {
		t.Errorf("authorize URL = %q, want prefix %q", u.String(), issuer+"/auth")
	}
}

// roundTripperFunc adapts a function to the http.RoundTripper interface.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
