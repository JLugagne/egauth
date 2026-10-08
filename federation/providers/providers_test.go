package providers_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/federation/providers"
)

const directory = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"

func client() providers.Client {
	return providers.Client{ID: "id", Secret: federation.NewSecret("SUPERSECRET")}
}

func TestMicrosoftAndFacebookNeverTrustEmail(t *testing.T) {
	ms, err := providers.Microsoft(directory, client())
	if err != nil {
		t.Fatal(err)
	}
	fb, err := providers.Facebook(client())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []federation.Provider{ms, fb} {
		if p.EmailVerification != federation.Never || p.Verified("a@example.com", true) {
			t.Fatalf("%s must never trust its email", p.Name)
		}
	}
}

func TestMicrosoftRefusesTenantsWithoutAFixedIssuer(t *testing.T) {
	for _, tenant := range []string{"", "common", "organizations", "consumers", "contoso.example", "a/../b", "a?b"} {
		t.Run(tenant, func(t *testing.T) {
			p, err := providers.Microsoft(tenant, client())
			if !errors.Is(err, federation.ErrInvalidProvider) {
				t.Fatalf("tenant %q pinned issuer %q, want ErrInvalidProvider", tenant, p.Issuer)
			}
		})
	}
	p, err := providers.Microsoft(strings.ToUpper(directory), client())
	if err != nil {
		t.Fatal(err)
	}
	if p.Issuer != "https://login.microsoftonline.com/"+directory+"/v2.0" {
		t.Fatalf("issuer = %q", p.Issuer)
	}
}

func TestBuiltinsNeverUpgradeAFalseClaim(t *testing.T) {
	google, _ := providers.Google(client())
	github, _ := providers.GitHub(client())
	linkedin, _ := providers.LinkedIn(client())
	gitlab, _ := providers.GitLab("https://gitlab.com", client())
	apple, _ := providers.Apple(client())
	for _, p := range []federation.Provider{google, github, linkedin, gitlab, apple} {
		if p.EmailVerification != federation.Always {
			t.Fatalf("%s: verification %v", p.Name, p.EmailVerification)
		}
		if p.Verified("victim@corp.example", false) {
			t.Fatalf("%s upgraded a false email_verified claim", p.Name)
		}
		if !p.Verified("owner@corp.example", true) {
			t.Fatalf("%s refused a true claim", p.Name)
		}
	}
}

func TestCognitoIssuerIsNotDerivedFromTheAuthURL(t *testing.T) {
	p, err := providers.Cognito(providers.CognitoPool{
		HostedUIDomain: "pfx.auth.eu-west-1.amazoncognito.com", UserPoolID: "eu-west-1_Abc",
	}, client())
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := url.Parse(p.AuthURL)
	iss, _ := url.Parse(p.Issuer)
	if auth.Host == iss.Host || iss.Host != "cognito-idp.eu-west-1.amazonaws.com" {
		t.Fatalf("issuer host %q must be the cognito-idp host, auth host %q", iss.Host, auth.Host)
	}
}

func TestCognitoRegionComesFromThePoolID(t *testing.T) {
	p, err := providers.Cognito(providers.CognitoPool{
		HostedUIDomain: "pfx.auth.us-east-2.amazoncognito.com", UserPoolID: "ap-southeast-2_Xyz",
	}, client())
	if err != nil {
		t.Fatal(err)
	}
	if p.Issuer != "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_Xyz" {
		t.Fatalf("issuer = %q", p.Issuer)
	}
}

func TestOIDCIssuerSurvivesForeignEndpoints(t *testing.T) {
	p, err := providers.OIDC("https://idp.example.com", client())
	if err != nil {
		t.Fatal(err)
	}
	p.AuthURL, p.TokenURL, p.JWKSURL = "https://evil.example.net/a", "https://evil.example.net/t", "https://idp.example.com/k"
	if err := p.Complete(); err != nil {
		t.Fatal(err)
	}
	if p.Issuer != "https://idp.example.com" {
		t.Fatalf("issuer = %q", p.Issuer)
	}
}

func TestOIDCNeedsAnIssuerAndNeverInventsOne(t *testing.T) {
	for _, issuer := range []string{
		"", "http://idp.example.com", "https://idp.example.com?x=1", "https://idp.example.com/?", "https://idp.example.com/#",
	} {
		if _, err := providers.OIDC(issuer, client()); !errors.Is(err, federation.ErrInvalidProvider) {
			t.Fatalf("issuer %q must be refused, got %v", issuer, err)
		}
	}
	p, err := providers.OIDC("https://idp.example.com", client())
	if err != nil {
		t.Fatal(err)
	}
	if p.JWKSURL != "" || !p.NeedsDiscovery() {
		t.Fatal("the jwks url must wait for discovery")
	}
}

func TestConstructorsRefuseHostileInput(t *testing.T) {
	cases := map[string]func() (federation.Provider, error){
		"okta path":     func() (federation.Provider, error) { return providers.Okta("a.okta.com/evil", client()) },
		"okta userinfo": func() (federation.Provider, error) { return providers.Okta("u@evil.com", client()) },
		"okta http":     func() (federation.Provider, error) { return providers.Okta("http://a.okta.com", client()) },
		"okta query":    func() (federation.Provider, error) { return providers.Okta("a.okta.com?", client()) },
		"auth0 empty":   func() (federation.Provider, error) { return providers.Auth0("", client()) },
		"cognito pool": func() (federation.Provider, error) {
			return providers.Cognito(providers.CognitoPool{HostedUIDomain: "h.example.com", UserPoolID: "../a"}, client())
		},
		"cognito host": func() (federation.Provider, error) {
			return providers.Cognito(providers.CognitoPool{HostedUIDomain: "h.example.com/x", UserPoolID: "eu-west-1_a"}, client())
		},
		"keycloak http": func() (federation.Provider, error) {
			return providers.Keycloak(providers.KeycloakRealm{BaseURL: "http://sso.example.com", Realm: "r"}, client())
		},
		"keycloak realm": func() (federation.Provider, error) {
			return providers.Keycloak(providers.KeycloakRealm{BaseURL: "https://sso.example.com", Realm: "a/b"}, client())
		},
		"keycloak query": func() (federation.Provider, error) {
			return providers.Keycloak(providers.KeycloakRealm{BaseURL: "https://sso.example.com?x=1", Realm: "r"}, client())
		},
		"keycloak empty query": func() (federation.Provider, error) {
			return providers.Keycloak(providers.KeycloakRealm{BaseURL: "https://sso.example.com/?", Realm: "r"}, client())
		},
		"gitlab credentials": func() (federation.Provider, error) { return providers.GitLab("https://u:p@git.example.com", client()) },
		"gitlab empty query": func() (federation.Provider, error) { return providers.GitLab("https://gitlab.com/?", client()) },
		"gitlab empty fragment": func() (federation.Provider, error) {
			return providers.GitLab("https://gitlab.com/#", client())
		},
		"empty client id": func() (federation.Provider, error) {
			return providers.Google(providers.Client{Secret: federation.NewSecret("s")})
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := build(); !errors.Is(err, federation.ErrInvalidProvider) {
				t.Fatalf("err = %v, want ErrInvalidProvider", err)
			}
		})
	}
}

func TestClaimBasedTrustsNothingUntilDomainsAreSet(t *testing.T) {
	p, err := providers.Okta("dev-1.okta.com", client())
	if err != nil {
		t.Fatal(err)
	}
	if p.EmailVerification != federation.ClaimBased || p.Verified("a@example.com", true) {
		t.Fatalf("got %v", p.EmailVerification)
	}
	p.Domains = []string{"example.com"}
	if err := p.Complete(); err != nil {
		t.Fatal(err)
	}
	if !p.Verified("a@example.com", true) || p.Verified("a@example.com", false) {
		t.Fatal("a listed domain is trusted only with a true claim")
	}
}

func TestSelfHostedGitLabIsNotTrustedByDefault(t *testing.T) {
	p, err := providers.GitLab("https://git.example.com/", client())
	if err != nil {
		t.Fatal(err)
	}
	if p.EmailVerification != federation.ClaimBased || p.Issuer != "https://git.example.com" || p.Verified("a@example.com", true) {
		t.Fatalf("got %v %q", p.EmailVerification, p.Issuer)
	}
}

func TestAuth0IssuerKeepsTrailingSlash(t *testing.T) {
	p, err := providers.Auth0("https://t.eu.auth0.com/", client())
	if err != nil {
		t.Fatal(err)
	}
	if p.Issuer != "https://t.eu.auth0.com/" {
		t.Fatalf("issuer = %q", p.Issuer)
	}
}

func TestAdjustedSpecIsValidated(t *testing.T) {
	p, err := providers.Google(client())
	if err != nil {
		t.Fatal(err)
	}
	p.Name, p.Scopes = "g2", []string{"openid"}
	if err := p.Complete(); err != nil {
		t.Fatal(err)
	}
	p.Name = "Bad Name"
	if err := p.Validate(); !errors.Is(err, federation.ErrInvalidProvider) {
		t.Fatal("a bad name must be refused")
	}
}

func TestClientSecretIsNeverFormatted(t *testing.T) {
	c := client()
	p, err := providers.Google(c)
	if err != nil {
		t.Fatal(err)
	}
	type unexported struct {
		c providers.Client
		p federation.Provider
	}
	pj, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	cj, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var slogOut bytes.Buffer
	slog.New(slog.NewJSONHandler(&slogOut, nil)).Info("cfg", "client", c, "providers", []federation.Provider{p})
	for _, s := range []string{
		fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c),
		fmt.Sprintf("%+v", unexported{c, p}), fmt.Sprintf("%#v", unexported{c, p}),
		string(pj), string(cj), slogOut.String(),
	} {
		if strings.Contains(s, "SUPERSECRET") {
			t.Fatalf("secret leaked in %q", s)
		}
	}
	if p.ClientSecret.Reveal() != "SUPERSECRET" {
		t.Fatal("the secret must reach the spec")
	}
}
