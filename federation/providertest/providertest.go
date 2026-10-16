// Package providertest is the contract suite of federation providers (G25). Run executes it over
// every built-in provider, Discord and LinkedIn included.
package providertest

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/federation/providers"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/principal"
	storefed "github.com/JLugagne/egauth/store/federation"
)

// Case describes one built-in provider and what it must declare. Issuer is empty for a provider
// that is not OIDC. Build receives the client ID the suite wants to use, possibly empty, and
// returns a spec whose endpoints and JWKS are resolved.
type Case struct {
	Name         string
	Build        func(clientID string) (federation.Provider, error)
	Issuer       string
	Verification federation.EmailVerification
}

// Builtins returns one Case per built-in constructor of the providers package.
func Builtins() []Case {
	const poolID = "eu-west-1_AbCdEf"
	const directory = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"
	client := func(id string) providers.Client {
		return providers.Client{ID: id, Secret: federation.NewSecret("s")}
	}
	return []Case{
		{"Google", func(id string) (federation.Provider, error) { return providers.Google(client(id)) },
			"https://accounts.google.com", federation.Always},
		{"Apple", func(id string) (federation.Provider, error) { return providers.Apple(client(id)) },
			"https://appleid.apple.com", federation.Always},
		{"Microsoft", func(id string) (federation.Provider, error) { return providers.Microsoft(directory, client(id)) },
			"https://login.microsoftonline.com/" + directory + "/v2.0", federation.Never},
		{"Okta", func(id string) (federation.Provider, error) { return providers.Okta("dev-1.okta.com", client(id)) },
			"https://dev-1.okta.com", federation.ClaimBased},
		{"Auth0", func(id string) (federation.Provider, error) { return providers.Auth0("t.eu.auth0.com", client(id)) },
			"https://t.eu.auth0.com/", federation.ClaimBased},
		{"Cognito", func(id string) (federation.Provider, error) {
			return providers.Cognito(providers.CognitoPool{
				HostedUIDomain: "pfx.auth.eu-west-1.amazoncognito.com", UserPoolID: poolID,
			}, client(id))
		}, "https://cognito-idp.eu-west-1.amazonaws.com/" + poolID, federation.ClaimBased},
		{"Keycloak", func(id string) (federation.Provider, error) {
			return providers.Keycloak(providers.KeycloakRealm{BaseURL: "https://sso.example.com", Realm: "corp"}, client(id))
		}, "https://sso.example.com/realms/corp", federation.ClaimBased},
		{"GitLab", func(id string) (federation.Provider, error) {
			return providers.GitLab("https://gitlab.com", client(id))
		}, "https://gitlab.com", federation.Always},
		{"GitLabSelfHosted", func(id string) (federation.Provider, error) {
			return providers.GitLab("https://git.example.com", client(id))
		}, "https://git.example.com", federation.ClaimBased},
		{"GitHub", func(id string) (federation.Provider, error) { return providers.GitHub(client(id)) },
			"", federation.Always},
		{"Facebook", func(id string) (federation.Provider, error) { return providers.Facebook(client(id)) },
			"", federation.Never},
		{"Discord", func(id string) (federation.Provider, error) { return providers.Discord(client(id)) },
			"", federation.Never},
		{"LinkedIn", func(id string) (federation.Provider, error) { return providers.LinkedIn(client(id)) },
			"https://www.linkedin.com/oauth", federation.Always},
		{"OIDC", func(id string) (federation.Provider, error) {
			p, err := providers.OIDC("https://idp.example.com", client(id))
			if err != nil {
				return p, err
			}
			p.AuthURL, p.TokenURL, p.JWKSURL = "https://auth.example.net/a", "https://auth.example.net/t", "https://idp.example.com/keys"
			return p, nil
		}, "https://idp.example.com", federation.ClaimBased},
	}
}

// Run executes the G25 suite over cases, or over Builtins when none is given.
func Run(t *testing.T, cases ...Case) {
	t.Helper()
	if len(cases) == 0 {
		cases = Builtins()
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			t.Run("EmptyClientID", func(t *testing.T) { emptyClientID(t, c) })
			t.Run("EmailVerificationDeclared", func(t *testing.T) { verificationDeclared(t, c) })
			t.Run("IssuerAndJWKS", func(t *testing.T) { issuerAndJWKS(t, c) })
			t.Run("FalseClaimRefused", func(t *testing.T) { falseClaimRefused(t, c) })
			t.Run("RuntimeCap", func(t *testing.T) { runtimeCap(t, c) })
		})
	}
}

func build(t *testing.T, c Case) federation.Provider {
	t.Helper()
	p, err := c.Build("client-id")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := p.Complete(); err != nil {
		t.Fatalf("spec is not complete: %v", err)
	}
	return p
}

func emptyClientID(t *testing.T, c Case) {
	p, err := c.Build("")
	if err == nil {
		t.Fatalf("an empty client id must be refused, got %v", p)
	}
	if !errors.Is(err, federation.ErrInvalidProvider) {
		t.Fatalf("error must wrap ErrInvalidProvider, got %v", err)
	}
}

func verificationDeclared(t *testing.T, c Case) {
	p := build(t, c)
	if !p.EmailVerification.Valid() {
		t.Fatalf("undeclared email verification %d", p.EmailVerification)
	}
	if p.EmailVerification != c.Verification {
		t.Fatalf("email verification = %v, want %v", p.EmailVerification, c.Verification)
	}
}

func issuerAndJWKS(t *testing.T, c Case) {
	p := build(t, c)
	if p.Issuer != c.Issuer {
		t.Fatalf("issuer = %q, want %q", p.Issuer, c.Issuer)
	}
	if c.Issuer != "" && p.JWKSURL == "" {
		t.Fatal("an OIDC provider must pin a JWKS url")
	}
	if c.Issuer == "" && p.JWKSURL != "" {
		t.Fatal("a plain OAuth2 provider has no JWKS")
	}
}

func falseClaimRefused(t *testing.T, c Case) {
	p := build(t, c)
	p.Domains = []string{"example.com"}
	for _, email := range []string{"victim@example.com", "victim@corp.example"} {
		if p.Verified(email, false) {
			t.Fatalf("a false email_verified claim must never be upgraded (%s)", email)
		}
	}
}

func runtimeCap(t *testing.T, c Case) {
	p := build(t, c)
	tenant, err := principal.ParseTenantID("t1")
	if err != nil {
		t.Fatal(err)
	}
	session, err := core.SessionCaller(principaltest.Full(), uuid.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	system, err := core.SystemCaller(tenant, "providertest")
	if err != nil {
		t.Fatal(err)
	}

	withDomains := p
	withDomains.Domains = []string{"example.com"}
	if _, err := federation.ForRuntime(withDomains, session); !errors.Is(err, federation.ErrDomainsSystemOnly) {
		t.Fatalf("a session caller must not set domains, got %v", err)
	}

	got, err := federation.ForRuntime(p, session)
	if err != nil {
		t.Fatal(err)
	}
	if got.EmailVerification != federation.Never || got.Verified("a@example.com", true) {
		t.Fatalf("a runtime spec without domains must trust no email, got %v", got.EmailVerification)
	}

	always := withDomains
	always.EmailVerification = federation.Always
	got, err = federation.ForRuntime(always, system)
	if err != nil {
		t.Fatal(err)
	}
	assertCapped(t, got)

	stored, err := federation.FromStore(storefed.ProviderSpec{
		Name: always.Name, ClientID: always.ClientID, AuthURL: always.AuthURL, TokenURL: always.TokenURL,
		UserInfoURL: always.UserInfoURL, Scopes: always.Scopes, Issuer: always.Issuer, JWKSURL: always.JWKSURL,
		Domains: always.Domains, EmailVerification: federation.Always,
	}, always.ClientSecret)
	if err != nil {
		t.Fatal(err)
	}
	assertCapped(t, stored)
}

func assertCapped(t *testing.T, got federation.Provider) {
	t.Helper()
	if got.EmailVerification != federation.ClaimBased {
		t.Fatalf("a runtime spec must be capped at ClaimBased, got %v", got.EmailVerification)
	}
	if !got.Verified("a@example.com", true) {
		t.Fatal("a claimed email of a listed domain must be honoured")
	}
	for _, email := range []string{"a@evil.com", "a@sub.example.com", "a@example.com.evil.com", "a@evil.com@example.com"} {
		if got.Verified(email, true) {
			t.Fatalf("%s is outside Domains", email)
		}
	}
	if got.Verified("a@example.com", false) {
		t.Fatal("an unverified claim must be refused")
	}
}
