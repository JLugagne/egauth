package providers

import (
	"strings"

	"github.com/JLugagne/egauth/federation"
)

// Microsoft builds the spec of a single Microsoft Entra ID directory. tenant must be the directory
// GUID: Entra id_tokens carry the GUID form of the issuer even when the tenant is addressed by a
// verified domain, and the multi-tenant values "common", "organizations" and "consumers" have no
// fixed issuer, so all of them are refused rather than pinned to an issuer no token matches. The
// Graph userinfo endpoint carries no email_verified claim, so its email is never trusted.
func Microsoft(tenant string, c Client) (federation.Provider, error) {
	tenant = strings.ToLower(strings.TrimSpace(tenant))
	if !guidPattern.MatchString(tenant) {
		return federation.Provider{}, invalidArg("tenant must be a directory guid")
	}
	root := "https://login.microsoftonline.com/" + tenant
	return build(federation.Provider{
		Name:              "microsoft",
		AuthURL:           root + "/oauth2/v2.0/authorize",
		TokenURL:          root + "/oauth2/v2.0/token",
		UserInfoURL:       "https://graph.microsoft.com/oidc/userinfo",
		Scopes:            oidcScopes(),
		Issuer:            root + "/v2.0",
		JWKSURL:           root + "/discovery/v2.0/keys",
		EmailVerification: federation.Never,
	}, c)
}

// Okta builds the spec of the org authorization server of an Okta domain such as
// "example.okta.com". It is ClaimBased: emails are trusted only once Domains is set.
func Okta(domain string, c Client) (federation.Provider, error) {
	host, err := hostOnly("domain", domain)
	if err != nil {
		return federation.Provider{}, err
	}
	root := "https://" + host
	return build(federation.Provider{
		Name:              "okta",
		AuthURL:           root + "/oauth2/v1/authorize",
		TokenURL:          root + "/oauth2/v1/token",
		UserInfoURL:       root + "/oauth2/v1/userinfo",
		Scopes:            oidcScopes(),
		Issuer:            root,
		JWKSURL:           root + "/oauth2/v1/keys",
		EmailVerification: federation.ClaimBased,
	}, c)
}

// Auth0 builds the spec of an Auth0 domain. Its issuer carries a trailing slash. It is ClaimBased:
// emails are trusted only once Domains is set.
func Auth0(domain string, c Client) (federation.Provider, error) {
	host, err := hostOnly("domain", domain)
	if err != nil {
		return federation.Provider{}, err
	}
	root := "https://" + host
	return build(federation.Provider{
		Name:              "auth0",
		AuthURL:           root + "/authorize",
		TokenURL:          root + "/oauth/token",
		UserInfoURL:       root + "/userinfo",
		Scopes:            oidcScopes(),
		Issuer:            root + "/",
		JWKSURL:           root + "/.well-known/jwks.json",
		EmailVerification: federation.ClaimBased,
	}, c)
}

// CognitoPool locates an Amazon Cognito user pool. The OAuth endpoints live on HostedUIDomain while
// the issuer and JWKS live on the cognito-idp host of the pool's region, which is the prefix of
// UserPoolID ("eu-west-1_AbC").
type CognitoPool struct {
	HostedUIDomain string
	UserPoolID     string
}

// Cognito builds the spec of an Amazon Cognito user pool. It is ClaimBased: emails are trusted
// only once Domains is set.
func Cognito(pool CognitoPool, c Client) (federation.Provider, error) {
	host, err := hostOnly("hosted ui domain", pool.HostedUIDomain)
	if err != nil {
		return federation.Provider{}, err
	}
	m := poolPattern.FindStringSubmatch(pool.UserPoolID)
	if m == nil {
		return federation.Provider{}, invalidArg("user pool id is malformed")
	}
	root := "https://" + host
	issuer := "https://cognito-idp." + m[1] + ".amazonaws.com/" + pool.UserPoolID
	return build(federation.Provider{
		Name:              "cognito",
		AuthURL:           root + "/oauth2/authorize",
		TokenURL:          root + "/oauth2/token",
		UserInfoURL:       root + "/oauth2/userInfo",
		Scopes:            oidcScopes(),
		Issuer:            issuer,
		JWKSURL:           issuer + "/.well-known/jwks.json",
		EmailVerification: federation.ClaimBased,
	}, c)
}

// KeycloakRealm locates a Keycloak realm. BaseURL is the https server root, with the "/auth"
// prefix on older deployments.
type KeycloakRealm struct {
	BaseURL string
	Realm   string
}

// Keycloak builds the spec of a Keycloak realm. It is ClaimBased: emails are trusted only once
// Domains is set.
func Keycloak(realm KeycloakRealm, c Client) (federation.Provider, error) {
	root, err := baseURL("base url", realm.BaseURL)
	if err != nil {
		return federation.Provider{}, err
	}
	if err := label("realm", realm.Realm); err != nil {
		return federation.Provider{}, err
	}
	realmURL := root + "/realms/" + realm.Realm
	oidc := realmURL + "/protocol/openid-connect"
	return build(federation.Provider{
		Name:              "keycloak",
		AuthURL:           oidc + "/auth",
		TokenURL:          oidc + "/token",
		UserInfoURL:       oidc + "/userinfo",
		Scopes:            oidcScopes(),
		Issuer:            realmURL,
		JWKSURL:           oidc + "/certs",
		EmailVerification: federation.ClaimBased,
	}, c)
}

// GitLab builds the spec of GitLab at base, "https://gitlab.com" or a self-managed instance.
// gitlab.com's email_verified claim is trusted for every domain; a self-managed instance is
// ClaimBased and trusts emails only once Domains is set.
func GitLab(base string, c Client) (federation.Provider, error) {
	root, err := baseURL("base", base)
	if err != nil {
		return federation.Provider{}, err
	}
	verification := federation.ClaimBased
	if root == "https://gitlab.com" {
		verification = federation.Always
	}
	return build(federation.Provider{
		Name:              "gitlab",
		AuthURL:           root + "/oauth/authorize",
		TokenURL:          root + "/oauth/token",
		UserInfoURL:       root + "/oauth/userinfo",
		Scopes:            oidcScopes(),
		Issuer:            root,
		JWKSURL:           root + "/oauth/discovery/keys",
		EmailVerification: verification,
	}, c)
}

// OIDC builds the spec of any OpenID Connect issuer. The issuer is pinned as given and must carry
// no query or fragment; endpoints and JWKS stay empty until discovery fills them. It is
// ClaimBased: emails are trusted only once Domains is set.
func OIDC(issuer string, c Client) (federation.Provider, error) {
	if issuer == "" {
		return federation.Provider{}, invalidArg("issuer is empty")
	}
	return build(federation.Provider{
		Name:              "oidc",
		Scopes:            oidcScopes(),
		Issuer:            issuer,
		EmailVerification: federation.ClaimBased,
	}, c)
}
