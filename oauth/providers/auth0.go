package providers

import (
	"github.com/JLugagne/egauth/oauth"
)

// Auth0 builds a Provider for Auth0 sign-in (OpenID Connect) on the given Auth0 domain (for
// example "your-tenant.us.auth0.com" or a custom domain). The endpoints are derived from the
// domain; the user is resolved via the /userinfo endpoint.
//
// To validate the id_token, pass oauth.WithOIDC with Auth0Issuer / Auth0JWKSURL. Note that
// Auth0's issuer carries a TRAILING SLASH ("https://your-tenant.us.auth0.com/"); Auth0Issuer
// returns it in that exact form so id_token "iss" validation matches:
//
//	providers.Auth0(domain, id, secret, oauth.WithOIDC(oauth.OIDCConfig{
//	    Issuer: providers.Auth0Issuer(domain), JWKSURL: providers.Auth0JWKSURL(domain),
//	}))
func Auth0(domain, clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider {
	base := normalizeHTTPSDomain(domain)
	authURL := base + "/authorize"
	tokenURL := base + "/oauth/token"
	userInfoURL := base + "/userinfo"
	return oauth.New("auth0", clientID, clientSecret, authURL, tokenURL,
		[]string{"openid", "email", "profile"}, oidcUserInfoFetcher(userInfoURL), opts...)
}

// Auth0Issuer returns the Auth0 OIDC issuer for domain, including the trailing slash that Auth0
// places in the id_token "iss" claim.
func Auth0Issuer(domain string) string {
	return normalizeHTTPSDomain(domain) + "/"
}

// Auth0JWKSURL returns the Auth0 JWKS endpoint for domain.
func Auth0JWKSURL(domain string) string {
	return normalizeHTTPSDomain(domain) + "/.well-known/jwks.json"
}
