package providers

import (
	"context"
	"net/http"

	"github.com/JLugagne/egauth/oauth"
)

// Okta builds a Provider for Okta sign-in (OpenID Connect) against the org authorization server
// on the given Okta domain (for example "dev-12345.okta.com" or "example.okta.com"). The org
// server's endpoints live under /oauth2/v1 and its issuer is the domain itself.
//
// To validate the id_token, pass oauth.WithOIDC with the issuer and JWKS URL returned by
// OktaIssuer / OktaJWKSURL:
//
//	issuer := providers.OktaIssuer(domain)
//	providers.Okta(domain, id, secret, oauth.WithOIDC(oauth.OIDCConfig{
//	    Issuer: issuer, JWKSURL: providers.OktaJWKSURL(domain),
//	}))
//
// Most Okta tenants instead front their apps with a *custom* authorization server (commonly the
// one named "default"); use OktaCustom for those.
func Okta(domain, clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider {
	base := normalizeHTTPSDomain(domain)
	return newOktaProvider(base+"/oauth2/v1", clientID, clientSecret, opts...)
}

// OktaCustom builds a Provider for an Okta custom authorization server identified by
// authServerID (for example "default") on the given domain. Its endpoints and issuer are scoped
// under /oauth2/{authServerID}. Pass OktaCustomIssuer / OktaCustomJWKSURL to oauth.WithOIDC.
func OktaCustom(domain, authServerID, clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider {
	base := normalizeHTTPSDomain(domain)
	return newOktaProvider(base+"/oauth2/"+authServerID+"/v1", clientID, clientSecret, opts...)
}

func newOktaProvider(prefix, clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider {
	authURL := prefix + "/authorize"
	tokenURL := prefix + "/token"
	userInfoURL := prefix + "/userinfo"
	return oauth.New("okta", clientID, clientSecret, authURL, tokenURL,
		[]string{"openid", "email", "profile"}, oidcUserInfoFetcher(userInfoURL), opts...)
}

// OktaIssuer returns the issuer for the org authorization server on domain.
func OktaIssuer(domain string) string { return normalizeHTTPSDomain(domain) }

// OktaJWKSURL returns the JWKS endpoint for the org authorization server on domain.
func OktaJWKSURL(domain string) string { return normalizeHTTPSDomain(domain) + "/oauth2/v1/keys" }

// OktaCustomIssuer returns the issuer for a custom authorization server (authServerID) on domain.
func OktaCustomIssuer(domain, authServerID string) string {
	return normalizeHTTPSDomain(domain) + "/oauth2/" + authServerID
}

// OktaCustomJWKSURL returns the JWKS endpoint for a custom authorization server on domain.
func OktaCustomJWKSURL(domain, authServerID string) string {
	return normalizeHTTPSDomain(domain) + "/oauth2/" + authServerID + "/v1/keys"
}

// oidcUserInfoFetcher returns a FetchUserFunc that reads the standard OIDC userinfo claims from
// userInfoURL. It is shared by the standards-compliant OIDC providers (Okta, Auth0, Keycloak,
// Cognito, generic OIDC) whose userinfo response follows the OIDC StandardClaims shape.
func oidcUserInfoFetcher(userInfoURL string) oauth.FetchUserFunc {
	return func(ctx context.Context, c *http.Client, accessToken string) (*oauth.UserInfo, error) {
		var u struct {
			Sub           any    `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
		}
		if err := oauth.GetJSON(ctx, c, userInfoURL, accessToken, &u); err != nil {
			return nil, err
		}
		return &oauth.UserInfo{
			ProviderID:    stringifyID(u.Sub),
			Email:         u.Email,
			EmailVerified: u.EmailVerified,
			Name:          u.Name,
		}, nil
	}
}
