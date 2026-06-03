package providers

import (
	"github.com/JLugagne/egauth/oauth"
)

// Keycloak builds a Provider for a Keycloak realm (OpenID Connect). baseURL is the Keycloak
// server root (for example "https://sso.example.com"; older deployments include an "/auth"
// path prefix in the base URL), and realm is the realm name. All endpoints live under
// {baseURL}/realms/{realm}/protocol/openid-connect.
//
// To validate the id_token, pass oauth.WithOIDC with KeycloakIssuer / KeycloakJWKSURL:
//
//	providers.Keycloak(baseURL, realm, id, secret, oauth.WithOIDC(oauth.OIDCConfig{
//	    Issuer:  providers.KeycloakIssuer(baseURL, realm),
//	    JWKSURL: providers.KeycloakJWKSURL(baseURL, realm),
//	}))
func Keycloak(baseURL, realm, clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider {
	prefix := keycloakPrefix(baseURL, realm)
	authURL := prefix + "/auth"
	tokenURL := prefix + "/token"
	userInfoURL := prefix + "/userinfo"
	return oauth.New("keycloak", clientID, clientSecret, authURL, tokenURL,
		[]string{"openid", "email", "profile"}, oidcUserInfoFetcher(userInfoURL), opts...)
}

// KeycloakIssuer returns the OIDC issuer for a Keycloak realm. Keycloak's issuer is
// {baseURL}/realms/{realm} (no trailing slash).
func KeycloakIssuer(baseURL, realm string) string {
	return normalizeHTTPSDomain(baseURL) + "/realms/" + realm
}

// KeycloakJWKSURL returns the JWKS endpoint for a Keycloak realm.
func KeycloakJWKSURL(baseURL, realm string) string {
	return keycloakPrefix(baseURL, realm) + "/certs"
}

func keycloakPrefix(baseURL, realm string) string {
	return normalizeHTTPSDomain(baseURL) + "/realms/" + realm + "/protocol/openid-connect"
}
