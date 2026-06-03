package providers

import (
	"github.com/JLugagne/egauth/oauth"
)

// Cognito builds a Provider for an Amazon Cognito user pool (OpenID Connect).
//
// Cognito splits its endpoints across two hosts, so this constructor takes both:
//
//   - hostedUIDomain is the user pool's hosted-UI domain that serves the OAuth endpoints, either
//     the Cognito-managed form ("your-prefix.auth.us-east-1.amazoncognito.com") or your custom
//     domain. The /oauth2/authorize, /oauth2/token and /oauth2/userInfo endpoints live here.
//   - region and userPoolID identify the token issuer host
//     ("cognito-idp.{region}.amazonaws.com/{userPoolID}"), which serves the id_token "iss" claim
//     and the JWKS. Pass CognitoIssuer / CognitoJWKSURL (built from these) to oauth.WithOIDC.
//
// Example with id_token validation:
//
//	providers.Cognito(hostedUI, region, poolID, id, secret, oauth.WithOIDC(oauth.OIDCConfig{
//	    Issuer:  providers.CognitoIssuer(region, poolID),
//	    JWKSURL: providers.CognitoJWKSURL(region, poolID),
//	}))
func Cognito(hostedUIDomain, region, userPoolID, clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider {
	base := normalizeHTTPSDomain(hostedUIDomain)
	authURL := base + "/oauth2/authorize"
	tokenURL := base + "/oauth2/token"
	userInfoURL := base + "/oauth2/userInfo"
	return oauth.New("cognito", clientID, clientSecret, authURL, tokenURL,
		[]string{"openid", "email", "profile"}, oidcUserInfoFetcher(userInfoURL), opts...)
}

// CognitoIssuer returns the OIDC issuer for a Cognito user pool. Note this is the cognito-idp
// host, not the hosted-UI domain.
func CognitoIssuer(region, userPoolID string) string {
	return "https://cognito-idp." + region + ".amazonaws.com/" + userPoolID
}

// CognitoJWKSURL returns the JWKS endpoint for a Cognito user pool.
func CognitoJWKSURL(region, userPoolID string) string {
	return CognitoIssuer(region, userPoolID) + "/.well-known/jwks.json"
}
