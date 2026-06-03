package providers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/JLugagne/egauth/oauth"
)

// Apple endpoints ("Sign in with Apple", OpenID Connect).
const (
	appleAuthURL  = "https://appleid.apple.com/auth/authorize"
	appleTokenURL = "https://appleid.apple.com/auth/token"

	// AppleIssuer and AppleJWKSURL are Apple's OIDC issuer and JWKS endpoint. Apple has no
	// userinfo endpoint — all profile data comes from the id_token — so Apple MUST be used with
	// oauth.WithOIDC. Pass these for id_token validation.
	AppleIssuer  = "https://appleid.apple.com"
	AppleJWKSURL = "https://appleid.apple.com/auth/keys"
)

// Apple builds a Provider for "Sign in with Apple" (OpenID Connect). Default scopes request the
// OpenID identity and email.
//
// Apple has two important quirks the caller must handle:
//
//   - There is NO userinfo endpoint. The user's identity is carried only by the id_token, so
//     Apple must be configured with oauth.WithOIDC; without it, Exchange returns an error. Use:
//
//     providers.Apple(id, clientSecret, oauth.WithOIDC(oauth.OIDCConfig{
//     Issuer: providers.AppleIssuer, JWKSURL: providers.AppleJWKSURL, Audience: id,
//     }))
//
//   - The "client secret" is not a static string. Apple requires a short-lived ES256-signed JWT
//     generated from your private key (the Services ID, Team ID, Key ID and .p8 key). Generate
//     it yourself and pass the resulting JWT as clientSecret, refreshing it before it expires.
//     The user's name is only returned by Apple on the first authorization, and via the
//     front-channel form post rather than the id_token, so persist it on first sign-in.
func Apple(servicesID, clientSecretJWT string, opts ...oauth.ProviderOption) *oauth.Provider {
	return oauth.New("apple", servicesID, clientSecretJWT, appleAuthURL, appleTokenURL,
		[]string{"openid", "email"}, fetchAppleUser, opts...)
}

// fetchAppleUser is only reached when Apple is configured WITHOUT oauth.WithOIDC, which is
// unsupported: Apple exposes no userinfo endpoint. It returns a descriptive error instead of
// making a doomed request.
func fetchAppleUser(_ context.Context, _ *http.Client, _ string) (*oauth.UserInfo, error) {
	return nil, fmt.Errorf("%w: Apple has no userinfo endpoint; configure providers.Apple with oauth.WithOIDC", oauth.ErrUserInfoFailed)
}
