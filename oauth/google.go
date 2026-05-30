package oauth

import (
	"context"
	"net/http"
)

// Google endpoints (OpenID Connect).
const (
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

	// GoogleIssuer and GoogleJWKSURL are Google's published OIDC issuer and JWKS endpoint. Pass
	// them to WithOIDC to validate Google's id_token (with nonce replay protection) instead of
	// relying on the access-token userinfo GET:
	//
	//	oauth.Google(id, secret, oauth.WithOIDC(oauth.OIDCConfig{
	//	    Issuer: oauth.GoogleIssuer, JWKSURL: oauth.GoogleJWKSURL,
	//	}))
	GoogleIssuer  = "https://accounts.google.com"
	GoogleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"
)

// Google builds a Provider for Google sign-in (OpenID Connect). Default scopes request the
// OpenID identity, email and basic profile. By default the user is resolved via the userinfo
// endpoint; add WithOIDC(OIDCConfig{Issuer: GoogleIssuer, JWKSURL: GoogleJWKSURL}) for
// id_token validation.
func Google(clientID, clientSecret string, opts ...ProviderOption) *Provider {
	return New("google", clientID, clientSecret, googleAuthURL, googleTokenURL,
		[]string{"openid", "email", "profile"}, fetchGoogleUser, opts...)
}

func fetchGoogleUser(ctx context.Context, c *http.Client, accessToken string) (*UserInfo, error) {
	var u struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := getJSON(ctx, c, googleUserInfoURL, accessToken, &u); err != nil {
		return nil, err
	}
	return &UserInfo{
		ProviderID:    u.Sub,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
	}, nil
}
