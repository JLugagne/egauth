package providers

import (
	"context"
	"net/http"

	"github.com/JLugagne/egauth/oauth"
)

// Google endpoints (OpenID Connect).
const (
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

	// GoogleIssuer and GoogleJWKSURL are Google's published OIDC issuer and JWKS endpoint. Pass
	// them to oauth.WithOIDC to validate Google's id_token (with nonce replay protection)
	// instead of relying on the access-token userinfo GET:
	//
	//	providers.Google(id, secret, oauth.WithOIDC(oauth.OIDCConfig{
	//	    Issuer: providers.GoogleIssuer, JWKSURL: providers.GoogleJWKSURL,
	//	}))
	GoogleIssuer  = "https://accounts.google.com"
	GoogleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"
)

// Google builds a Provider for Google sign-in (OpenID Connect). Default scopes request the
// OpenID identity, email and basic profile. By default the user is resolved via the userinfo
// endpoint; add oauth.WithOIDC(oauth.OIDCConfig{Issuer: GoogleIssuer, JWKSURL: GoogleJWKSURL})
// for id_token validation.
func Google(clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider {
	return oauth.New("google", clientID, clientSecret, googleAuthURL, googleTokenURL,
		[]string{"openid", "email", "profile"}, fetchGoogleUser, opts...)
}

func fetchGoogleUser(ctx context.Context, c *http.Client, accessToken string) (*oauth.UserInfo, error) {
	var u struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := oauth.GetJSON(ctx, c, googleUserInfoURL, accessToken, &u); err != nil {
		return nil, err
	}
	return &oauth.UserInfo{
		ProviderID:    u.Sub,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
	}, nil
}
