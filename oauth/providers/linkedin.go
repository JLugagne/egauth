package providers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/JLugagne/egauth/oauth"
)

// LinkedIn endpoints (OpenID Connect — "Sign In with LinkedIn using OpenID Connect").
const (
	linkedinAuthURL     = "https://www.linkedin.com/oauth/v2/authorization"
	linkedinTokenURL    = "https://www.linkedin.com/oauth/v2/accessToken"
	linkedinUserInfoURL = "https://api.linkedin.com/v2/userinfo"

	// LinkedInIssuer and LinkedInJWKSURL are LinkedIn's OIDC issuer and JWKS endpoint. Pass them
	// to oauth.WithOIDC for id_token validation.
	LinkedInIssuer  = "https://www.linkedin.com/oauth"
	LinkedInJWKSURL = "https://www.linkedin.com/oauth/openid/jwks"
)

// LinkedIn builds a Provider for LinkedIn sign-in (OpenID Connect). Default scopes request the
// OpenID identity, email and basic profile. By default the user is resolved via the userinfo
// endpoint; add oauth.WithOIDC(oauth.OIDCConfig{Issuer: LinkedInIssuer, JWKSURL: LinkedInJWKSURL})
// for id_token validation.
func LinkedIn(clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider {
	return oauth.New("linkedin", clientID, clientSecret, linkedinAuthURL, linkedinTokenURL,
		[]string{"openid", "email", "profile"}, fetchLinkedInUser, opts...)
}

func fetchLinkedInUser(ctx context.Context, c *http.Client, accessToken string) (*oauth.UserInfo, error) {
	var u struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := oauth.GetJSON(ctx, c, linkedinUserInfoURL, accessToken, &u); err != nil {
		return nil, err
	}
	if u.Sub == "" {
		return nil, fmt.Errorf("%w: provider returned no subject id", oauth.ErrUserInfoFailed)
	}
	return &oauth.UserInfo{
		ProviderID:    u.Sub,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
	}, nil
}
