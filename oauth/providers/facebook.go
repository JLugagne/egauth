package providers

import (
	"context"
	"net/http"

	"github.com/JLugagne/egauth/oauth"
)

// Facebook endpoints (OAuth2 + Graph API). Facebook is not an OIDC provider, so there is no
// issuer/JWKS pair and the user is always resolved from the Graph /me endpoint.
const (
	facebookGraphVersion = "v22.0"
	facebookAuthURL      = "https://www.facebook.com/" + facebookGraphVersion + "/dialog/oauth"
	facebookTokenURL     = "https://graph.facebook.com/" + facebookGraphVersion + "/oauth/access_token"
	facebookUserInfoURL  = "https://graph.facebook.com/" + facebookGraphVersion + "/me?fields=id,name,email"
)

// Facebook builds a Provider for Facebook sign-in. Default scopes request the public profile
// and email. Facebook is a plain OAuth2 provider (not OIDC): the user is resolved from the
// Graph API /me endpoint, and Facebook does not expose an email-verified signal, so
// UserInfo.EmailVerified is always false. PKCE is supported and stays enabled by default.
func Facebook(clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider {
	return oauth.New("facebook", clientID, clientSecret, facebookAuthURL, facebookTokenURL,
		[]string{"public_profile", "email"}, fetchFacebookUser, opts...)
}

func fetchFacebookUser(ctx context.Context, c *http.Client, accessToken string) (*oauth.UserInfo, error) {
	var u struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := oauth.GetJSON(ctx, c, facebookUserInfoURL, accessToken, &u); err != nil {
		return nil, err
	}
	return &oauth.UserInfo{
		ProviderID: u.ID,
		Email:      u.Email,
		Name:       u.Name,
	}, nil
}
