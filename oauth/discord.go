package oauth

import (
	"context"
	"net/http"
)

// Discord endpoints.
const (
	discordAuthURL     = "https://discord.com/api/oauth2/authorize"
	discordTokenURL    = "https://discord.com/api/oauth2/token"
	discordUserInfoURL = "https://discord.com/api/users/@me"
)

// Discord builds a Provider for Discord sign-in. Default scopes request the basic identity
// and the user's email.
func Discord(clientID, clientSecret string, opts ...ProviderOption) *Provider {
	return New("discord", clientID, clientSecret, discordAuthURL, discordTokenURL,
		[]string{"identify", "email"}, fetchDiscordUser, opts...)
}

func fetchDiscordUser(ctx context.Context, c *http.Client, accessToken string) (*UserInfo, error) {
	var u struct {
		ID       string `json:"id"`
		Email    string `json:"email"`
		Verified bool   `json:"verified"`
		Username string `json:"username"`
	}
	if err := getJSON(ctx, c, discordUserInfoURL, accessToken, &u); err != nil {
		return nil, err
	}
	return &UserInfo{
		ProviderID:    u.ID,
		Email:         u.Email,
		EmailVerified: u.Verified,
		Name:          u.Username,
	}, nil
}
