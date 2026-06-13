// Package providers ships ready-made oauth.Provider constructors for well-known identity
// providers (Discord, GitHub, Google). They are thin wrappers over oauth.New and live in a
// dedicated package so the core oauth machinery stays free of provider-specific endpoints and
// userinfo parsing. Write your own constructor the same way: call oauth.New with the provider
// endpoints and a fetch func built on oauth.GetJSON.
package providers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/JLugagne/egauth/oauth"
)

// Discord endpoints.
const (
	discordAuthURL     = "https://discord.com/api/oauth2/authorize"
	discordTokenURL    = "https://discord.com/api/oauth2/token"
	discordUserInfoURL = "https://discord.com/api/users/@me"
)

// Discord builds a Provider for Discord sign-in. Default scopes request the basic identity
// and the user's email.
func Discord(clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider {
	return oauth.New("discord", clientID, clientSecret, discordAuthURL, discordTokenURL,
		[]string{"identify", "email"}, fetchDiscordUser, opts...)
}

func fetchDiscordUser(ctx context.Context, c *http.Client, accessToken string) (*oauth.UserInfo, error) {
	var u struct {
		ID       string `json:"id"`
		Email    string `json:"email"`
		Verified bool   `json:"verified"`
		Username string `json:"username"`
	}
	if err := oauth.GetJSON(ctx, c, discordUserInfoURL, accessToken, &u); err != nil {
		return nil, err
	}
	if u.ID == "" {
		return nil, fmt.Errorf("%w: provider returned no subject id", oauth.ErrUserInfoFailed)
	}
	return &oauth.UserInfo{
		ProviderID:    u.ID,
		Email:         u.Email,
		EmailVerified: u.Verified,
		Name:          u.Username,
	}, nil
}
