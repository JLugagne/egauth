package oauth

import (
	"context"
	"net/http"
	"strconv"
)

// GitHub endpoints.
const (
	githubAuthURL      = "https://github.com/login/oauth/authorize"
	githubTokenURL     = "https://github.com/login/oauth/access_token"
	githubUserURL      = "https://api.github.com/user"
	githubUserEmailURL = "https://api.github.com/user/emails"
)

// GitHub builds a Provider for GitHub sign-in. Default scopes request the user profile and
// email addresses (GitHub does not expose a private primary email without "user:email").
func GitHub(clientID, clientSecret string, opts ...ProviderOption) *Provider {
	return New("github", clientID, clientSecret, githubAuthURL, githubTokenURL,
		[]string{"read:user", "user:email"}, fetchGitHubUser, opts...)
}

func fetchGitHubUser(ctx context.Context, c *http.Client, accessToken string) (*UserInfo, error) {
	var profile struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := getJSON(ctx, c, githubUserURL, accessToken, &profile); err != nil {
		return nil, err
	}

	info := &UserInfo{
		ProviderID: strconv.FormatInt(profile.ID, 10),
		Email:      profile.Email,
		Name:       profile.Name,
	}

	// The profile email is null when the user keeps it private; resolve the primary verified
	// address from the dedicated endpoint. Its absence is not fatal — the caller decides what
	// to do with an empty email.
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := getJSON(ctx, c, githubUserEmailURL, accessToken, &emails); err == nil {
		for _, e := range emails {
			if e.Primary {
				info.Email = e.Email
				info.EmailVerified = e.Verified
				break
			}
		}
	}

	return info, nil
}
