package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/JLugagne/egauth/oauth"
)

// GitLab.com endpoints (OpenID Connect). For a self-hosted instance use GitLabSelfHosted.
const (
	gitlabBaseURL = "https://gitlab.com"

	// GitLabIssuer and GitLabJWKSURL are GitLab.com's OIDC issuer and JWKS endpoint. Pass them to
	// oauth.WithOIDC for id_token validation. For a self-hosted instance derive the equivalents
	// from your base URL (issuer = base URL, JWKS = baseURL + "/oauth/discovery/keys").
	GitLabIssuer  = gitlabBaseURL
	GitLabJWKSURL = gitlabBaseURL + "/oauth/discovery/keys"
)

// GitLab builds a Provider for GitLab.com sign-in (OpenID Connect). Default scopes request the
// OpenID identity, email and basic profile. By default the user is resolved via the userinfo
// endpoint; add oauth.WithOIDC(oauth.OIDCConfig{Issuer: GitLabIssuer, JWKSURL: GitLabJWKSURL})
// for id_token validation.
func GitLab(clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider {
	return GitLabSelfHosted(gitlabBaseURL, clientID, clientSecret, opts...)
}

// GitLabSelfHosted builds a Provider for a self-managed GitLab instance reachable at baseURL
// (for example "https://gitlab.example.com"). The OIDC issuer is baseURL and the JWKS endpoint
// is baseURL + "/oauth/discovery/keys"; pass those to oauth.WithOIDC for id_token validation.
func GitLabSelfHosted(baseURL, clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider {
	baseURL = strings.TrimRight(baseURL, "/")
	authURL := baseURL + "/oauth/authorize"
	tokenURL := baseURL + "/oauth/token"
	userInfoURL := baseURL + "/oauth/userinfo"
	return oauth.New("gitlab", clientID, clientSecret, authURL, tokenURL,
		[]string{"openid", "email", "profile"}, gitlabFetcher(userInfoURL), opts...)
}

func gitlabFetcher(userInfoURL string) oauth.FetchUserFunc {
	return func(ctx context.Context, c *http.Client, accessToken string) (*oauth.UserInfo, error) {
		var u struct {
			Sub           any    `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
		}
		if err := oauth.GetJSON(ctx, c, userInfoURL, accessToken, &u); err != nil {
			return nil, err
		}
		providerID := stringifyID(u.Sub)
		if providerID == "" {
			return nil, fmt.Errorf("%w: provider returned no subject id", oauth.ErrUserInfoFailed)
		}
		return &oauth.UserInfo{
			ProviderID:    providerID,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,
			Name:          u.Name,
		}, nil
	}
}

// stringifyID normalizes a JSON "sub"/"id" value that a provider may encode as either a string
// or a number into a stable string identifier.
func stringifyID(v any) string {
	switch id := v.(type) {
	case string:
		return id
	case json.Number:
		return id.String()
	case float64:
		return strconv.FormatInt(int64(id), 10)
	default:
		return ""
	}
}
