package providers_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/oauth"
	"github.com/JLugagne/egauth/oauth/providers"
)

// authParams builds an authorization-code URL for p and returns its parsed query. It fails the
// test if the provider recorded a deferred configErr (surfaced as an empty/invalid URL).
func authParams(t *testing.T, p *oauth.Provider) url.Values {
	t.Helper()
	raw := p.AuthCodeURL("state", "https://app.example.com/cb", "challenge")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("AuthCodeURL returned an unparseable URL %q: %v", raw, err)
	}
	if u.Scheme != "https" {
		t.Fatalf("expected https authorize URL, got %q", raw)
	}
	return u.Query()
}

func TestConstructors_NameAndEndpoints(t *testing.T) {
	cases := []struct {
		name     string
		provider *oauth.Provider
		wantName string
		authHost string
		scopes   []string
	}{
		{"google", providers.Google("id", "secret"), "google", "accounts.google.com", []string{"openid", "email", "profile"}},
		{"github", providers.GitHub("id", "secret"), "github", "github.com", []string{"read:user", "user:email"}},
		{"discord", providers.Discord("id", "secret"), "discord", "discord.com", []string{"identify", "email"}},
		{"linkedin", providers.LinkedIn("id", "secret"), "linkedin", "www.linkedin.com", []string{"openid", "email", "profile"}},
		{"facebook", providers.Facebook("id", "secret"), "facebook", "www.facebook.com", []string{"public_profile", "email"}},
		{"gitlab", providers.GitLab("id", "secret"), "gitlab", "gitlab.com", []string{"openid", "email", "profile"}},
		{"apple", providers.Apple("id", "secret"), "apple", "appleid.apple.com", []string{"openid", "email"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.provider.Name(); got != tc.wantName {
				t.Errorf("Name() = %q, want %q", got, tc.wantName)
			}
			q := authParams(t, tc.provider)
			if got := q.Get("client_id"); got != "id" {
				t.Errorf("client_id = %q, want \"id\"", got)
			}
			raw := tc.provider.AuthCodeURL("state", "https://app.example.com/cb", "challenge")
			if u, _ := url.Parse(raw); u.Host != tc.authHost {
				t.Errorf("authorize host = %q, want %q", u.Host, tc.authHost)
			}
			gotScope := q.Get("scope")
			for _, s := range tc.scopes {
				if !strings.Contains(gotScope, s) {
					t.Errorf("scope %q missing %q", gotScope, s)
				}
			}
		})
	}
}

func TestMicrosoft_TenantInEndpoints(t *testing.T) {
	p := providers.Microsoft("contoso.onmicrosoft.com", "id", "secret")
	raw := p.AuthCodeURL("state", "https://app.example.com/cb", "challenge")
	if !strings.Contains(raw, "/contoso.onmicrosoft.com/oauth2/v2.0/authorize") {
		t.Errorf("authorize URL %q does not embed the tenant", raw)
	}
	if p.Name() != "microsoft" {
		t.Errorf("Name() = %q, want \"microsoft\"", p.Name())
	}
}

func TestMicrosoft_EmptyTenantDefaultsToCommon(t *testing.T) {
	p := providers.Microsoft("", "id", "secret")
	raw := p.AuthCodeURL("state", "https://app.example.com/cb", "challenge")
	if !strings.Contains(raw, "/common/oauth2/v2.0/authorize") {
		t.Errorf("empty tenant should default to %q; got %q", providers.MicrosoftTenantCommon, raw)
	}
}

func TestGitLabSelfHosted_DerivesEndpointsFromBaseURL(t *testing.T) {
	p := providers.GitLabSelfHosted("https://gitlab.example.com/", "id", "secret")
	raw := p.AuthCodeURL("state", "https://app.example.com/cb", "challenge")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("unparseable URL %q: %v", raw, err)
	}
	if u.Host != "gitlab.example.com" {
		t.Errorf("authorize host = %q, want self-hosted host", u.Host)
	}
	if u.Path != "/oauth/authorize" {
		t.Errorf("authorize path = %q, want /oauth/authorize (trailing slash on base URL must be trimmed)", u.Path)
	}
}
