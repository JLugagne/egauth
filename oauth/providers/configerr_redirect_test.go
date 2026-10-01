package providers_test

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/oauth"
	"github.com/JLugagne/egauth/oauth/providers"
)

// F-OAPROV-001 regression: a provider whose endpoint URL failed the https-only validation
// records a deferred configErr. Exchange honors it; the begin path must too. Otherwise the
// authorization redirect carries state, PKCE challenge, client_id and redirect_uri to an
// unvalidated cleartext or cross-origin endpoint.
func TestBeginHandler_RefusesProviderWithDeferredConfigError(t *testing.T) {
	stateKey := newStateKey(t)

	cases := []struct {
		name     string
		provider *oauth.Provider
	}{
		{
			name:     "cleartext preset domain",
			provider: providers.Auth0("http://insecure-tenant.example.com", "client-id", "client-secret"),
		},
		{
			name: "protocol-relative authorization endpoint",
			provider: oauth.New(
				"audit-configerr",
				"client-id",
				"client-secret",
				"//evil-idp.example/authorize",
				"https://insecure-idp.example/token",
				[]string{"openid", "email"},
				func(_ context.Context, _ *http.Client, _ string) (*oauth.UserInfo, error) {
					return nil, nil
				},
			),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Precondition: the provider itself rejects the configuration on exchange.
			if _, err := tc.provider.Exchange(t.Context(), "code", "https://app.example.com/cb", ""); err == nil {
				t.Fatal("precondition failed: Exchange accepted a provider whose endpoint URL failed validation")
			}

			h := oauth.BeginHandler(tc.provider,
				oauth.WithStateSigningKey(stateKey),
				oauth.WithRedirectURL("https://app.example.com/auth/callback"),
			)
			rec := httptest.NewRecorder()
			h(rec, httptest.NewRequest(http.MethodGet, "https://app.example.com/auth/login", nil))

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("BeginHandler status = %d, want 500: a provider whose config was rejected must fail closed, not redirect (Location %q)", rec.Code, rec.Header().Get("Location"))
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Fatalf("BeginHandler emitted a Location header %q for a misconfigured provider", loc)
			}
		})
	}
}

// TestAuthCodeURL_EmptyWhenProviderConfigInvalid pins the second half of the fix: direct
// callers must not be able to build a URL from a rejected provider either.
func TestAuthCodeURL_EmptyWhenProviderConfigInvalid(t *testing.T) {
	p := providers.Auth0("http://insecure-tenant.example.com", "client-id", "client-secret")
	if got := p.AuthCodeURL("state", "https://app.example.com/cb", ""); got != "" {
		t.Fatalf("AuthCodeURL built %q from a provider whose configuration was rejected", got)
	}
}

// TestBeginHandler_ValidHTTPSProviderStillRedirects is the control: the fail-closed check
// must not break the happy path.
func TestBeginHandler_ValidHTTPSProviderStillRedirects(t *testing.T) {
	h := oauth.BeginHandler(
		providers.Auth0("tenant.example.com", "client-id", "client-secret"),
		oauth.WithStateSigningKey(newStateKey(t)),
		oauth.WithRedirectURL("https://app.example.com/auth/callback"),
	)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "https://app.example.com/auth/login", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("BeginHandler status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "https://tenant.example.com/authorize?") {
		t.Fatalf("unexpected authorization Location %q", loc)
	}
}

func newStateKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return key
}
