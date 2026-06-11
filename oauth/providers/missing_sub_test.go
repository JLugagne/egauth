package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/oauth"
)

// serveJSON starts a test server that returns body as application/json for every request.
func serveJSON(t *testing.T, body any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// redirectAllTo returns an http.RoundTripper that rewrites every request's URL
// host+scheme to point at targetBase (a test-server URL), preserving the path/query.
// This lets us redirect hard-coded production URL constants to a local httptest.Server.
func redirectAllTo(targetBase string) http.RoundTripper {
	return testRoundTripper(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		clone.URL.Scheme = "http"
		parsed, _ := http.NewRequest(http.MethodGet, targetBase, nil)
		clone.URL.Host = parsed.URL.Host
		return http.DefaultTransport.RoundTrip(clone)
	})
}

// TestFetchersRejectEmptyProviderSubject is the regression test for TASK-062.
// Each userinfo-path fetcher must return a wrapped oauth.ErrUserInfoFailed when the
// provider response contains an empty or missing subject ("sub" / "id") so that a
// cross-account identity collision via ProviderID="" is impossible.
func TestFetchersRejectEmptyProviderSubject(t *testing.T) {
	ctx := context.Background()

	t.Run("oidcUserInfoFetcher/empty sub", func(t *testing.T) {
		srv := serveJSON(t, map[string]any{
			"sub": "", "email": "victim@example.com", "email_verified": true, "name": "Victim",
		})
		fetcher := oidcUserInfoFetcher(srv.URL)
		_, err := fetcher(ctx, srv.Client(), "tok")
		if err == nil {
			t.Fatal("expected error for empty sub, got nil")
		}
		if !errors.Is(err, oauth.ErrUserInfoFailed) {
			t.Errorf("error = %v, want wrapped oauth.ErrUserInfoFailed", err)
		}
	})

	t.Run("oidcUserInfoFetcher/null sub", func(t *testing.T) {
		srv := serveJSON(t, map[string]any{
			"sub": nil, "email": "victim@example.com", "email_verified": true, "name": "Victim",
		})
		fetcher := oidcUserInfoFetcher(srv.URL)
		_, err := fetcher(ctx, srv.Client(), "tok")
		if err == nil {
			t.Fatal("expected error for null sub, got nil")
		}
		if !errors.Is(err, oauth.ErrUserInfoFailed) {
			t.Errorf("error = %v, want wrapped oauth.ErrUserInfoFailed", err)
		}
	})

	t.Run("oidcUserInfoFetcher/missing sub", func(t *testing.T) {
		srv := serveJSON(t, map[string]any{
			"email": "victim@example.com", "email_verified": true, "name": "Victim",
		})
		fetcher := oidcUserInfoFetcher(srv.URL)
		_, err := fetcher(ctx, srv.Client(), "tok")
		if err == nil {
			t.Fatal("expected error for missing sub, got nil")
		}
		if !errors.Is(err, oauth.ErrUserInfoFailed) {
			t.Errorf("error = %v, want wrapped oauth.ErrUserInfoFailed", err)
		}
	})

	t.Run("gitlabFetcher/empty sub", func(t *testing.T) {
		srv := serveJSON(t, map[string]any{
			"sub": "", "email": "victim@example.com", "email_verified": true, "name": "Victim",
		})
		fetcher := gitlabFetcher(srv.URL)
		_, err := fetcher(ctx, srv.Client(), "tok")
		if err == nil {
			t.Fatal("expected error for empty sub, got nil")
		}
		if !errors.Is(err, oauth.ErrUserInfoFailed) {
			t.Errorf("error = %v, want wrapped oauth.ErrUserInfoFailed", err)
		}
	})

	t.Run("gitlabFetcher/null sub", func(t *testing.T) {
		srv := serveJSON(t, map[string]any{
			"sub": nil, "email": "victim@example.com", "email_verified": true, "name": "Victim",
		})
		fetcher := gitlabFetcher(srv.URL)
		_, err := fetcher(ctx, srv.Client(), "tok")
		if err == nil {
			t.Fatal("expected error for null sub, got nil")
		}
		if !errors.Is(err, oauth.ErrUserInfoFailed) {
			t.Errorf("error = %v, want wrapped oauth.ErrUserInfoFailed", err)
		}
	})

	t.Run("fetchGoogleUser/empty sub", func(t *testing.T) {
		srv := serveJSON(t, map[string]any{
			"sub": "", "email": "victim@example.com", "email_verified": true, "name": "Victim",
		})
		c := srv.Client()
		c.Transport = redirectAllTo(srv.URL)
		_, err := fetchGoogleUser(ctx, c, "tok")
		if err == nil {
			t.Fatal("expected error for empty sub, got nil")
		}
		if !errors.Is(err, oauth.ErrUserInfoFailed) {
			t.Errorf("error = %v, want wrapped oauth.ErrUserInfoFailed", err)
		}
	})

	t.Run("fetchMicrosoftUser/empty sub", func(t *testing.T) {
		srv := serveJSON(t, map[string]any{
			"sub": "", "email": "victim@example.com", "name": "Victim",
		})
		c := srv.Client()
		c.Transport = redirectAllTo(srv.URL)
		_, err := fetchMicrosoftUser(ctx, c, "tok")
		if err == nil {
			t.Fatal("expected error for empty sub, got nil")
		}
		if !errors.Is(err, oauth.ErrUserInfoFailed) {
			t.Errorf("error = %v, want wrapped oauth.ErrUserInfoFailed", err)
		}
	})

	t.Run("fetchLinkedInUser/empty sub", func(t *testing.T) {
		srv := serveJSON(t, map[string]any{
			"sub": "", "email": "victim@example.com", "email_verified": true, "name": "Victim",
		})
		c := srv.Client()
		c.Transport = redirectAllTo(srv.URL)
		_, err := fetchLinkedInUser(ctx, c, "tok")
		if err == nil {
			t.Fatal("expected error for empty sub, got nil")
		}
		if !errors.Is(err, oauth.ErrUserInfoFailed) {
			t.Errorf("error = %v, want wrapped oauth.ErrUserInfoFailed", err)
		}
	})

	t.Run("fetchDiscordUser/empty id", func(t *testing.T) {
		srv := serveJSON(t, map[string]any{
			"id": "", "email": "victim@example.com", "verified": true, "username": "Victim",
		})
		c := srv.Client()
		c.Transport = redirectAllTo(srv.URL)
		_, err := fetchDiscordUser(ctx, c, "tok")
		if err == nil {
			t.Fatal("expected error for empty id, got nil")
		}
		if !errors.Is(err, oauth.ErrUserInfoFailed) {
			t.Errorf("error = %v, want wrapped oauth.ErrUserInfoFailed", err)
		}
	})

	t.Run("fetchFacebookUser/empty id", func(t *testing.T) {
		srv := serveJSON(t, map[string]any{
			"id": "", "email": "victim@example.com", "name": "Victim",
		})
		c := srv.Client()
		c.Transport = redirectAllTo(srv.URL)
		_, err := fetchFacebookUser(ctx, c, "tok")
		if err == nil {
			t.Fatal("expected error for empty id, got nil")
		}
		if !errors.Is(err, oauth.ErrUserInfoFailed) {
			t.Errorf("error = %v, want wrapped oauth.ErrUserInfoFailed", err)
		}
	})

	t.Run("fetchGitHubUser/zero id", func(t *testing.T) {
		// GitHub uses a numeric id; 0 is the zero-value (missing/absent).
		srv := serveJSON(t, map[string]any{
			"id": 0, "login": "ghost", "email": "victim@example.com", "name": "Ghost",
		})
		c := srv.Client()
		c.Transport = redirectAllTo(srv.URL)
		_, err := fetchGitHubUser(ctx, c, "tok")
		if err == nil {
			t.Fatal("expected error for zero GitHub id, got nil")
		}
		if !errors.Is(err, oauth.ErrUserInfoFailed) {
			t.Errorf("error = %v, want wrapped oauth.ErrUserInfoFailed", err)
		}
	})
}

// testRoundTripper adapts a function to http.RoundTripper for test HTTP clients.
type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
