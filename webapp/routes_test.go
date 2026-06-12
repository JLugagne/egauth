package webapp_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/JLugagne/egauth/identity"
	identitymem "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/JLugagne/egauth/tokens/basic"
	"github.com/JLugagne/egauth/webapp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestHandler(t *testing.T, routes webapp.Routes) http.Handler {
	t.Helper()
	idSvc := identity.NewService(identitymem.NewStore(), argon2.NewHasher(), policy.NewDefaultPolicy())
	h, err := webapp.NewWebApp(webapp.Config{
		Identity:   idSvc,
		TokenStore: basic.NewMemoryStore(),
		SigningKey: "a-high-entropy-secret-kept-out-of-source-control",
		Issuer:     "test-app",
		Routes:     routes,
	})
	require.NoError(t, err)
	return h
}

func registerForm() url.Values {
	return url.Values{"email": {"alice@example.com"}, "password": {"Correct horse battery staple 1!"}}
}

// TestRoutes_DefaultsWhenUnset proves that with a zero Routes the preset still mounts the
// documented Default*Route paths, so the convenient out-of-the-box layout is unchanged.
func TestRoutes_DefaultsWhenUnset(t *testing.T) {
	srv := httptest.NewServer(newTestHandler(t, webapp.Routes{}))
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/auth/register", registerForm())
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "default /auth/register must be mounted")
}

// TestRoutes_CustomPathIsMounted proves a dev can move the endpoints to their own URL layout:
// the custom path serves the handler AND the default path is no longer registered (404),
// confirming the override replaces rather than augments the default.
func TestRoutes_CustomPathIsMounted(t *testing.T) {
	srv := httptest.NewServer(newTestHandler(t, webapp.Routes{
		Register: "POST /api/v1/sign-up",
	}))
	defer srv.Close()

	// Custom path works.
	resp, err := http.PostForm(srv.URL+"/api/v1/sign-up", registerForm())
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "custom register path must be mounted")

	// Default path is gone (override replaces it).
	resp2, err := http.PostForm(srv.URL+"/auth/register", registerForm())
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode, "default register path must not be mounted once overridden")
}

// TestRoutes_PartialOverride proves overriding one route leaves the others at their defaults.
func TestRoutes_PartialOverride(t *testing.T) {
	srv := httptest.NewServer(newTestHandler(t, webapp.Routes{
		Login: "POST /signin",
	}))
	defer srv.Close()

	// Overridden login route lives at the custom path; the default /auth/login is gone.
	resp, err := http.PostForm(srv.URL+"/auth/login", registerForm())
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "default login path must be gone when Login is overridden")

	// Register was NOT overridden, so its default path still works.
	resp2, err := http.PostForm(srv.URL+"/auth/register", registerForm())
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp2.StatusCode, "un-overridden register must stay at its default path")
}
