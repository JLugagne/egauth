package webapp_test

import (
	"net/http"
	"net/http/httptest"
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

func baseConfig() webapp.Config {
	return webapp.Config{
		Identity:   identity.NewService(identitymem.NewStore(), argon2.NewHasher(), policy.NewDefaultPolicy()),
		TokenStore: basic.NewMemoryStore(),
		SigningKey: "a-high-entropy-secret-kept-out-of-source-control",
		Issuer:     "test-app",
	}
}

// TestNewWebApp_RequiresTrustedOriginsOrInsecure proves the preset makes "CSRF-by-default" mean
// the same thing across handler families: it refuses to build with an empty TrustedOrigins unless
// the consumer explicitly opts out via InsecureNoOriginCheck.
func TestNewWebApp_RequiresTrustedOriginsOrInsecure(t *testing.T) {
	_, err := webapp.NewWebApp(baseConfig())
	require.Error(t, err, "empty TrustedOrigins without the insecure opt-in must fail to build")
	assert.Contains(t, err.Error(), "TrustedOrigins")
}

// TestNewWebApp_TrustedOriginsBuilds proves the secure path: supplying TrustedOrigins builds.
func TestNewWebApp_TrustedOriginsBuilds(t *testing.T) {
	cfg := baseConfig()
	cfg.TrustedOrigins = []string{"app.example.com"}
	_, err := webapp.NewWebApp(cfg)
	require.NoError(t, err)
}

// TestNewWebApp_InsecureOptInBuildsAndDisablesOriginCheck proves the explicit opt-out builds and
// wires WithInsecureNoOriginCheck into the identity family: a register POST with no Origin header
// (as http.PostForm sends) still succeeds.
func TestNewWebApp_InsecureOptInBuildsAndDisablesOriginCheck(t *testing.T) {
	cfg := baseConfig()
	cfg.InsecureNoOriginCheck = true
	h, err := webapp.NewWebApp(cfg)
	require.NoError(t, err)

	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/auth/register",
		map[string][]string{"email": {"alice@example.com"}, "password": {"Correct horse battery staple 1!"}})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode,
		"with the insecure opt-in, a no-Origin register must succeed")
}
