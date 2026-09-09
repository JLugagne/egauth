package webapp_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/webapp"
)

// postRegisterWithOrigin POSTs the register form with an explicit Origin header and
// returns the response status, so tests can assert the CSRF origin-check verdict.
func postRegisterWithOrigin(t *testing.T, h http.Handler, origin string) int {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()

	form := url.Values{}
	form.Set("email", "alice@example.com")
	form.Set("password", "Correct horse battery staple 1!")
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/auth/register", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// TestNewWebApp_TrustedOrigins_DocumentedFullOriginFormat is the regression test for the
// documented full-origin format ("https://app.example.com"): the preset must accept the
// front-end origin the operator allowlisted, not answer 403 cross_site_blocked.
func TestNewWebApp_TrustedOrigins_DocumentedFullOriginFormat(t *testing.T) {
	cfg := baseConfig()
	cfg.TrustedOrigins = []string{"https://app.example.com"}
	h, err := webapp.NewWebApp(cfg)
	require.NoError(t, err)

	assert.Equal(t, http.StatusNoContent, postRegisterWithOrigin(t, h, "https://app.example.com"),
		"the documented full-origin format must be accepted")
}

// TestNewWebApp_TrustedOrigins_BareHostFormUnchanged proves the bare-host form
// ("app.example.com") keeps working after normalization is introduced.
func TestNewWebApp_TrustedOrigins_BareHostFormUnchanged(t *testing.T) {
	cfg := baseConfig()
	cfg.TrustedOrigins = []string{"app.example.com"}
	h, err := webapp.NewWebApp(cfg)
	require.NoError(t, err)

	assert.Equal(t, http.StatusNoContent, postRegisterWithOrigin(t, h, "https://app.example.com"),
		"the bare-host form must remain accepted")
}

// TestNewWebApp_TrustedOrigins_LookalikeHostsRejected proves normalization does not widen
// the allowlist: lookalike hosts of the trusted origin stay rejected with 403.
func TestNewWebApp_TrustedOrigins_LookalikeHostsRejected(t *testing.T) {
	for _, tt := range []struct {
		origin string
	}{
		{origin: "https://app.example.com.evil.com"},
		{origin: "https://evil-app.example.com"},
		{origin: "app.example.com.evil.com"},
	} {
		cfg := baseConfig()
		cfg.TrustedOrigins = []string{"https://app.example.com"}
		h, err := webapp.NewWebApp(cfg)
		require.NoError(t, err)

		assert.Equal(t, http.StatusForbidden, postRegisterWithOrigin(t, h, tt.origin),
			"lookalike origin %q must be rejected", tt.origin)
	}
}

// TestNewWebApp_TrustedOrigins_RejectsUnparseableEntries proves NewWebApp loudly rejects
// allowlist entries that cannot be normalized to a host, instead of silently narrowing
// the allowlist to nothing.
func TestNewWebApp_TrustedOrigins_RejectsUnparseableEntries(t *testing.T) {
	for _, entry := range []string{":://bad", "/path-only", ""} {
		cfg := baseConfig()
		cfg.TrustedOrigins = []string{entry}
		_, err := webapp.NewWebApp(cfg)
		require.Error(t, err, "entry %q must be rejected", entry)
		assert.ErrorContains(t, err, "TrustedOrigins", "entry %q", entry)
	}
}
