package webapp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/webapp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewWebApp_ConflictingCSRFConfig_RejectsContradiction confirms SEC-SES-11 (CVSS 8.1).
//
// Security invariant:
// The webapp.NewWebApp constructor MUST explicitly reject any contradictory configuration
// where TrustedOrigins is set AND InsecureNoOriginCheck is enabled to true.
// The presence of a trusted-origins allowlist (TrustedOrigins) implies a formal intent
// to enable and restrict CSRF protection; allowing InsecureNoOriginCheck in parallel
// constitutes a major security configuration conflict that must fail immediately at construction (fail-closed).
//
// Current vulnerable behaviour:
// In webapp.NewWebApp (webapp/webapp.go:122-124 and 169-178), the guard only checks:
//
//	len(cfg.TrustedOrigins) == 0 && !cfg.InsecureNoOriginCheck
//
// If the developer configures TrustedOrigins while keeping InsecureNoOriginCheck: true,
// NewWebApp silently accepts the configuration, and WithInsecureNoOriginCheck()
// overwrites WithTrustedOrigins(). CSRF protection is completely disabled without the administrator's knowledge.
func TestNewWebApp_ConflictingCSRFConfig_RejectsContradiction(t *testing.T) {
	cfg := baseConfig()
	cfg.TrustedOrigins = []string{"https://app.example.com"}
	cfg.InsecureNoOriginCheck = true

	// SECURITY INVARIANT VIOLATED: the constructor must reject this contradictory combination
	_, err := webapp.NewWebApp(cfg)
	require.Error(t, err,
		"SEC-SES-11: webapp.NewWebApp must reject the contradictory combination of TrustedOrigins and InsecureNoOriginCheck")
	assert.Contains(t, err.Error(), "cannot specify both TrustedOrigins and InsecureNoOriginCheck")
}

// TestNewWebApp_CookieDomain_DoesNotPanicAndSetsScopedCookies confirms SEC-SES-03.
// When CookieDomain is configured, NewWebApp must configure non-__Host cookies scoped to that
// domain without panicking at runtime when setting or clearing cookies.
func TestNewWebApp_CookieDomain_DoesNotPanicAndSetsScopedCookies(t *testing.T) {
	cfg := baseConfig()
	cfg.InsecureNoOriginCheck = true
	cfg.CookieDomain = "example.com"

	h, err := webapp.NewWebApp(cfg)
	require.NoError(t, err, "NewWebApp should accept valid CookieDomain")

	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/auth/register",
		map[string][]string{"email": {"alice@example.com"}, "password": {"Correct horse battery staple 1!"}})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	cookies := resp.Cookies()
	require.NotEmpty(t, cookies)

	var accessCookie, refreshCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "access_token" {
			accessCookie = c
		}
		if c.Name == "refresh_token" {
			refreshCookie = c
		}
	}
	require.NotNil(t, accessCookie, "access_token cookie must be set without __Host- prefix when domain is configured")
	assert.Equal(t, "example.com", accessCookie.Domain)
	require.NotNil(t, refreshCookie, "refresh_token cookie must be set without __Host- prefix when domain is configured")
	assert.Equal(t, "example.com", refreshCookie.Domain)
}

// TestNewWebApp_CookieDomain_RejectsInvalidDomain verifies that malformed cookie domains
// (e.g. containing scheme, port, or path) are rejected at construction.
func TestNewWebApp_CookieDomain_RejectsInvalidDomain(t *testing.T) {
	invalidDomains := []string{
		"https://example.com",
		"http://example.com",
		"example.com:8080",
		"example.com/path",
	}

	for _, domain := range invalidDomains {
		cfg := baseConfig()
		cfg.InsecureNoOriginCheck = true
		cfg.CookieDomain = domain

		_, err := webapp.NewWebApp(cfg)
		require.Error(t, err, "NewWebApp must reject invalid CookieDomain: %s", domain)
		assert.Contains(t, err.Error(), "CookieDomain")
	}
}
