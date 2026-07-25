package webapp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/webapp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewWebApp_CookieDomainServesRegisterAndRefresh proves Config.CookieDomain produces a
// working preset: registration writes usable cookies scoped to the domain, and the refresh
// route accepts them.
func TestNewWebApp_CookieDomainServesRegisterAndRefresh(t *testing.T) {
	cfg := baseConfig()
	cfg.CookieDomain = "example.com"
	cfg.InsecureNoOriginCheck = true

	h, err := webapp.NewWebApp(cfg)
	require.NoError(t, err)

	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/auth/register",
		map[string][]string{"email": {"alice@example.com"}, "password": {"Correct horse battery staple 1!"}})
	require.NoError(t, err, "register must not blow up the connection")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	issued := resp.Cookies()
	require.Len(t, issued, 2, "register must issue both auth cookies")
	for _, c := range issued {
		assert.False(t, strings.HasPrefix(c.Name, "__Host-"),
			"a domain-scoped cookie cannot keep the __Host- prefix, got %q", c.Name)
		assert.Equal(t, "example.com", c.Domain)
	}

	refreshReq, err := http.NewRequest(http.MethodPost, srv.URL+"/auth/refresh", nil)
	require.NoError(t, err)
	for _, c := range issued {
		refreshReq.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	refreshResp, err := http.DefaultClient.Do(refreshReq)
	require.NoError(t, err, "refresh must not blow up the connection")
	defer func() { _ = refreshResp.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, refreshResp.StatusCode)
}
