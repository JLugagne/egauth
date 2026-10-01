package httputil_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/httputil"
)

// TestRequestOriginURL_RefererFallbackStrictOrigin pins the hardening of the Referer fallback.
// A Referer is a full page URL, so its path/query/fragment are legitimate and are dropped — only
// its origin is ever consulted. The origin, however, must be canonical: the permissive url.Parse
// would otherwise read "https://evil@allowed/" (userinfo; the real host is evil) and
// "//allowed/" (scheme-relative) with the allowed host in the Host field, and the same-origin
// check would accept them.
func TestRequestOriginURL_RefererFallbackStrictOrigin(t *testing.T) {
	mk := func(referer string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Header.Set("Referer", referer)
		return r
	}

	rejected := []struct {
		referer string
		why     string
	}{
		{"https://evil.example.com@app.example.com/", "userinfo: the real host is evil.example.com"},
		{"https://evil.example.com@app.example.com/settings", "userinfo with a path"},
		{"//app.example.com/settings", "scheme-relative: no scheme asserted"},
		{"//evil.example.com@app.example.com/", "scheme-relative userinfo"},
		{"ftp://app.example.com/settings", "non-http(s) scheme"},
		{"app.example.com/settings", "no scheme"},
		{"https:/app.example.com/settings", "path form without an authority"},
		{"https:app.example.com", "opaque form without an authority"},
	}
	for _, tc := range rejected {
		t.Run(tc.referer, func(t *testing.T) {
			assert.Nil(t, httputil.RequestOriginURL(mk(tc.referer)),
				"a Referer whose origin is not canonical must be rejected (%s)", tc.why)
		})
	}

	accepted := []struct {
		referer string
		scheme  string
		host    string
	}{
		{"https://app.example.com/settings", "https", "app.example.com"},
		{"https://app.example.com:8443/a/b?q=1#frag", "https", "app.example.com:8443"},
		{"http://127.0.0.1:3000/", "http", "127.0.0.1:3000"},
		{"https://[::1]:8443/page", "https", "[::1]:8443"},
	}
	for _, tc := range accepted {
		t.Run(tc.referer, func(t *testing.T) {
			u := httputil.RequestOriginURL(mk(tc.referer))
			require.NotNil(t, u, "a full-URL Referer from a real browser must still resolve to its origin")
			assert.Equal(t, tc.scheme, u.Scheme)
			assert.Equal(t, tc.host, u.Host)
			assert.Empty(t, u.Path, "only the canonical origin is returned")
			assert.Empty(t, u.RawQuery)
			assert.Empty(t, u.Fragment)
		})
	}
}

// TestOriginAllowed_RefererFallbackRejectsSmuggledHost drives the hardening through the exported
// same-origin predicate: with no Origin header, a smuggling Referer must not be same-origin.
func TestOriginAllowed_RefererFallbackRejectsSmuggledHost(t *testing.T) {
	for _, referer := range []string{
		"https://evil.example.com@app.example.com/",
		"//app.example.com/",
	} {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Host = "app.example.com"
		req.Header.Set("Referer", referer)
		assert.False(t, httputil.OriginAllowed(req, nil),
			"%s must not be treated as same-origin", referer)
	}
}
