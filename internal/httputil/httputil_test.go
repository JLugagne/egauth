package httputil_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/internal/httputil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOriginAllowed pins the exact-match semantics of the shared origin helper. A regression to
// substring/suffix matching (the classic "convenience" bug) is a CSRF bypass, so it is guarded
// here in the package where the logic lives, not only incidentally through the handler packages.
func TestOriginAllowed(t *testing.T) {
	req := func(origin, referer string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/", nil) // Host defaults to example.com
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if referer != "" {
			r.Header.Set("Referer", referer)
		}
		return r
	}
	reqHTTPS := func(origin, referer string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://example.com/", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if referer != "" {
			r.Header.Set("Referer", referer)
		}
		return r
	}
	reqForwardedHTTPS := func(origin, referer string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
		r.Header.Set("X-Forwarded-Proto", "https")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if referer != "" {
			r.Header.Set("Referer", referer)
		}
		return r
	}
	reqTLS := func(origin, referer string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
		r.TLS = &tls.ConnectionState{}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if referer != "" {
			r.Header.Set("Referer", referer)
		}
		return r
	}
	trusted := map[string]bool{"app.example.com": true}

	cases := []struct {
		name    string
		r       *http.Request
		trusted map[string]bool
		want    bool
	}{
		{"empty allowlist allows own host", req("https://example.com", ""), nil, true},
		{"empty allowlist rejects foreign host", req("https://evil.com", ""), nil, false},
		{"own Host is always trusted", req("https://example.com", ""), trusted, true},
		{"exact allowlisted host allowed", req("https://app.example.com", ""), trusted, true},
		{"foreign host rejected", req("https://evil.com", ""), trusted, false},
		{"suffix of a trusted host must be rejected", req("https://evil-app.example.com", ""), trusted, false},
		{"parent domain of a trusted host must be rejected", req("https://example.com:8443", ""), trusted, false},
		{"opaque null origin rejected", req("null", ""), trusted, false},
		{"missing Origin and Referer rejected", req("", ""), trusted, false},
		{"falls back to Referer host when Origin absent", req("", "https://app.example.com/page"), trusted, true},

		// Cross-scheme protection
		{"cross-scheme http origin targeting https request rejected", reqHTTPS("http://example.com", ""), trusted, false},
		{"cross-scheme http referer targeting https request rejected", reqHTTPS("", "http://example.com/page"), trusted, false},
		{"cross-scheme http origin targeting forwarded https rejected", reqForwardedHTTPS("http://example.com", ""), trusted, false},
		{"cross-scheme http origin targeting tls connection rejected", reqTLS("http://example.com", ""), trusted, false},
		{"cross-scheme http origin targeting trusted host on https rejected", reqHTTPS("http://app.example.com", ""), trusted, false},
		{"matching https origin targeting https request allowed", reqHTTPS("https://example.com", ""), trusted, true},
		{"trusted https origin targeting https request allowed", reqHTTPS("https://app.example.com", ""), trusted, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, httputil.OriginAllowed(tc.r, tc.trusted))
		})
	}
}

func TestRequestOriginURL(t *testing.T) {
	mk := func(origin, referer string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if referer != "" {
			r.Header.Set("Referer", referer)
		}
		return r
	}

	u := httputil.RequestOriginURL(mk("https://app.example.com:8443", ""))
	require.NotNil(t, u)
	assert.Equal(t, "https", u.Scheme)
	assert.Equal(t, "app.example.com:8443", u.Host)

	assert.Nil(t, httputil.RequestOriginURL(mk("null", "https://app.example.com")), "opaque null origin yields nil")

	uRef := httputil.RequestOriginURL(mk("", "https://ref.example.com/x?q=1"))
	require.NotNil(t, uRef)
	assert.Equal(t, "https", uRef.Scheme)
	assert.Equal(t, "ref.example.com", uRef.Host)

	assert.Nil(t, httputil.RequestOriginURL(mk("", "")))
	assert.Nil(t, httputil.RequestOriginURL(mk("://invalid", "")))
}

func TestRequestOriginHost(t *testing.T) {
	mk := func(origin, referer string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if referer != "" {
			r.Header.Set("Referer", referer)
		}
		return r
	}
	assert.Equal(t, "app.example.com", httputil.RequestOriginHost(mk("https://app.example.com", "")))
	assert.Equal(t, "", httputil.RequestOriginHost(mk("null", "https://app.example.com")), "opaque null origin yields no host, no Referer fallback")
	assert.Equal(t, "ref.example.com", httputil.RequestOriginHost(mk("", "https://ref.example.com/x")), "Referer is the fallback")
	assert.Equal(t, "", httputil.RequestOriginHost(mk("", "")))
}

func TestParseLimitedForm(t *testing.T) {
	fail := func() (func(http.ResponseWriter, *http.Request, int, string), *int, *string) {
		var code int
		var errCode string
		return func(_ http.ResponseWriter, _ *http.Request, c int, ec string) { code, errCode = c, ec }, &code, &errCode
	}

	t.Run("body within cap parses", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{"a": {"b"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		failFn, code, _ := fail()
		ok := httputil.ParseLimitedForm(httptest.NewRecorder(), r, 1024, failFn)
		assert.True(t, ok)
		assert.Equal(t, 0, *code, "failFn must not be called on success")
		assert.Equal(t, "b", r.PostForm.Get("a"))
	})

	t.Run("oversized body maps to 413 request_too_large", func(t *testing.T) {
		big := "a=" + strings.Repeat("x", 4096)
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(big))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		failFn, code, errCode := fail()
		ok := httputil.ParseLimitedForm(httptest.NewRecorder(), r, 16, failFn)
		assert.False(t, ok)
		assert.Equal(t, http.StatusRequestEntityTooLarge, *code)
		assert.Equal(t, "request_too_large", *errCode)
	})
}
