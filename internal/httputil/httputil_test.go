package httputil_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/internal/httputil"
	"github.com/stretchr/testify/assert"
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
	trusted := map[string]bool{"app.example.com": true}

	cases := []struct {
		name    string
		r       *http.Request
		trusted map[string]bool
		want    bool
	}{
		{"empty allowlist allows all (opt-in protection)", req("https://evil.com", ""), nil, true},
		{"own Host is always trusted", req("https://example.com", ""), trusted, true},
		{"exact allowlisted host allowed", req("https://app.example.com", ""), trusted, true},
		{"foreign host rejected", req("https://evil.com", ""), trusted, false},
		{"suffix of a trusted host must be rejected", req("https://evil-app.example.com", ""), trusted, false},
		{"parent domain of a trusted host must be rejected", req("https://example.com:8443", ""), trusted, false},
		{"opaque null origin rejected", req("null", ""), trusted, false},
		{"missing Origin and Referer rejected", req("", ""), trusted, false},
		{"falls back to Referer host when Origin absent", req("", "https://app.example.com/page"), trusted, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, httputil.OriginAllowed(tc.r, tc.trusted))
		})
	}
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
