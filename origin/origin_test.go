package origin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/origin"
	"github.com/stretchr/testify/assert"
)

func TestAllowed(t *testing.T) {
	req := func(originHeader, referer string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/", nil) // Host is example.com
		if originHeader != "" {
			r.Header.Set("Origin", originHeader)
		}
		if referer != "" {
			r.Header.Set("Referer", referer)
		}
		return r
	}
	trusted := map[string]bool{"app.example.com": true}

	cases := []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"own host allowed without allowlist", req("https://example.com", ""), true},
		{"foreign host rejected", req("https://evil.com", ""), false},
		{"allowlisted host allowed", req("https://app.example.com", ""), true},
		{"suffix lookalike rejected", req("https://evil-app.example.com", ""), false},
		{"prefix lookalike rejected", req("https://app.example.com.evil.com", ""), false},
		{"missing origin and referer rejected", req("", ""), false},
		{"referer fallback allowed", req("", "https://app.example.com/page"), true},
		{"opaque null rejected", req("null", ""), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, origin.Allowed(tc.r, trusted))
		})
	}
}

// TestAllowed_CrossScheme pins the https-request / http-origin rejection, shared with the
// built-in handlers.
func TestAllowed_CrossScheme(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "https://example.com/", nil)
	r.Header.Set("Origin", "http://example.com")
	assert.False(t, origin.Allowed(r, nil), "an http Origin on an https request must be rejected")
}

// TestNormalizeHosts verifies the exported normalizer accepts both documented forms and
// rejects entries that are neither a full origin nor a bare host.
func TestNormalizeHosts(t *testing.T) {
	got, err := origin.NormalizeHosts([]string{"https://app.example.com:8443", "API.example.com"})
	assert.NoError(t, err)
	assert.Equal(t, []string{"app.example.com:8443", "api.example.com"}, got)

	_, err = origin.NormalizeHosts([]string{"app.example.com/admin"})
	assert.Error(t, err)
}

// TestTrustedSet verifies the best-effort set builder used by the per-module options:
// full origins and bare hosts normalize identically and lookalikes never enter the set.
func TestTrustedSet(t *testing.T) {
	set := origin.TrustedSet("https://app.example.com", "api.example.com")
	assert.True(t, set["app.example.com"], "full origin must be normalized to its bare host")
	assert.True(t, set["api.example.com"], "bare host must be kept")
	assert.False(t, set["evil-app.example.com"], "lookalike must not be present")
	assert.False(t, set["app.example.com.evil.com"], "lookalike must not be present")
}

// TestMiddleware pins the exported CSRF gate used to protect custom cookie-authenticated
// routes: unsafe methods are checked, safe methods pass, and the behavior matches the
// built-in handlers.
func TestMiddleware(t *testing.T) {
	newHandler := func(opts ...origin.Option) (http.Handler, *bool) {
		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		})
		return origin.Middleware(next, opts...), &called
	}

	t.Run("cross-origin POST rejected", func(t *testing.T) {
		h, called := newHandler(origin.WithTrustedOrigins("app.example.com"))
		req := httptest.NewRequest(http.MethodPost, "https://example.com/", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.False(t, *called, "handler must not run for a cross-site request")
	})

	t.Run("same-origin POST allowed", func(t *testing.T) {
		h, _ := newHandler()
		req := httptest.NewRequest(http.MethodPost, "https://example.com/", nil)
		req.Header.Set("Origin", "https://example.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("allowlisted POST allowed with full origin", func(t *testing.T) {
		h, _ := newHandler(origin.WithTrustedOrigins("https://app.example.com"))
		req := httptest.NewRequest(http.MethodPost, "https://example.com/", nil)
		req.Header.Set("Origin", "https://app.example.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("missing origin and referer rejected", func(t *testing.T) {
		h, called := newHandler()
		req := httptest.NewRequest(http.MethodPost, "https://example.com/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.False(t, *called)
	})

	t.Run("lookalike host rejected", func(t *testing.T) {
		h, called := newHandler(origin.WithTrustedOrigins("app.example.com"))
		req := httptest.NewRequest(http.MethodPost, "https://example.com/", nil)
		req.Header.Set("Origin", "https://app.example.com.evil.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.False(t, *called)
	})

	t.Run("cross-scheme http origin rejected on https", func(t *testing.T) {
		h, called := newHandler()
		req := httptest.NewRequest(http.MethodPost, "https://example.com/", nil)
		req.Header.Set("Origin", "http://example.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.False(t, *called)
	})

	t.Run("safe method passes cross-origin", func(t *testing.T) {
		h, _ := newHandler()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("insecure opt-out allows cross-origin", func(t *testing.T) {
		h, _ := newHandler(origin.WithInsecureNoOriginCheck())
		req := httptest.NewRequest(http.MethodPost, "https://example.com/", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})
}
