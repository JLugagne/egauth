package tokens_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findCookie returns the *http.Cookie with the given name from a recorder's response.
func findCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestCookiesSecureDefaults(t *testing.T) {
	c := tokens.DefaultCookies()
	rec := httptest.NewRecorder()

	c.SetAccess(rec, "access-value")

	cookie := findCookie(t, rec, tokens.DefaultAccessCookieName)
	require.NotNil(t, cookie, "access cookie must be set")
	assert.Equal(t, "access-value", cookie.Value)
	assert.True(t, cookie.HttpOnly, "access cookie must be HttpOnly")
	assert.True(t, cookie.Secure, "access cookie must be Secure by default")
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	assert.Equal(t, "/", cookie.Path)
	assert.Equal(t, 0, cookie.MaxAge, "access cookie must be a session cookie")
}

func TestCookiesZeroValueIsSecure(t *testing.T) {
	// A zero-value Cookies (e.g. a caller that forgot DefaultCookies) and a
	// partially-initialized one must BOTH still behave securely — most importantly they
	// must remain Secure, since the Go bool zero value must be the secure default.
	for name, c := range map[string]tokens.Cookies{
		"zero value":   {},
		"partial init": {AccessName: "sess"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c.SetAccess(rec, "v")

			cookieName := tokens.DefaultAccessCookieName
			if c.AccessName != "" {
				cookieName = c.AccessName
			}
			cookie := findCookie(t, rec, cookieName)
			require.NotNil(t, cookie)
			assert.True(t, cookie.Secure, "Secure must default to true")
			assert.True(t, cookie.HttpOnly)
			assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
			assert.Equal(t, "/", cookie.Path)
		})
	}
}

func TestWithInsecureClearsSecure(t *testing.T) {
	// Insecure:true is incompatible with __Host- names, so we must use plain names.
	c := tokens.Cookies{AccessName: "access_token", RefreshName: "refresh_token", Insecure: true}
	rec := httptest.NewRecorder()
	c.SetAccess(rec, "v")
	cookie := findCookie(t, rec, "access_token")
	require.NotNil(t, cookie)
	assert.False(t, cookie.Secure, "Insecure must disable the Secure attribute")
}

func TestSetRefreshPersistentVsSession(t *testing.T) {
	c := tokens.DefaultCookies()
	expires := time.Now().Add(24 * time.Hour)

	t.Run("persistent (remember-me) sets Max-Age", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c.SetRefresh(rec, "rt", expires, true)
		cookie := findCookie(t, rec, tokens.DefaultRefreshCookieName)
		require.NotNil(t, cookie)
		assert.Greater(t, cookie.MaxAge, 0, "persistent refresh cookie must have Max-Age")
		assert.True(t, cookie.HttpOnly)
		assert.True(t, cookie.Secure)
	})

	t.Run("session cookie has no Max-Age", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c.SetRefresh(rec, "rt", expires, false)
		cookie := findCookie(t, rec, tokens.DefaultRefreshCookieName)
		require.NotNil(t, cookie)
		assert.Equal(t, 0, cookie.MaxAge, "session refresh cookie must not have Max-Age")
	})
}

func TestClearExpiresBothCookies(t *testing.T) {
	c := tokens.DefaultCookies()
	rec := httptest.NewRecorder()

	c.Clear(rec)

	access := findCookie(t, rec, tokens.DefaultAccessCookieName)
	refresh := findCookie(t, rec, tokens.DefaultRefreshCookieName)
	require.NotNil(t, access)
	require.NotNil(t, refresh)
	assert.Less(t, access.MaxAge, 0, "cleared access cookie must have negative Max-Age")
	assert.Less(t, refresh.MaxAge, 0, "cleared refresh cookie must have negative Max-Age")
}

func TestReadCookies(t *testing.T) {
	c := tokens.DefaultCookies()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: tokens.DefaultAccessCookieName, Value: "atok"})
	req.AddCookie(&http.Cookie{Name: tokens.DefaultRefreshCookieName, Value: "rtok"})

	at, ok := c.Access(req)
	assert.True(t, ok)
	assert.Equal(t, "atok", at)

	rt, ok := c.Refresh(req)
	assert.True(t, ok)
	assert.Equal(t, "rtok", rt)

	// Missing / empty cookies report not-present.
	empty := httptest.NewRequest(http.MethodGet, "/", nil)
	_, ok = c.Access(empty)
	assert.False(t, ok)
}

func TestCustomCookieAttributes(t *testing.T) {
	c := tokens.Cookies{
		AccessName:  "at",
		RefreshName: "rt",
		Domain:      "example.com",
		Path:        "/app",
		RefreshPath: "/auth/refresh",
		SameSite:    http.SameSiteStrictMode,
		Insecure:    true,
	}
	rec := httptest.NewRecorder()
	c.SetAccess(rec, "a")
	c.SetRefresh(rec, "r", time.Now().Add(time.Hour), true)

	access := findCookie(t, rec, "at")
	refresh := findCookie(t, rec, "rt")
	require.NotNil(t, access)
	require.NotNil(t, refresh)
	assert.Equal(t, "example.com", access.Domain)
	assert.Equal(t, "/app", access.Path)
	assert.Equal(t, http.SameSiteStrictMode, access.SameSite)
	assert.False(t, access.Secure)
	assert.Equal(t, "/auth/refresh", refresh.Path)
}

// TestHostPrefixDefaultNames verifies that both default cookie names use the __Host- prefix,
// which forces browsers to enforce host-locked, Secure, Path=/ — defeating subdomain cookie-tossing.
func TestHostPrefixDefaultNames(t *testing.T) {
	const wantAccess = "__Host-access_token"
	const wantRefresh = "__Host-refresh_token"
	assert.Equal(t, wantAccess, tokens.DefaultAccessCookieName, "DefaultAccessCookieName must use __Host- prefix")
	assert.Equal(t, wantRefresh, tokens.DefaultRefreshCookieName, "DefaultRefreshCookieName must use __Host- prefix")
}

// TestHostPrefixValidation verifies that using a __Host- name with an incompatible attribute
// combination (Domain set, non-root Path, or Insecure) is rejected by Validate.
func TestHostPrefixValidation(t *testing.T) {
	t.Run("__Host- with Domain fails", func(t *testing.T) {
		c := tokens.Cookies{
			AccessName: "__Host-access_token",
			Domain:     "example.com",
			Path:       "/",
		}
		err := c.Validate()
		require.Error(t, err, "__Host- name with Domain set must fail validation")
	})

	t.Run("__Host- with non-root Path fails", func(t *testing.T) {
		c := tokens.Cookies{
			AccessName: "__Host-access_token",
			Path:       "/api",
		}
		err := c.Validate()
		require.Error(t, err, "__Host- name with non-root Path must fail validation")
	})

	t.Run("__Host- with Insecure fails", func(t *testing.T) {
		c := tokens.Cookies{
			AccessName: "__Host-access_token",
			Path:       "/",
			Insecure:   true,
		}
		err := c.Validate()
		require.Error(t, err, "__Host- name with Insecure=true must fail validation")
	})

	t.Run("non-__Host- name with Domain is fine", func(t *testing.T) {
		c := tokens.Cookies{
			AccessName: "access_token",
			Domain:     "example.com",
			Path:       "/",
		}
		err := c.Validate()
		require.NoError(t, err)
	})

	t.Run("RefreshName __Host- with Domain fails", func(t *testing.T) {
		c := tokens.Cookies{
			RefreshName: "__Host-refresh_token",
			Domain:      "example.com",
			Path:        "/",
			RefreshPath: "/",
		}
		err := c.Validate()
		require.Error(t, err, "__Host- RefreshName with Domain set must fail validation")
	})
}
