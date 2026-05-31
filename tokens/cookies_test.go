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
	c := tokens.Cookies{Insecure: true}
	rec := httptest.NewRecorder()
	c.SetAccess(rec, "v")
	cookie := findCookie(t, rec, tokens.DefaultAccessCookieName)
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
