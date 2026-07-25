package passkey_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// beginRegistration runs BeginRegistrationHandler with a same-origin POST and returns the
// ceremony cookie it wrote.
func beginCeremonyCookie(t *testing.T, extra ...passkey.HandlerOption) []*http.Cookie {
	t.Helper()
	svc, _ := testService(t)
	uid := uuid.Must(uuid.NewV7())
	opts := append([]passkey.HandlerOption{resolver(uid), passkey.WithCookieKey(testCookieKey), passkey.WithInsecureNoOriginCheck()}, extra...)
	h := passkey.BeginRegistrationHandler(svc, opts...)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/passkey/register/begin", strings.NewReader("")))
	require.Equal(t, http.StatusOK, rec.Code)
	return rec.Result().Cookies()
}

// TestDefaultSessionCookieName_CarriesHostPrefix pins http/HTTP-10: the ceremony cookie must
// carry the browser-enforced __Host- prefix by default so a sibling subdomain cannot toss a
// same-named cookie in front of the legitimate one.
func TestDefaultSessionCookieName_CarriesHostPrefix(t *testing.T) {
	assert.True(t, strings.HasPrefix(passkey.DefaultSessionCookieName, "__Host-"),
		"the default ceremony cookie name must carry the __Host- prefix, got %q", passkey.DefaultSessionCookieName)
}

func TestCeremonyCookie_DefaultIsHostLocked(t *testing.T) {
	cookies := beginCeremonyCookie(t)
	c := findCookie(cookies, passkey.DefaultSessionCookieName)
	require.NotNil(t, c, "the ceremony cookie must be written under the __Host- name")
	assert.Empty(t, c.Domain, "a __Host- cookie must carry no Domain")
	assert.Equal(t, "/", c.Path, "a __Host- cookie must be rooted at /")
	assert.True(t, c.Secure, "a __Host- cookie must be Secure")
}

// TestCeremonyCookie_DomainDemotesHostPrefix pins that a caller who scopes the cookie to a
// domain — which the __Host- prefix forbids — gets a demoted name rather than a cookie every
// browser silently drops.
func TestCeremonyCookie_DomainDemotesHostPrefix(t *testing.T) {
	cookies := beginCeremonyCookie(t, passkey.WithCookieDomain("example.com"))
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.False(t, strings.HasPrefix(c.Name, "__Host-"),
		"a domain-scoped ceremony cookie cannot keep the __Host- prefix, got %q", c.Name)
	assert.Equal(t, "example.com", c.Domain)
}

// TestCeremonyCookie_InsecureDemotesHostPrefix pins the same for the local-HTTP escape hatch:
// browsers reject a non-Secure __Host- cookie outright.
func TestCeremonyCookie_InsecureDemotesHostPrefix(t *testing.T) {
	cookies := beginCeremonyCookie(t, passkey.WithInsecureCookies())
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.False(t, strings.HasPrefix(c.Name, "__Host-"),
		"a non-Secure ceremony cookie cannot keep the __Host- prefix, got %q", c.Name)
	assert.False(t, c.Secure)
}

// TestCeremonyCookie_RoundTripsUnderDemotedName proves Begin and Finish agree on the demoted
// name, so the demotion cannot break the ceremony.
func TestCeremonyCookie_RoundTripsUnderDemotedName(t *testing.T) {
	svc, _ := testService(t)
	uid := uuid.Must(uuid.NewV7())
	opts := []passkey.HandlerOption{
		resolver(uid), passkey.WithCookieKey(testCookieKey),
		passkey.WithInsecureNoOriginCheck(), passkey.WithInsecureCookies(),
	}
	rec := httptest.NewRecorder()
	passkey.BeginRegistrationHandler(svc, opts...)(rec, httptest.NewRequest(http.MethodPost, "/begin", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, rec.Result().Cookies(), 1)
	cookie := rec.Result().Cookies()[0]

	finishReq := httptest.NewRequest(http.MethodPost, "/finish", strings.NewReader("{}"))
	finishReq.AddCookie(cookie)
	finishRec := httptest.NewRecorder()
	passkey.FinishRegistrationHandler(svc, opts...)(finishRec, finishReq)
	assert.NotContains(t, finishRec.Body.String(), "session_invalid",
		"Finish must find the cookie Begin wrote under the demoted name")
}
