package passkey

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hostPrefixTestService(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(&hostPrefixTestStore{}, Config{
		RPID:           "example.com",
		RPDisplayName:  "Example",
		RPOrigins:      []string{"https://example.com"},
		CookieKey:      []byte(testHostPrefixCookieKey),
		ChallengeStore: &hostPrefixTestChallengeStore{},
	})
	require.NoError(t, err)
	return svc
}

// hostPrefixTestStore is a minimal in-package Store double (passkey/memory imports passkey, so
// the internal test file cannot use it without an import cycle).
type hostPrefixTestStore struct{}

func (hostPrefixTestStore) SaveCredential(context.Context, string, *Credential) error { return nil }
func (hostPrefixTestStore) GetCredentials(context.Context, string, uuid.UUID) ([]*Credential, error) {
	return nil, nil
}
func (hostPrefixTestStore) UpdateCredential(context.Context, string, *Credential) error {
	return nil
}
func (hostPrefixTestStore) DeleteCredential(context.Context, string, uuid.UUID, []byte) error {
	return nil
}

// hostPrefixTestChallengeStore is a minimal in-package ChallengeStore double.
type hostPrefixTestChallengeStore struct{}

func (hostPrefixTestChallengeStore) Put(context.Context, string, string, time.Time) error {
	return nil
}
func (hostPrefixTestChallengeStore) Consume(context.Context, string, string) (bool, error) {
	return true, nil
}

const testHostPrefixCookieKey = "0123456789abcdef0123456789abcdef"

func hostPrefixTestResolver(uid uuid.UUID) HandlerOption {
	return WithUserResolver(func(*http.Request) (uuid.UUID, string, string, string, bool) {
		return uid, "alice", "Alice", "t1", true
	})
}

func findCeremonyCookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestDefaultSessionCookieName_IsHostPrefixed(t *testing.T) {
	require.True(t, strings.HasPrefix(DefaultSessionCookieName, hostPrefix),
		"the default ceremony cookie name must carry the __Host- prefix (host-lock hardening)")
}

// TestBeginRegistrationHandler_HostLockedCeremonyCookieAttributes proves the emitted ceremony cookie
// satisfies the browser-enforced __Host- requirements the default name promises: Secure, no
// Domain, and Path=/.
func TestBeginRegistrationHandler_HostLockedCeremonyCookieAttributes(t *testing.T) {
	svc := hostPrefixTestService(t)
	h := BeginRegistrationHandler(svc,
		hostPrefixTestResolver(uuid.Must(uuid.NewV7())),
		WithCookieKey([]byte(testHostPrefixCookieKey)),
	)

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/passkey/register/begin", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	cookie := findCeremonyCookieByName(rec.Result().Cookies(), DefaultSessionCookieName)
	require.NotNil(t, cookie, "begin login must set the ceremony cookie")
	assert.NotEmpty(t, cookie.Value)
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure, "__Host- ceremony cookie must be Secure")
	assert.Empty(t, cookie.Domain, "__Host- ceremony cookie must be host-only (no Domain)")
	assert.Equal(t, "/", cookie.Path, "__Host- ceremony cookie must have Path=/")
}

func TestValidateHandlerConfig_HostPrefixAttributes(t *testing.T) {
	require.NoError(t, ValidateHandlerConfig(), "the default configuration is __Host--compatible")

	require.NoError(t, ValidateHandlerConfig(
		WithSessionCookieName("passkey_ceremony"), WithCookieDomain("example.com")),
		"non-__Host- name + Domain is the documented cross-subdomain opt-out")
	require.NoError(t, ValidateHandlerConfig(
		WithSessionCookieName("passkey_ceremony"), WithInsecureCookies()),
		"non-__Host- name + insecure cookies is allowed for plaintext HTTP dev")

	err := ValidateHandlerConfig(WithCookieDomain("example.com"))
	require.Error(t, err, "the default __Host- name rejects a shared Domain")
	assert.Contains(t, err.Error(), "Domain")

	err = ValidateHandlerConfig(WithInsecureCookies())
	require.Error(t, err, "the default __Host- name rejects insecure cookies")
	assert.Contains(t, err.Error(), "Secure")
}

func TestBeginRegistrationHandler_HostPrefixMisconfigurationFailsClosed(t *testing.T) {
	svc := hostPrefixTestService(t)
	subject := []HandlerOption{
		hostPrefixTestResolver(uuid.Must(uuid.NewV7())),
		WithCookieKey([]byte(testHostPrefixCookieKey)),
	}

	t.Run("domain with the default __Host- name", func(t *testing.T) {
		rec := httptest.NewRecorder()
		BeginRegistrationHandler(svc, append(append([]HandlerOption(nil), subject...), WithCookieDomain("example.com"))...)(
			rec, httptest.NewRequest(http.MethodPost, "/passkey/register/begin", nil))
		require.Equal(t, http.StatusInternalServerError, rec.Code,
			"a __Host- ceremony cookie with a Domain is silently discarded by browsers — the handler must fail closed")
		assert.Nil(t, findCeremonyCookieByName(rec.Result().Cookies(), DefaultSessionCookieName),
			"no ceremony cookie may be emitted from a misconfigured handler")
	})

	t.Run("insecure with the default __Host- name", func(t *testing.T) {
		rec := httptest.NewRecorder()
		BeginRegistrationHandler(svc, append(append([]HandlerOption(nil), subject...), WithInsecureCookies())...)(
			rec, httptest.NewRequest(http.MethodPost, "/passkey/register/begin", nil))
		require.Equal(t, http.StatusInternalServerError, rec.Code,
			"a __Host- ceremony cookie without Secure is silently discarded by browsers — the handler must fail closed")
		assert.Nil(t, findCeremonyCookieByName(rec.Result().Cookies(), DefaultSessionCookieName),
			"no ceremony cookie may be emitted from a misconfigured handler")
	})
}

func TestBeginRegistrationHandler_PlainNameOptOutSucceeds(t *testing.T) {
	svc := hostPrefixTestService(t)
	h := BeginRegistrationHandler(svc,
		hostPrefixTestResolver(uuid.Must(uuid.NewV7())),
		WithCookieKey([]byte(testHostPrefixCookieKey)),
		WithSessionCookieName("passkey_ceremony"),
		WithInsecureCookies(),
	)

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/passkey/register/begin", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotNil(t, findCeremonyCookieByName(rec.Result().Cookies(), "passkey_ceremony"),
		"the plain-name opt-out must still emit the ceremony cookie")
}
