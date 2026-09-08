// Regression tests for SECRETS-02 (issue #105): the passkey ceremony-cookie HMAC
// keys published in this repo's examples and SDK docs are publicly known on GitHub,
// yet they satisfy MinCookieKeyLength — and an all-zero key passes the length gate
// trivially. The length gate alone cannot reject them, so NewService must refuse an
// all-zero key and any key copied from a published example outright: a copy-pasted
// deployment must fail fast instead of HMAC-ing ceremony cookies with an
// attacker-known key.

package passkey_test

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	"github.com/JLugagne/egauth/passkey/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// publishedCookieKey is the exact ceremony-cookie key literal published in the SDK
// docs (docs/content/docs/sdk/mfa.md). It passes the MinCookieKeyLength gate, which
// is why a dedicated denylist is required to reject it.
const publishedCookieKey = "very-secure-32-byte-secret-key!!"

func TestNewService_RejectsAllZeroCookieKey(t *testing.T) {
	cfg := secureCfg()
	cfg.CookieKey = make([]byte, passkey.MinCookieKeyLength)
	_, err := passkey.NewService(memory.NewStore(), cfg)
	require.Error(t, err, "an all-zero cookie key must be rejected at construction")
	assert.Contains(t, err.Error(), "all zero", "the error should name the all-zero key")
	assert.Contains(t, err.Error(), "crypto/rand", "the error should be actionable: point at crypto/rand or a secret manager")
}

func TestNewService_RejectsPublishedDocsCookieKey(t *testing.T) {
	cfg := secureCfg()
	cfg.CookieKey = []byte(publishedCookieKey)
	require.GreaterOrEqual(t, len(cfg.CookieKey), passkey.MinCookieKeyLength,
		"the published docs key must pass the length gate for this test to be meaningful")
	_, err := passkey.NewService(memory.NewStore(), cfg)
	require.Error(t, err, "the published docs cookie key must be rejected at construction")
	assert.Contains(t, err.Error(), "published", "the error should call out the published example key")
	assert.Contains(t, err.Error(), "crypto/rand", "the error should be actionable: point at crypto/rand or a secret manager")
}

func TestNewService_InsecureNoChallengeStoreDoesNotBypassCookieKeyDenylist(t *testing.T) {
	cfg := secureCfg()
	cfg.CookieKey = []byte(publishedCookieKey)
	cfg.ChallengeStore = nil
	cfg.InsecureNoChallengeStore = true
	_, err := passkey.NewService(memory.NewStore(), cfg)
	require.Error(t, err, "the insecure challenge-store opt-out must not re-accept a published cookie key")
}

func TestNewService_AcceptsRandomCookieKey(t *testing.T) {
	cfg := secureCfg()
	cfg.CookieKey = make([]byte, passkey.MinCookieKeyLength)
	_, err := rand.Read(cfg.CookieKey)
	require.NoError(t, err)
	_, err = passkey.NewService(memory.NewStore(), cfg)
	require.NoError(t, err, "a legitimate random 32-byte cookie key must still be accepted")
}

func TestBeginRegistrationHandler_ZeroCookieKeyOverrideFailsClosed(t *testing.T) {
	svc, _ := testService(t)
	// A per-handler WithCookieKey override of all-zero bytes must fail closed, exactly
	// like the short-key override: NewService's guard must not be silently bypassable
	// at the handler layer with an attacker-known HMAC key.
	zero := make([]byte, passkey.MinCookieKeyLength)
	h := passkey.BeginRegistrationHandler(svc, resolver(uuid.Must(uuid.NewV7())), passkey.WithCookieKey(zero))
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Nil(t, findCookie(rec.Result().Cookies(), passkey.DefaultSessionCookieName))
}

func TestBeginRegistrationHandler_PublishedCookieKeyOverrideFailsClosed(t *testing.T) {
	svc, _ := testService(t)
	h := passkey.BeginRegistrationHandler(svc, resolver(uuid.Must(uuid.NewV7())), passkey.WithCookieKey([]byte(publishedCookieKey)))
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Nil(t, findCookie(rec.Result().Cookies(), passkey.DefaultSessionCookieName))
}

func TestBeginRegistrationHandler_TenantResolverZeroKeyFailsClosed(t *testing.T) {
	svc, _ := testService(t)
	h := passkey.BeginRegistrationHandler(svc, resolver(uuid.Must(uuid.NewV7())),
		passkey.WithTenantCookieKeys(func(context.Context, string) ([]byte, error) {
			return make([]byte, passkey.MinCookieKeyLength), nil
		}))
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Nil(t, findCookie(rec.Result().Cookies(), passkey.DefaultSessionCookieName))
}
