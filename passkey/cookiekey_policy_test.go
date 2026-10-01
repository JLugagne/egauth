// Regression tests for F-PASSKEY-003: the ceremony-cookie key validation must apply the
// shared credential-material policy (internal/secretpolicy), not a private partial denylist.
// Repeated-single-byte keys and near-copies of published example keys pass the length gate but
// are guessable/attacker-known, so they must be refused at construction and per request.
package passkey_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/internal/secretpolicy"
	"github.com/JLugagne/egauth/passkey"
	"github.com/JLugagne/egauth/passkey/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewService_RejectsRepeatedByteCookieKey covers the trivially guessable class: any key
// made of one repeated byte satisfies the length gate and can be guessed from a short
// weak-key dictionary, so it must be refused with the shared ErrTrivial sentinel.
func TestNewService_RejectsRepeatedByteCookieKey(t *testing.T) {
	for _, b := range []byte{0x00, 0x42, 0xff} {
		cfg := secureCfg()
		cfg.CookieKey = bytes.Repeat([]byte{b}, passkey.MinCookieKeyLength)
		_, err := passkey.NewService(memory.NewStore(), cfg)
		require.Error(t, err, "a repeated-byte cookie key (0x%02x) must be rejected", b)
		assert.ErrorIs(t, err, secretpolicy.ErrTrivial,
			"the refusal must come from the shared policy, not a private check")
	}
}

// TestNewService_RejectsNearCopyCookieKey covers the marker class: a key that merely contains
// a marker from a published example credential is attacker-known even though it is not
// byte-identical to any listed literal.
func TestNewService_RejectsNearCopyCookieKey(t *testing.T) {
	cfg := secureCfg()
	cfg.CookieKey = []byte("prefix-a-32-byte-minimum-hs256-signing-secret-suffix!!")
	require.GreaterOrEqual(t, len(cfg.CookieKey), passkey.MinCookieKeyLength)
	_, err := passkey.NewService(memory.NewStore(), cfg)
	require.Error(t, err, "a near-copy of a published example key must be rejected")
	assert.ErrorIs(t, err, secretpolicy.ErrNearCopy)
}

// TestBeginRegistrationHandler_RepeatedByteCookieKeyOverrideFailsClosed proves the per-request
// key resolution applies the same policy: a handler-level WithCookieKey override must not be
// able to smuggle in a trivially guessable key after construction.
func TestBeginRegistrationHandler_RepeatedByteCookieKeyOverrideFailsClosed(t *testing.T) {
	svc, _ := testService(t)
	weak := bytes.Repeat([]byte{'a'}, passkey.MinCookieKeyLength)
	h := passkey.BeginRegistrationHandler(svc, resolver(uuid.Must(uuid.NewV7())), passkey.WithCookieKey(weak), passkey.WithInsecureNoAssuranceCheck())
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Nil(t, findCookie(rec.Result().Cookies(), passkey.DefaultSessionCookieName))
}
