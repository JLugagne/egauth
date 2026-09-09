package oauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for the state signing key minimum length: a key shorter than the 32-byte
// HMAC-SHA-256 output is brute-forceable offline from a single captured state cookie
// (see TestStateSigningKey_UnderMinimumBruteforceRecoverable), so the handlers must fail
// closed on it exactly like on a missing key (STATE-01).

func TestValidateHandlerConfig_RejectsShortStateSigningKey(t *testing.T) {
	for _, key := range [][]byte{
		[]byte("k"),
		[]byte("0123456789012345678901234567890"), // 31 bytes
	} {
		err := ValidateHandlerConfig(WithStateSigningKey(key))
		require.Error(t, err, "a %d-byte state signing key must fail the startup check", len(key))
		assert.Contains(t, err.Error(), "WithStateSigningKey")
		assert.Contains(t, err.Error(), "32")
	}

	require.NoError(t, ValidateHandlerConfig(WithStateSigningKey(make([]byte, MinStateSigningKeyLength))),
		"a key of exactly MinStateSigningKeyLength bytes must be accepted")
}

func TestBeginHandler_ShortStateSigningKeyFailsClosed(t *testing.T) {
	body := `{"sub":"prov-1"}`
	p, _ := stubProviderServer(t, &body)

	rec := httptest.NewRecorder()
	BeginHandler(p, WithRedirectURL(testRedirect), WithStateSigningKey([]byte("k")))(
		rec, httptest.NewRequest(http.MethodGet, "/auth/test/login", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code,
		"begin must fail closed with a too-short state signing key")
	assert.True(t, strings.Contains(rec.Body.String(), "misconfigured"),
		"the misconfiguration error must be surfaced like the missing-key one")
}

func TestCallbackHandler_ShortStateSigningKeyFailsClosed(t *testing.T) {
	body := `{"sub":"prov-1"}`
	p, _ := stubProviderServer(t, &body)

	rec := httptest.NewRecorder()
	CallbackHandler[struct{}](p, &stubLinker{}, &stubIssuer{}, claimsOf, WithRedirectURL(testRedirect), WithStateSigningKey([]byte("k")))(
		rec, httptest.NewRequest(http.MethodGet, "/auth/test/callback?state=s&code=c", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code,
		"callback must fail closed with a too-short state signing key")
}

// TestStateSigningKey_UnderMinimumBruteforceRecoverable documents the attack the minimum
// length prevents: a state cookie signed under a 1-byte HMAC key is recoverable offline by
// trying all 256 single-byte candidates. After the fix such a key can no longer be wired
// into the handlers, but the low-level pack/unpack primitives still demonstrate why the
// misconfiguration must be impossible.
func TestStateSigningKey_UnderMinimumBruteforceRecoverable(t *testing.T) {
	weakKey := []byte{0x9A}
	packed := packState("state", "verifier", "nonce", "google", "tenant", weakKey)

	for candidate := 0; candidate < 256; candidate++ {
		if _, _, _, _, _, ok := unpackState(packed, []byte{byte(candidate)}); ok {
			assert.Equal(t, weakKey, []byte{byte(candidate)},
				"the 1-byte signing key must be recoverable offline from a single captured cookie")
			return
		}
	}
	t.Fatal("1-byte HMAC key was not brute-forceable; the documented attack no longer reproduces")
}
