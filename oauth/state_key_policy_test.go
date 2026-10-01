package oauth

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// F-OAFLOW-001 regression: the state signing key is validated by the shared credential
// policy, not a single exact-match denylist lookup. The passkey SDK-doc literal and
// marker-bearing near-copies are attacker-known; a state cookie forged under one of them
// binds the CSRF state, PKCE verifier, OIDC nonce, provider, tenant and redirect_uri, so
// the callback would accept an attacker-crafted flow.
func TestValidateHandlerConfig_RejectsPublishedAndNearCopyStateKeys(t *testing.T) {
	keys := map[string]string{
		"published passkey literal": "very-secure-32-byte-secret-key!!",
		"published HS256 literal":   "super-secret-32-byte-key-here!!!",
		"marker near-copy":          "a-32-byte-minimum-hs256-signing-secret!!-prod",
	}
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			err := ValidateHandlerConfig(WithStateSigningKey([]byte(key)))
			require.Error(t, err, "a published/near-copy state signing key must fail the startup check")
			assert.Contains(t, err.Error(), "published")
		})
	}
}

func TestValidateHandlerConfig_AcceptsANonTrivialMinimumLengthKey(t *testing.T) {
	key := make([]byte, MinStateSigningKeyLength)
	_, err := rand.Read(key)
	require.NoError(t, err)
	require.NoError(t, ValidateHandlerConfig(WithStateSigningKey(key)))
}

func TestBeginHandler_PublishedStateKeyFailsClosed(t *testing.T) {
	body := `{"sub":"prov-1"}`
	p, _ := stubProviderServer(t, &body)

	for _, key := range []string{
		"very-secure-32-byte-secret-key!!",
		"super-secret-32-byte-key-here!!!",
		"a-32-byte-minimum-hs256-signing-secret!!-prod",
	} {
		t.Run(key, func(t *testing.T) {
			rec := httptest.NewRecorder()
			BeginHandler(p, WithRedirectURL(testRedirect), WithStateSigningKey([]byte(key)))(
				rec, httptest.NewRequest(http.MethodGet, "/auth/test/login", nil))
			assert.Equal(t, http.StatusInternalServerError, rec.Code)
			assert.Empty(t, rec.Header().Get("Location"), "no redirect may be emitted under a known key")
		})
	}
}

// TestCallbackHandler_ForgedCookieUnderKnownStateKeyIsRefused mirrors the audit PoC: an
// attacker who knows the configured key can pack a complete state bucket, so the callback
// must refuse the handler configuration rather than issue a session from the forged cookie.
func TestCallbackHandler_ForgedCookieUnderKnownStateKeyIsRefused(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)

	publishedKey := []byte("very-secure-32-byte-secret-key!!")
	forged := packState(stateBucket{
		State:       "attacker-state",
		Verifier:    "attacker-verifier",
		Provider:    p.Name(),
		RedirectURI: testRedirect,
		IssuedAt:    time.Now().Unix(),
	}, publishedKey)

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}
	rec := runCallback(t, p, linker, issuer,
		&http.Cookie{Name: DefaultStateCookieName, Value: forged},
		url.Values{"state": {"attacker-state"}, "code": {"attacker-code"}}.Encode(),
		WithRedirectURL(testRedirect), WithStateSigningKey(publishedKey))

	assert.NotEqual(t, http.StatusNoContent, rec.Code,
		"a forged state cookie signed with a published key must not drive issuance")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}
