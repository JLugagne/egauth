package oauth

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for SEC-12: OAuth state cookie binding to provider + tenant.

func TestPackUnpackState_RoundTripWithProviderTenant(t *testing.T) {
	cases := []struct {
		name                                     string
		state, verifier, nonce, provider, tenant string
	}{
		{"plain", "st", "vf", "nc", "google", "acme"},
		{"empty_optional", "st", "", "", "google", ""},
		{"separator_in_fields", "st", "vf", "nc", "prov.with.dots", "tenant.x.y"},
		{"spaces", "st", "vf", "nc", "my provider", "big tenant"},
		{"unicode", "st", "vf", "nc", "providér-名", "tenànt-名"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			packed := packState(tc.state, tc.verifier, tc.nonce, tc.provider, tc.tenant)
			state, verifier, nonce, provider, tenant, ok := unpackState(packed)
			require.True(t, ok, "well-formed packed state must unpack")
			assert.Equal(t, tc.state, state)
			assert.Equal(t, tc.verifier, verifier)
			assert.Equal(t, tc.nonce, nonce)
			assert.Equal(t, tc.provider, provider)
			assert.Equal(t, tc.tenant, tenant)
		})
	}
}

func TestUnpackState_RejectsWrongFieldCount(t *testing.T) {
	// A legacy / forged 3-field cookie must fail closed.
	legacy := "st" + stateSeparator + "vf" + stateSeparator + "nc"
	_, _, _, _, _, ok := unpackState(legacy)
	assert.False(t, ok, "old 3-field cookie must be rejected")

	// Too many fields.
	_, _, _, _, _, ok = unpackState("a.b.c.d.e.f")
	assert.False(t, ok, "6-field cookie must be rejected")

	// Empty state.
	_, _, _, _, _, ok = unpackState("")
	assert.False(t, ok, "empty cookie must be rejected")
}

// TestCallbackHandler_ProviderConfusionRejected drives a Begin for provider A,
// captures its state cookie + state query param, and replays them against a
// Callback bound to a different provider B. The mismatch must be rejected.
func TestCallbackHandler_ProviderConfusionRejected(t *testing.T) {
	bodyA := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	pA, _ := stubProviderServer(t, &bodyA)

	bodyB := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	pB, _ := stubProviderServer(t, &bodyB)
	// Give provider B a distinct name so the binding can tell them apart.
	pB.name = "other"

	stateCookie, state := runBegin(t, pA, WithRedirectURL(testRedirect))

	// Replaying provider A's cookie against provider B's callback must fail.
	recB := runCallback(t, pB, &stubLinker{}, &stubIssuer{}, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))
	assert.Equal(t, http.StatusForbidden, recB.Code, "cross-provider state replay must be rejected")

	// Sanity: replaying against provider A's own callback still works.
	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour)}}
	recA := runCallback(t, pA, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))
	assert.Equal(t, http.StatusNoContent, recA.Code, "same-provider callback must still succeed")
}

// TestCallbackHandler_TenantConfusionRejected packs a state cookie for tenant X
// and presents it to a callback resolving tenant Y.
func TestCallbackHandler_TenantConfusionRejected(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)

	tenantX := func(*http.Request) string { return "tenant-x" }
	tenantY := func(*http.Request) string { return "tenant-y" }

	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect), WithTenantResolver(tenantX))

	// Callback resolving a different tenant must reject the cookie.
	recY := runCallback(t, p, &stubLinker{}, &stubIssuer{}, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect), WithTenantResolver(tenantY))
	assert.Equal(t, http.StatusForbidden, recY.Code, "cross-tenant state replay must be rejected")

	// Same tenant still succeeds.
	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour)}}
	recX := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect), WithTenantResolver(tenantX))
	assert.Equal(t, http.StatusNoContent, recX.Code, "same-tenant callback must still succeed")
}

// Tests for SEC-OAU-03: State cookie HMAC integrity verification.

func TestPackUnpackState_HMAC(t *testing.T) {
	key := []byte("01234567890123456789012345678901") // 32 bytes
	state := "my-state"
	verifier := "my-verifier"
	nonce := "my-nonce"
	provider := "google"
	tenant := "acme"

	packed := packState(state, verifier, nonce, provider, tenant, key)
	gotState, gotVerifier, gotNonce, gotProvider, gotTenant, ok := unpackState(packed, key)
	require.True(t, ok, "valid signed state must unpack successfully")
	assert.Equal(t, state, gotState)
	assert.Equal(t, verifier, gotVerifier)
	assert.Equal(t, nonce, gotNonce)
	assert.Equal(t, provider, gotProvider)
	assert.Equal(t, tenant, gotTenant)

	// Tampered payload must fail
	tamperedPayload := "other-state" + packed[len(state):]
	_, _, _, _, _, ok = unpackState(tamperedPayload, key)
	assert.False(t, ok, "tampered state payload must fail unpackState")

	// Tampered signature must fail
	tamperedSig := packed[:len(packed)-3] + "xyz"
	_, _, _, _, _, ok = unpackState(tamperedSig, key)
	assert.False(t, ok, "tampered signature must fail unpackState")

	// Unsigned (legacy 5-part) cookie must fail when key is required
	unsigned := packState(state, verifier, nonce, provider, tenant)
	_, _, _, _, _, ok = unpackState(unsigned, key)
	assert.False(t, ok, "unsigned state cookie must fail when signing key is provided")

	// Wrong key must fail
	wrongKey := []byte("wrongwrongwrongwrongwrongwrong12")
	_, _, _, _, _, ok = unpackState(packed, wrongKey)
	assert.False(t, ok, "state cookie verified with wrong key must fail")
}

func TestCallbackHandler_StateHMAC_TamperedAndUnauthenticatedRejected(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)
	key := []byte("01234567890123456789012345678901")

	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect), WithStateSigningKey(key))

	// 1. Tampered cookie value rejected with 403 invalid_state
	tamperedCookie := &http.Cookie{
		Name:  stateCookie.Name,
		Value: stateCookie.Value + "tampered",
	}
	recTampered := runCallback(t, p, &stubLinker{}, &stubIssuer{}, tamperedCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect), WithStateSigningKey(key))
	assert.Equal(t, http.StatusForbidden, recTampered.Code)
	assert.Contains(t, recTampered.Body.String(), "invalid_state")

	// 2. Unsigned / unauthenticated cookie rejected with 403 invalid_state
	unsignedCookie := &http.Cookie{
		Name:  stateCookie.Name,
		Value: packState(state, "vf", "nc", p.Name(), ""),
	}
	recUnsigned := runCallback(t, p, &stubLinker{}, &stubIssuer{}, unsignedCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect), WithStateSigningKey(key))
	assert.Equal(t, http.StatusForbidden, recUnsigned.Code)
	assert.Contains(t, recUnsigned.Body.String(), "invalid_state")

	// 3. Legitimate signed cookie succeeds
	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour)}}
	recValid := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect), WithStateSigningKey(key))
	assert.Equal(t, http.StatusNoContent, recValid.Code)
}
