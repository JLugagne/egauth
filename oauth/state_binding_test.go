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
	linker := &stubLinker{user: &identity.User{ID: uuid.New(), Email: "u@example.com"}}
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
	linker := &stubLinker{user: &identity.User{ID: uuid.New(), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour)}}
	recX := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect), WithTenantResolver(tenantX))
	assert.Equal(t, http.StatusNoContent, recX.Code, "same-tenant callback must still succeed")
}
