package oauth

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// These tests drive the OAuth state cookie with deterministic pseudo-random inputs and check
// that the signed state either round-trips exactly or fails closed: a tampered, truncated,
// wrongly-keyed, replayed (already-cleared) or cross-tenant value must never be accepted.

const statePropAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"

func statePropSegment(rng *rand.Rand, maxLen int) string {
	b := make([]byte, rng.Intn(maxLen+1))
	for i := range b {
		b[i] = statePropAlphabet[rng.Intn(len(statePropAlphabet))]
	}
	return string(b)
}

// statePropText produces arbitrary text (including dots, spaces and non-ASCII) for the fields
// that packState base64-encodes before joining, so they cannot disturb the field layout.
func statePropText(rng *rand.Rand, maxLen int) string {
	runes := []rune("aA0.-_@:/ üñλ世")
	b := make([]rune, rng.Intn(maxLen+1))
	for i := range b {
		b[i] = runes[rng.Intn(len(runes))]
	}
	return string(b)
}

func statePropBytes(rng *rand.Rand, minLen, maxLen int) []byte {
	b := make([]byte, minLen+rng.Intn(maxLen-minLen+1))
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return b
}

// TestOAuthStateProperty_SignUnpackRoundTrip checks the pack/unpack inverse property and the
// fail-closed axes of the decoder: tampering, truncation, a wrong key and a missing key.
func TestOAuthStateProperty_SignUnpackRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5eed))

	for i := 0; i < 400; i++ {
		key := statePropBytes(rng, 16, 64)
		state := statePropSegment(rng, 32)
		for state == "" {
			state = statePropSegment(rng, 32)
		}
		verifier := statePropSegment(rng, 64)
		nonce := statePropSegment(rng, 64)
		provider := statePropText(rng, 24)
		tenant := statePropText(rng, 24)

		packed := packState(state, verifier, nonce, provider, tenant, key)
		gotState, gotVerifier, gotNonce, gotProvider, gotTenant, ok := unpackState(packed, key)
		require.True(t, ok, "iteration %d: signed state must unpack", i)
		require.Equal(t, state, gotState)
		require.Equal(t, verifier, gotVerifier)
		require.Equal(t, nonce, gotNonce)
		require.Equal(t, provider, gotProvider)
		require.Equal(t, tenant, gotTenant)

		// A signed value must not be usable with any other key, and no key at all.
		other := statePropBytes(rng, 16, 64)
		for string(other) == string(key) {
			other = statePropBytes(rng, 16, 64)
		}
		_, _, _, _, _, ok = unpackState(packed, other)
		require.False(t, ok, "iteration %d: a foreign key must reject the state", i)
		_, _, _, _, _, ok = unpackState(packed, nil)
		require.False(t, ok, "iteration %d: an unsigned decode must fail closed", i)

		// Tampering: changing any single character except the very last (whose trailing bits
		// the lenient base64 decoder may ignore) must invalidate the value.
		if len(packed) > 1 {
			pos := rng.Intn(len(packed) - 1)
			replacement := byte(statePropAlphabet[rng.Intn(len(statePropAlphabet))])
			for replacement == packed[pos] {
				replacement = statePropAlphabet[rng.Intn(len(statePropAlphabet))]
			}
			tampered := packed[:pos] + string(replacement) + packed[pos+1:]
			_, _, _, _, _, ok = unpackState(tampered, key)
			require.False(t, ok, "iteration %d: tampered state must be rejected", i)
		}

		// Truncation must never yield a valid decode.
		if len(packed) > 1 {
			cut := rng.Intn(len(packed))
			_, _, _, _, _, ok = unpackState(packed[:cut], key)
			require.False(t, ok, "iteration %d: truncated state must be rejected", i)
		}
	}

	// packState without a key is never acceptable to unpackState: there is no "unsigned mode".
	unsigned := packState("state", "verifier", "nonce", "provider", "tenant", nil)
	_, _, _, _, _, ok := unpackState(unsigned, statePropBytes(rng, 16, 64))
	require.False(t, ok, "a state packed without a key must never unpack")
}

// TestOAuthStateProperty_CallbackBinding checks the callback-level invariants: the state cookie
// expires with the configured TTL, a valid cookie is single-use (always cleared), and a
// missing, tampered or cross-tenant cookie fails closed without invoking the linker or issuing
// auth cookies.
func TestOAuthStateProperty_CallbackBinding(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)
	rng := rand.New(rand.NewSource(2026))

	for i := 0; i < 8; i++ {
		tenantA := fmt.Sprintf("tenant-%d-a", i)
		tenantB := fmt.Sprintf("tenant-%d-b", i)
		resolverA := func(*http.Request) string { return tenantA }
		resolverB := func(*http.Request) string { return tenantB }

		ttl := time.Duration(1+rng.Intn(300)) * time.Second
		stateCookie, state := runBegin(t, p,
			WithRedirectURL(testRedirect),
			WithTenantResolver(resolverA),
			WithStateTTL(ttl))
		require.Equal(t, int(ttl.Seconds()), stateCookie.MaxAge,
			"the state cookie's Max-Age is the server-side expiry bound")
		require.Greater(t, stateCookie.MaxAge, 0)

		// Happy path: the exact tenant and state succeed, and the cookie is consumed.
		linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
		issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
			AccessToken:           "access",
			RefreshToken:          "refresh",
			RefreshTokenExpiresAt: time.Now().Add(time.Hour),
		}}
		query := url.Values{"state": {state}, "code": {"auth-code"}}.Encode()
		rec := runCallback(t, p, linker, issuer, stateCookie, query,
			WithRedirectURL(testRedirect), WithTenantResolver(resolverA))
		require.Equal(t, http.StatusNoContent, rec.Code, "a valid state/tenant pair must succeed")
		require.True(t, stateCookieCleared(rec), "the callback must consume the state cookie")
		require.Equal(t, "prov-1", linker.gotProviderID, "the linker must have run on the valid callback")

		// Cross-tenant replay: the same signed cookie presented under another tenant fails
		// closed before the identity link or issuance.
		crossLinker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
		crossIssuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
			AccessToken:           "access",
			RefreshToken:          "refresh",
			RefreshTokenExpiresAt: time.Now().Add(time.Hour),
		}}
		rec = runCallback(t, p, crossLinker, crossIssuer, stateCookie, query,
			WithRedirectURL(testRedirect), WithTenantResolver(resolverB))
		require.Equal(t, http.StatusForbidden, rec.Code, "a cross-tenant state cookie must fail closed")
		require.True(t, stateCookieCleared(rec))
		require.Empty(t, crossLinker.gotProviderID, "no identity linking may occur on a rejected callback")
		require.False(t, authCookieIssued(rec), "no auth cookie may be issued on a rejected callback")

		// Tampered cookie: flipping the first byte of the signed value fails closed.
		tampered := *stateCookie
		tampered.Value = flipFirstByte(stateCookie.Value)
		tamperLinker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
		rec = runCallback(t, p, tamperLinker, crossIssuer, &tampered, query,
			WithRedirectURL(testRedirect), WithTenantResolver(resolverA))
		require.Equal(t, http.StatusForbidden, rec.Code, "a tampered state cookie must fail closed")
		require.True(t, stateCookieCleared(rec))
		require.Empty(t, tamperLinker.gotProviderID)
		require.False(t, authCookieIssued(rec))

		// Replayed (already-cleared) or expired cookie: no cookie at all fails closed.
		rec = runCallback(t, p, tamperLinker, crossIssuer, nil, query,
			WithRedirectURL(testRedirect), WithTenantResolver(resolverA))
		require.Equal(t, http.StatusForbidden, rec.Code, "a missing state cookie must fail closed")
		require.True(t, stateCookieCleared(rec))
		require.Empty(t, tamperLinker.gotProviderID)
		require.False(t, authCookieIssued(rec))
	}
}

// flipFirstByte changes the first character of s so the signed payload differs.
func flipFirstByte(s string) string {
	if s == "" {
		return "x"
	}
	if s[0] == 'x' {
		return "y" + s[1:]
	}
	return "x" + s[1:]
}

// stateCookieCleared reports whether the response instructs the browser to delete the state
// cookie (Max-Age < 0), which is what makes the state single-use.
func stateCookieCleared(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == DefaultStateCookieName && c.Value == "" && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

// authCookieIssued reports whether the response carries a non-empty auth access cookie.
func authCookieIssued(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == tokens.DefaultAccessCookieName && c.Value != "" {
			return true
		}
	}
	return false
}
