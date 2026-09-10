package passkey

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/require"
)

// These tests drive the passkey ceremony-cookie seal/open primitives with deterministic
// pseudo-random inputs. The cookie is the only trusted carrier of the WebAuthn challenge
// between Begin and Finish, so seal/open must round-trip exactly and fail closed on every
// other input: a wrong key, a wrong tenant, a tampered or truncated value.

const propCookieAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"

func propCookieBytes(rng *rand.Rand, minLen, maxLen int) []byte {
	b := make([]byte, minLen+rng.Intn(maxLen-minLen+1))
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return b
}

func propCookieString(rng *rand.Rand, maxLen int) string {
	b := make([]byte, rng.Intn(maxLen+1))
	for i := range b {
		b[i] = propCookieAlphabet[rng.Intn(len(propCookieAlphabet))]
	}
	return string(b)
}

// TestPasskeyCookieProperty_SealOpenRoundTrip checks the seal/open inverse property and the
// fail-closed axes: wrong key, tampering, truncation and arbitrary attacker strings.
func TestPasskeyCookieProperty_SealOpenRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(0xc00c1e))
	cfg := handlerConfig{}

	for i := 0; i < 400; i++ {
		key := propCookieBytes(rng, MinCookieKeyLength, MinCookieKeyLength+32)
		raw := propCookieBytes(rng, 0, 256)

		sealed := cfg.seal(key, raw)
		got, ok := cfg.open(key, sealed)
		require.True(t, ok, "iteration %d: a sealed value must open", i)
		require.Equal(t, raw, got, "iteration %d: open must return the exact payload", i)

		// A foreign key must never open the value.
		other := propCookieBytes(rng, MinCookieKeyLength, MinCookieKeyLength+32)
		for string(other) == string(key) {
			other = propCookieBytes(rng, MinCookieKeyLength, MinCookieKeyLength+32)
		}
		_, ok = cfg.open(other, sealed)
		require.False(t, ok, "iteration %d: a foreign key must reject the cookie", i)

		// Tampering: changing any single character except the very last (whose trailing bits
		// the lenient base64 decoder may ignore) must invalidate the value.
		if len(sealed) > 1 {
			pos := rng.Intn(len(sealed) - 1)
			replacement := byte(propCookieAlphabet[rng.Intn(len(propCookieAlphabet))])
			for replacement == sealed[pos] {
				replacement = propCookieAlphabet[rng.Intn(len(propCookieAlphabet))]
			}
			tampered := sealed[:pos] + string(replacement) + sealed[pos+1:]
			_, ok = cfg.open(key, tampered)
			require.False(t, ok, "iteration %d: tampered cookie must be rejected", i)
		}

		// Truncation must never yield the payload.
		if len(sealed) > 1 {
			cut := rng.Intn(len(sealed))
			_, ok = cfg.open(key, sealed[:cut])
			require.False(t, ok, "iteration %d: truncated cookie must be rejected", i)
		}

		// An arbitrary attacker string must never open.
		_, ok = cfg.open(key, propCookieString(rng, 128))
		require.False(t, ok, "iteration %d: an arbitrary cookie string must be rejected", i)
	}
}

// TestPasskeyCookieProperty_TenantBinding checks that a ceremony cookie sealed for one tenant
// cannot be opened under another, and that a matching tenant round-trips the SessionData.
func TestPasskeyCookieProperty_TenantBinding(t *testing.T) {
	rng := rand.New(rand.NewSource(0x7e2a17))

	for i := 0; i < 12; i++ {
		tenantA := fmt.Sprintf("tenant-%d-a", i)
		tenantB := fmt.Sprintf("tenant-%d-b", i)
		keyA := propCookieBytes(rng, MinCookieKeyLength, MinCookieKeyLength+16)
		keyB := propCookieBytes(rng, MinCookieKeyLength, MinCookieKeyLength+16)

		resolver := func(_ context.Context, tenant string) ([]byte, error) {
			switch tenant {
			case tenantA:
				return keyA, nil
			case tenantB:
				return keyB, nil
			default:
				return nil, errors.New("unknown tenant")
			}
		}
		cfg := handlerConfig{
			sessionCookie:  DefaultSessionCookieName,
			sessionTTL:     time.Minute,
			cookieSameSite: http.SameSiteLaxMode,
			cookieKeys:     resolver,
		}

		want := webauthn.SessionData{
			Challenge:        propCookieString(rng, 64),
			UserVerification: protocol.VerificationRequired,
		}

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/passkey/begin", nil)
		require.True(t, cfg.storeSession(rec, req, tenantA, &want), "sealing for tenant A must succeed")
		cookie := findCookie(rec, DefaultSessionCookieName)
		require.NotNil(t, cookie)
		require.NotEmpty(t, cookie.Value)

		// Same cookie, different tenant: the per-tenant key must reject it.
		otherRec := httptest.NewRecorder()
		otherReq := httptest.NewRequest(http.MethodPost, "/passkey/finish", nil)
		otherReq.AddCookie(cookie)
		got, ok := cfg.loadSession(otherRec, otherReq, tenantB)
		require.False(t, ok, "iteration %d: a cookie sealed for tenant A must not open under tenant B", i)
		require.Equal(t, webauthn.SessionData{}, got)
		require.True(t, ceremonyCookieCleared(otherRec), "loadSession must clear the ceremony cookie")

		// Same cookie, matching tenant: round-trips the SessionData.
		matchRec := httptest.NewRecorder()
		matchReq := httptest.NewRequest(http.MethodPost, "/passkey/finish", nil)
		matchReq.AddCookie(cookie)
		got, ok = cfg.loadSession(matchRec, matchReq, tenantA)
		require.True(t, ok, "iteration %d: the sealing tenant must open its own cookie", i)
		require.Equal(t, want, got)
		require.True(t, ceremonyCookieCleared(matchRec))
	}
}

func findCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func ceremonyCookieCleared(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == DefaultSessionCookieName && c.Value == "" && c.MaxAge < 0 {
			return true
		}
	}
	return false
}
