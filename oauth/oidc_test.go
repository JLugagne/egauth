package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oidcIssuer is a test double for an OIDC provider: it holds a signing key, serves its JWKS, and
// serves a configurable token-endpoint body.
type oidcIssuer struct {
	key       *rsa.PrivateKey
	kid       string
	iss       string
	tokenBody string
	srv       *httptest.Server
}

func newOIDCIssuer(t *testing.T) *oidcIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ti := &oidcIssuer{key: key, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, ti.jwksJSON())
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, ti.discoveryJSON())
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, ti.tokenBody)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	ti.srv = srv
	// The issuer is the server's own (http loopback) origin so the issuer host, discovery host and
	// jwks_uri host all match — exercising the SEC-07 host-binding path. Loopback http means tests
	// run on the dev-only AllowInsecureURLs path (the SSRF-safe client would block loopback).
	ti.iss = srv.URL
	return ti
}

// discoveryJSON serves the issuer's OIDC discovery document, binding jwks_uri to the issuer host.
func (ti *oidcIssuer) discoveryJSON() string {
	return fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, ti.iss, ti.jwksURL())
}

func (ti *oidcIssuer) jwksURL() string { return ti.srv.URL + "/jwks" }

func (ti *oidcIssuer) jwksJSON() string {
	n := base64.RawURLEncoding.EncodeToString(ti.key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(ti.key.E)).Bytes())
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"use":"sig","alg":"RS256","n":%q,"e":%q}]}`, ti.kid, n, e)
}

// sign builds a signed RS256 id_token from claims, filling default exp/iat when absent.
func (ti *oidcIssuer) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	return signWithKey(t, ti.key, ti.kid, claims)
}

func signWithKey(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = float64(time.Now().Add(time.Hour).Unix())
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = float64(time.Now().Add(-time.Minute).Unix())
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s
}

func baseIDClaims(iss, aud, nonce string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":            iss,
		"aud":            aud,
		"sub":            "oidc-sub-1",
		"email":          "u@example.com",
		"email_verified": true,
		"name":           "U",
		"nonce":          nonce,
	}
}

func (ti *oidcIssuer) verifier(t *testing.T) *oidcVerifier {
	t.Helper()
	// JWKSURL is intentionally omitted so the verifier resolves it via OIDC discovery (SEC-07).
	// AllowInsecureURLs lets the http loopback test IdP through the otherwise-https-only gate.
	v, err := newOIDCVerifier(OIDCConfig{
		Issuer:            ti.iss,
		Audience:          "cid",
		HTTPClient:        ti.srv.Client(),
		AllowInsecureURLs: true,
	}, "cid")
	require.NoError(t, err)
	return v
}

// --- verifier unit tests -------------------------------------------------------------------

func TestOIDCVerify_Valid(t *testing.T) {
	ti := newOIDCIssuer(t)
	idToken := ti.sign(t, baseIDClaims(ti.iss, "cid", "the-nonce"))

	info, err := ti.verifier(t).verify(context.Background(), idToken, "the-nonce")
	require.NoError(t, err)
	assert.Equal(t, "oidc-sub-1", info.ProviderID)
	assert.Equal(t, "u@example.com", info.Email)
	assert.True(t, info.EmailVerified)
	assert.Equal(t, "U", info.Name)
}

func TestOIDCVerify_BadSignatureRejected(t *testing.T) {
	ti := newOIDCIssuer(t)
	// Sign with a DIFFERENT key than the one published in the JWKS.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	idToken := signWithKey(t, otherKey, ti.kid, baseIDClaims(ti.iss, "cid", "n"))

	_, err = ti.verifier(t).verify(context.Background(), idToken, "n")
	require.ErrorIs(t, err, ErrIDTokenInvalid)
}

func TestOIDCVerify_WrongIssuerRejected(t *testing.T) {
	ti := newOIDCIssuer(t)
	idToken := ti.sign(t, baseIDClaims("https://evil.test", "cid", "n"))

	_, err := ti.verifier(t).verify(context.Background(), idToken, "n")
	require.ErrorIs(t, err, ErrIDTokenInvalid)
}

func TestOIDCVerify_WrongAudienceRejected(t *testing.T) {
	ti := newOIDCIssuer(t)
	idToken := ti.sign(t, baseIDClaims(ti.iss, "someone-else", "n"))

	_, err := ti.verifier(t).verify(context.Background(), idToken, "n")
	require.ErrorIs(t, err, ErrIDTokenInvalid)
}

func TestOIDCVerify_MultiAudienceWithoutAzpRejected(t *testing.T) {
	ti := newOIDCIssuer(t)
	claims := baseIDClaims(ti.iss, "cid", "n")
	// Our audience is present, but alongside another party and with no azp: a confused-deputy
	// token (OIDC Core 3.1.3.7) — must be rejected.
	claims["aud"] = []string{"cid", "other-client"}
	idToken := ti.sign(t, claims)

	_, err := ti.verifier(t).verify(context.Background(), idToken, "n")
	require.ErrorIs(t, err, ErrIDTokenInvalid)
}

func TestOIDCVerify_MultiAudienceWithMatchingAzpAccepted(t *testing.T) {
	ti := newOIDCIssuer(t)
	claims := baseIDClaims(ti.iss, "cid", "n")
	claims["aud"] = []string{"cid", "other-client"}
	claims["azp"] = "cid"
	idToken := ti.sign(t, claims)

	info, err := ti.verifier(t).verify(context.Background(), idToken, "n")
	require.NoError(t, err)
	assert.Equal(t, "oidc-sub-1", info.ProviderID)
}

func TestOIDCVerify_AzpMismatchRejected(t *testing.T) {
	ti := newOIDCIssuer(t)
	claims := baseIDClaims(ti.iss, "cid", "n")
	// Single audience contains us, but the token was authorized for a different party.
	claims["azp"] = "other-client"
	idToken := ti.sign(t, claims)

	_, err := ti.verifier(t).verify(context.Background(), idToken, "n")
	require.ErrorIs(t, err, ErrIDTokenInvalid)
}

func TestOIDCVerify_ExpiredRejected(t *testing.T) {
	ti := newOIDCIssuer(t)
	claims := baseIDClaims(ti.iss, "cid", "n")
	claims["exp"] = float64(time.Now().Add(-time.Hour).Unix())
	idToken := ti.sign(t, claims)

	_, err := ti.verifier(t).verify(context.Background(), idToken, "n")
	require.ErrorIs(t, err, ErrIDTokenInvalid)
}

func TestOIDCVerify_NonceMismatchRejected(t *testing.T) {
	ti := newOIDCIssuer(t)
	idToken := ti.sign(t, baseIDClaims(ti.iss, "cid", "minted-nonce"))

	_, err := ti.verifier(t).verify(context.Background(), idToken, "different-nonce")
	require.ErrorIs(t, err, ErrNonceMismatch)
}

func TestOIDCVerify_MissingNonceClaimRejected(t *testing.T) {
	ti := newOIDCIssuer(t)
	claims := baseIDClaims(ti.iss, "cid", "")
	delete(claims, "nonce")
	idToken := ti.sign(t, claims)

	_, err := ti.verifier(t).verify(context.Background(), idToken, "expected")
	require.ErrorIs(t, err, ErrNonceMismatch)
}

func TestOIDCVerify_EmptyExpectedNonceRejected(t *testing.T) {
	ti := newOIDCIssuer(t)
	idToken := ti.sign(t, baseIDClaims(ti.iss, "cid", "some-nonce"))

	// An empty expected nonce must never pass, even if the token carries one.
	_, err := ti.verifier(t).verify(context.Background(), idToken, "")
	require.ErrorIs(t, err, ErrNonceMismatch)
}

func TestOIDCVerify_AlgNoneRejected(t *testing.T) {
	ti := newOIDCIssuer(t)
	claims := baseIDClaims(ti.iss, "cid", "n")
	claims["exp"] = float64(time.Now().Add(time.Hour).Unix())
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	idToken, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = ti.verifier(t).verify(context.Background(), idToken, "n")
	require.ErrorIs(t, err, ErrIDTokenInvalid)
}

func TestOIDCVerify_HS256ConfusionRejected(t *testing.T) {
	ti := newOIDCIssuer(t)
	claims := baseIDClaims(ti.iss, "cid", "n")
	claims["exp"] = float64(time.Now().Add(time.Hour).Unix())
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	idToken, err := tok.SignedString([]byte("shared-secret-guess"))
	require.NoError(t, err)

	// A symmetric alg must be rejected outright (alg-confusion defense), not verified against
	// the RSA public key.
	_, err = ti.verifier(t).verify(context.Background(), idToken, "n")
	require.ErrorIs(t, err, ErrIDTokenInvalid)
}

func TestOIDCVerify_MissingSubRejected(t *testing.T) {
	ti := newOIDCIssuer(t)
	claims := baseIDClaims(ti.iss, "cid", "n")
	delete(claims, "sub")
	idToken := ti.sign(t, claims)

	_, err := ti.verifier(t).verify(context.Background(), idToken, "n")
	require.ErrorIs(t, err, ErrIDTokenInvalid)
}

func TestOIDCVerify_UnknownKidRejected(t *testing.T) {
	ti := newOIDCIssuer(t)
	claims := baseIDClaims(ti.iss, "cid", "n")
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "rotated-away-kid"
	idToken, err := tok.SignedString(ti.key)
	require.NoError(t, err)

	_, err = ti.verifier(t).verify(context.Background(), idToken, "n")
	require.ErrorIs(t, err, ErrIDTokenInvalid)
}

// --- JWKS parsing --------------------------------------------------------------------------

// ecXY returns the base64url-encoded affine coordinates of an EC public key (from its SEC1
// uncompressed encoding), avoiding the deprecated raw X/Y fields.
func ecXY(t *testing.T, pub *ecdsa.PublicKey) (string, string) {
	t.Helper()
	raw, err := pub.Bytes()
	require.NoError(t, err)
	size := (pub.Curve.Params().BitSize + 7) / 8
	require.Len(t, raw, 1+2*size)
	return base64.RawURLEncoding.EncodeToString(raw[1 : 1+size]),
		base64.RawURLEncoding.EncodeToString(raw[1+size:])
}

func TestParseJWKS_RSAandEC(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rn := base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes())
	re := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes())
	ex, ey := ecXY(t, &ecKey.PublicKey)
	doc := fmt.Sprintf(`{"keys":[
		{"kty":"RSA","kid":"r1","use":"sig","n":%q,"e":%q},
		{"kty":"EC","kid":"e1","crv":"P-256","x":%q,"y":%q},
		{"kty":"RSA","kid":"enc1","use":"enc","n":%q,"e":%q}
	]}`, rn, re, ex, ey, rn, re)

	keys, err := parseJWKS([]byte(doc))
	require.NoError(t, err)
	assert.Len(t, keys, 2, "the enc key must be skipped")
	assert.IsType(t, &rsa.PublicKey{}, keys["r1"])
	assert.IsType(t, &ecdsa.PublicKey{}, keys["e1"])
	assert.Equal(t, rsaKey.N, keys["r1"].(*rsa.PublicKey).N)
	assert.True(t, keys["e1"].(*ecdsa.PublicKey).Equal(&ecKey.PublicKey), "EC key must round-trip")
}

func TestParseJWKS_NoUsableKeys(t *testing.T) {
	_, err := parseJWKS([]byte(`{"keys":[{"kty":"OKP","kid":"x","crv":"Ed25519","x":"abc"}]}`))
	require.ErrorIs(t, err, ErrIDTokenInvalid)
}

// --- ECDSA end-to-end ----------------------------------------------------------------------

func TestOIDCVerify_ES256(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	const kid = "ec-1"
	ex, ey := ecXY(t, &ecKey.PublicKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, fmt.Sprintf(`{"keys":[{"kty":"EC","kid":%q,"crv":"P-256","x":%q,"y":%q}]}`, kid, ex, ey))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	// Bind the discovery document's issuer and jwks_uri to the server's loopback origin so the
	// SEC-07 host-binding check passes; the http loopback runs on the dev/insecure path.
	iss := srv.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, iss, srv.URL+"/jwks"))
	})

	claims := baseIDClaims(iss, "cid", "ec-nonce")
	claims["exp"] = float64(time.Now().Add(time.Hour).Unix())
	claims["iat"] = float64(time.Now().Add(-time.Minute).Unix())
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	idToken, err := tok.SignedString(ecKey)
	require.NoError(t, err)

	v, err := newOIDCVerifier(OIDCConfig{Issuer: iss, Audience: "cid", HTTPClient: srv.Client(), AllowInsecureURLs: true}, "cid")
	require.NoError(t, err)
	info, err := v.verify(context.Background(), idToken, "ec-nonce")
	require.NoError(t, err)
	assert.Equal(t, "oidc-sub-1", info.ProviderID)
}

// --- configuration -------------------------------------------------------------------------

func TestNewOIDCVerifier_Validation(t *testing.T) {
	t.Run("issuer required", func(t *testing.T) {
		_, err := newOIDCVerifier(OIDCConfig{JWKSURL: "https://x/jwks"}, "cid")
		require.Error(t, err)
	})
	t.Run("non-https issuer rejected by default", func(t *testing.T) {
		_, err := newOIDCVerifier(OIDCConfig{Issuer: "http://x"}, "cid")
		require.Error(t, err)
	})
	t.Run("jwks optional - discovery used when absent", func(t *testing.T) {
		// SEC-07: JWKSURL is no longer required; an absent one is resolved lazily via discovery,
		// so construction succeeds (the network call happens at first verify, not here).
		v, err := newOIDCVerifier(OIDCConfig{Issuer: "https://x"}, "cid")
		require.NoError(t, err)
		assert.Empty(t, v.jwks.url, "jwks url is resolved lazily via discovery")
	})
	t.Run("jwks override with matching host accepted", func(t *testing.T) {
		v, err := newOIDCVerifier(OIDCConfig{Issuer: "https://x.example.com", JWKSURL: "https://x.example.com/jwks"}, "cid")
		require.NoError(t, err)
		assert.Equal(t, "https://x.example.com/jwks", v.jwks.url)
	})
	t.Run("jwks override on a different host accepted", func(t *testing.T) {
		v, err := newOIDCVerifier(OIDCConfig{Issuer: "https://accounts.google.com", JWKSURL: "https://www.googleapis.com/oauth2/v3/certs"}, "cid")
		require.NoError(t, err)
		assert.Equal(t, "https://www.googleapis.com/oauth2/v3/certs", v.jwks.url)
	})
	t.Run("audience required when no clientID", func(t *testing.T) {
		_, err := newOIDCVerifier(OIDCConfig{Issuer: "https://x", JWKSURL: "https://x/jwks"}, "")
		require.Error(t, err)
	})
	t.Run("defaults clientID as audience", func(t *testing.T) {
		v, err := newOIDCVerifier(OIDCConfig{Issuer: "https://x", JWKSURL: "https://x/jwks"}, "my-client")
		require.NoError(t, err)
		assert.Equal(t, "my-client", v.audience)
	})
}

// --- handler integration -------------------------------------------------------------------

func runBeginCapture(t *testing.T, p *Provider, opts ...HandlerOption) (*http.Cookie, string, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	BeginHandler(p, opts...)(rec, httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil))
	require.Equal(t, http.StatusFound, rec.Code)

	res := rec.Result()
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == DefaultStateCookieName {
			cookie = c
		}
	}
	require.NotNil(t, cookie)
	loc, err := url.Parse(res.Header.Get("Location"))
	require.NoError(t, err)
	q := loc.Query()
	return cookie, q.Get("state"), q.Get("nonce")
}

func (ti *oidcIssuer) provider(t *testing.T) *Provider {
	t.Helper()
	fetch := func(context.Context, *http.Client, string) (*UserInfo, error) {
		t.Fatal("fetchUser must not be called for an OIDC-enabled provider")
		return nil, nil
	}
	// WithInsecureURLs + AllowInsecureURLs put this on the dev path so the http loopback test IdP
	// (auth/token/issuer/discovery/jwks) is accepted; JWKSURL is omitted to exercise discovery.
	return New("oidc-test", "cid", "secret", ti.srv.URL+"/auth", ti.srv.URL+"/token",
		[]string{"openid", "email"}, fetch,
		WithHTTPClient(ti.srv.Client()),
		WithInsecureURLs(),
		WithOIDC(OIDCConfig{Issuer: ti.iss, Audience: "cid", HTTPClient: ti.srv.Client(), AllowInsecureURLs: true}))
}

func TestBeginHandler_OIDCMintsNonce(t *testing.T) {
	ti := newOIDCIssuer(t)
	_, _, nonce := runBeginCapture(t, ti.provider(t), WithRedirectURL(testRedirect))
	assert.NotEmpty(t, nonce, "OIDC begin must include a nonce in the authorization URL")
}

func TestBeginHandler_NonOIDCHasNoNonce(t *testing.T) {
	body := `{"sub":"s","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)
	_, _, nonce := runBeginCapture(t, p, WithRedirectURL(testRedirect))
	assert.Empty(t, nonce, "a plain OAuth2 provider must not emit a nonce")
}

func TestCallbackHandler_OIDCSuccess(t *testing.T) {
	ti := newOIDCIssuer(t)
	p := ti.provider(t)
	cookie, state, nonce := runBeginCapture(t, p, WithRedirectURL(testRedirect))

	idToken := ti.sign(t, baseIDClaims(ti.iss, "cid", nonce))
	ti.tokenBody = fmt.Sprintf(`{"access_token":"at","token_type":"bearer","id_token":%q}`, idToken)

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{AccessToken: "a", RefreshToken: "r", RefreshTokenExpiresAt: time.Now().Add(time.Hour)}}

	rec := runCallback(t, p, linker, issuer, cookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "oidc-sub-1", linker.gotProviderID, "provider id must come from the verified id_token sub")
	assert.Equal(t, "u@example.com", linker.gotEmail)
	assert.True(t, linker.gotVerified)
}

func TestCallbackHandler_OIDCNonceMismatchRejected(t *testing.T) {
	ti := newOIDCIssuer(t)
	p := ti.provider(t)
	cookie, state, _ := runBeginCapture(t, p, WithRedirectURL(testRedirect))

	// id_token carries a nonce that does NOT match the one bound to the state cookie.
	idToken := ti.sign(t, baseIDClaims(ti.iss, "cid", "attacker-nonce"))
	ti.tokenBody = fmt.Sprintf(`{"access_token":"at","token_type":"bearer","id_token":%q}`, idToken)

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7())}}
	rec := runCallback(t, p, linker, &stubIssuer{}, cookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))

	assert.Equal(t, http.StatusBadGateway, rec.Code, "a nonce mismatch must fail the exchange")
	assert.Empty(t, linker.gotProviderID, "linker must not be reached on a failed id_token validation")
}

func TestCallbackHandler_OIDCMissingIDTokenRejected(t *testing.T) {
	ti := newOIDCIssuer(t)
	p := ti.provider(t)
	cookie, state, _ := runBeginCapture(t, p, WithRedirectURL(testRedirect))

	ti.tokenBody = `{"access_token":"at","token_type":"bearer"}` // no id_token

	rec := runCallback(t, p, &stubLinker{}, &stubIssuer{}, cookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect))

	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

// rsaJWKEntry renders a single RSA JWK object string from an explicit modulus and exponent
// big.Int, used to build hostile JWKS documents in the SEC-11 bound tests.
func rsaJWKEntry(kid string, n, e *big.Int) string {
	rn := base64.RawURLEncoding.EncodeToString(n.Bytes())
	re := base64.RawURLEncoding.EncodeToString(e.Bytes())
	return fmt.Sprintf(`{"kty":"RSA","kid":%q,"use":"sig","n":%q,"e":%q}`, kid, rn, re)
}

// TestParseJWKS_TooManyKeysRejected covers SEC-11 #1: a JWKS declaring more than maxJWKSKeys
// keys is rejected outright before any per-key construction is attempted.
func TestParseJWKS_TooManyKeysRejected(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	n := rsaKey.N
	e := big.NewInt(int64(rsaKey.E))

	entries := make([]string, 0, maxJWKSKeys+1)
	for i := range maxJWKSKeys + 1 {
		entries = append(entries, rsaJWKEntry(fmt.Sprintf("k%d", i), n, e))
	}
	doc := fmt.Sprintf(`{"keys":[%s]}`, strings.Join(entries, ","))

	_, err = parseJWKS([]byte(doc))
	require.ErrorIs(t, err, ErrIDTokenInvalid)
}

// TestParseJWKS_KeyCountAtCapAccepted is a positive control: exactly maxJWKSKeys valid keys parse.
func TestParseJWKS_KeyCountAtCapAccepted(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	n := rsaKey.N
	e := big.NewInt(int64(rsaKey.E))

	entries := make([]string, 0, maxJWKSKeys)
	for i := range maxJWKSKeys {
		entries = append(entries, rsaJWKEntry(fmt.Sprintf("k%d", i), n, e))
	}
	doc := fmt.Sprintf(`{"keys":[%s]}`, strings.Join(entries, ","))

	keys, err := parseJWKS([]byte(doc))
	require.NoError(t, err)
	assert.Len(t, keys, maxJWKSKeys)
}

// TestParseJWKS_RSAModulusTooSmallRejected covers SEC-11 #2: a sub-2048-bit RSA modulus is the
// only key, so the whole document yields no usable signing keys.
func TestParseJWKS_RSAModulusTooSmallRejected(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	doc := fmt.Sprintf(`{"keys":[%s]}`, rsaJWKEntry("small", small.N, big.NewInt(int64(small.E))))

	_, err = parseJWKS([]byte(doc))
	require.ErrorIs(t, err, ErrIDTokenInvalid)
}

// TestParseJWKS_RSAModulusTooLargeRejected covers SEC-11 #2: an absurd >8192-bit modulus is skipped.
func TestParseJWKS_RSAModulusTooLargeRejected(t *testing.T) {
	// Synthesise a 9000-bit modulus without paying for key generation.
	n := new(big.Int).Lsh(big.NewInt(1), 8999)
	n.SetBit(n, 0, 1) // make it odd, harmless cosmetic
	doc := fmt.Sprintf(`{"keys":[%s]}`, rsaJWKEntry("huge", n, big.NewInt(65537)))

	_, err := parseJWKS([]byte(doc))
	require.ErrorIs(t, err, ErrIDTokenInvalid)
}

// TestParseJWKS_BadExponentRejected covers SEC-11 #2: e=1, an even e, and an absurdly large e are
// each rejected, so a document carrying only such a key has no usable signing keys.
func TestParseJWKS_BadExponentRejected(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	n := rsaKey.N

	cases := map[string]*big.Int{
		"e=1":      big.NewInt(1),
		"e=even":   big.NewInt(4),
		"e=toobig": new(big.Int).Lsh(big.NewInt(1), 40),
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			doc := fmt.Sprintf(`{"keys":[%s]}`, rsaJWKEntry("bad", n, e))
			_, err := parseJWKS([]byte(doc))
			require.ErrorIs(t, err, ErrIDTokenInvalid)
		})
	}
}

// TestParseJWKS_BadKeySkippedAmongGood confirms reject-vs-skip semantics: an oversized key alongside
// a valid one is silently dropped while the good key survives.
func TestParseJWKS_BadKeySkippedAmongGood(t *testing.T) {
	good, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	huge := new(big.Int).Lsh(big.NewInt(1), 8999)
	doc := fmt.Sprintf(`{"keys":[%s,%s]}`,
		rsaJWKEntry("good", good.N, big.NewInt(int64(good.E))),
		rsaJWKEntry("huge", huge, big.NewInt(65537)),
	)

	keys, err := parseJWKS([]byte(doc))
	require.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.IsType(t, &rsa.PublicKey{}, keys["good"])
	_, ok := keys["huge"]
	assert.False(t, ok, "oversized key must be skipped")
}

// TestWithOIDC_DefersErrorOnInvalidConfig covers PANIC-01: an invalid OIDCConfig must NOT
// panic during construction. WithOIDC runs synchronously inside New, and on the dynamic
// ProviderStore that runs per request over tenant-controlled data, so a panic there breaks the
// login route. The error is instead deferred onto the Provider (configErr) and surfaced at
// Exchange, mirroring the existing non-https endpoint configErr pattern.
func TestWithOIDC_DefersErrorOnInvalidConfig(t *testing.T) {
	var p *Provider
	assert.NotPanics(t, func() {
		p = New("google", "cid", "secret", "https://accounts.google.com/o/oauth2/v2/auth",
			"https://oauth2.googleapis.com/token", []string{"openid", "email", "profile"}, nil,
			WithOIDC(OIDCConfig{Issuer: "", JWKSURL: ""}))
	})
	require.NotNil(t, p)
	// OIDC verifier construction failed, so the provider fails closed: oidcEnabled is false (no
	// nil-deref of p.oidc anywhere) and Exchange returns the deferred configErr.
	assert.False(t, p.oidcEnabled())
	_, err := p.Exchange(context.Background(), "code", "https://app/cb", "verifier")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WithOIDC")
}

// TestJWKSCache_NegativeCachingAndRateLimiting covers SEC-OAU-05:
// 1. Repeated lookups for an unknown kid do not trigger repeated JWKS HTTP fetches (negative caching).
// 2. Rapid lookups for distinct unknown kids within minRefreshInterval do not trigger repeated JWKS HTTP fetches (cooldown rate limiting).
func TestJWKSCache_NegativeCachingAndRateLimiting(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	n := base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes())
	jwksJSON := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"valid-key","use":"sig","alg":"RS256","n":%q,"e":%q}]}`, n, e)

	var jwksRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jwksRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, jwksJSON)
	}))
	defer srv.Close()

	mockNow := time.Now()
	cache := &jwksCache{
		url:           srv.URL,
		allowInsecure: true,
		client:        srv.Client(),
		ttl:           time.Hour,
		now:           func() time.Time { return mockNow },
	}

	ctx := context.Background()

	// 1. First lookup for unknown kid triggers JWKS refresh.
	_, err = cache.publicKey(ctx, "unknown-kid-1")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrIDTokenInvalid)
	assert.Equal(t, int32(1), jwksRequests.Load(), "first lookup for unknown-kid-1 triggers JWKS refresh")

	// 2. Repeated lookup for the exact same unknown kid within negative TTL must NOT trigger JWKS refresh.
	_, err = cache.publicKey(ctx, "unknown-kid-1")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrIDTokenInvalid)
	assert.Equal(t, int32(1), jwksRequests.Load(), "repeated lookup for unknown-kid-1 must use negative cache")

	// 3. Rapid lookup for a distinct unknown kid within minRefreshInterval (e.g., 1s later) must NOT trigger JWKS refresh.
	mockNow = mockNow.Add(1 * time.Second)
	_, err = cache.publicKey(ctx, "unknown-kid-2")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrIDTokenInvalid)
	assert.Equal(t, int32(1), jwksRequests.Load(), "rapid lookup for different unknown-kid-2 within minRefreshInterval must be rate limited")

	// 4. Repeated lookup for unknown-kid-2 must also hit negative cache.
	_, err = cache.publicKey(ctx, "unknown-kid-2")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrIDTokenInvalid)
	assert.Equal(t, int32(1), jwksRequests.Load(), "repeated lookup for unknown-kid-2 must hit negative cache")

	// 5. Lookup after minRefreshInterval (e.g., 6 seconds after last refresh):
	// Cooldown has expired, so looking up a new unknown kid triggers a refresh.
	mockNow = mockNow.Add(6 * time.Second)
	_, err = cache.publicKey(ctx, "unknown-kid-3")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrIDTokenInvalid)
	assert.Equal(t, int32(2), jwksRequests.Load(), "lookup for new unknown kid after minRefreshInterval triggers JWKS refresh")

	// 6. Valid kid lookup succeeds and does not trigger another refresh.
	key, err := cache.publicKey(ctx, "valid-key")
	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, int32(2), jwksRequests.Load(), "valid kid lookup returns cached key without refresh")
}

// TestJWKSCache_NegativeCache_Eviction verifies that the negative cache size is bounded
// at maxNegativeCacheEntries to prevent memory exhaustion (SEC-OAU-05).
func TestJWKSCache_NegativeCache_Eviction(t *testing.T) {
	mockNow := time.Now()
	cache := &jwksCache{
		negativeTTL: 30 * time.Second,
		now:         func() time.Time { return mockNow },
	}

	// Insert more than maxNegativeCacheEntries entries.
	for i := 0; i < maxNegativeCacheEntries+50; i++ {
		cache.setNegative(fmt.Sprintf("kid-%d", i))
	}

	cache.mu.RLock()
	size := len(cache.negCache)
	cache.mu.RUnlock()

	assert.LessOrEqual(t, size, maxNegativeCacheEntries, "negative cache size must be capped at maxNegativeCacheEntries")

	// Advance time so that existing entries expire, and insert a new one.
	mockNow = mockNow.Add(35 * time.Second)
	cache.setNegative("new-kid")

	cache.mu.RLock()
	sizeAfterExpiry := len(cache.negCache)
	cache.mu.RUnlock()

	assert.Equal(t, 1, sizeAfterExpiry, "expired entries should be cleaned up on eviction")
	assert.True(t, cache.isNegativelyCached("new-kid"))
}

// TestJWKSCache_NegativeCache_Expiry verifies that expired negative cache entries allow refetch.
func TestJWKSCache_NegativeCache_Expiry(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	n := base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes())
	jwksJSON := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"valid-key","use":"sig","alg":"RS256","n":%q,"e":%q}]}`, n, e)

	var jwksRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, jwksJSON)
	}))
	defer srv.Close()

	mockNow := time.Now()
	cache := &jwksCache{
		url:           srv.URL,
		allowInsecure: true,
		client:        srv.Client(),
		ttl:           time.Hour,
		negativeTTL:   30 * time.Second,
		now:           func() time.Time { return mockNow },
	}

	ctx := context.Background()

	// Initial lookup for unknown kid triggers JWKS refresh.
	_, err = cache.publicKey(ctx, "unknown-kid")
	require.Error(t, err)
	assert.Equal(t, int32(1), jwksRequests.Load())

	// Advance time past negative TTL.
	mockNow = mockNow.Add(35 * time.Second)

	// Now that negative TTL has expired (and cooldown has expired too), looking up unknown-kid
	// should trigger another refresh attempt.
	_, err = cache.publicKey(ctx, "unknown-kid")
	require.Error(t, err)
	assert.Equal(t, int32(2), jwksRequests.Load(), "lookup after negative TTL expiry triggers a new refresh")
}

// TestWithOIDC_AllowedAlgsValidation covers SEC-OAU-09:
// "none" and symmetric HMAC algorithms are forbidden in AllowedAlgs to prevent algorithm-confusion attacks.
// Supported asymmetric algorithms (RS*, ES*, PS*, EdDSA) are accepted.
func TestWithOIDC_AllowedAlgsValidation(t *testing.T) {
	t.Run("rejects none algorithm", func(t *testing.T) {
		p := New("oidc", "client-id", "client-secret",
			"https://auth.example.com/authorize",
			"https://auth.example.com/token",
			[]string{"openid"},
			nil,
			WithOIDC(OIDCConfig{
				Issuer:      "https://idp.example.com",
				AllowedAlgs: []string{"none"},
			}),
		)
		require.Error(t, p.configErr)
		assert.Contains(t, p.configErr.Error(), "algorithm \"none\" is not allowed")
	})

	t.Run("rejects HS256 algorithm", func(t *testing.T) {
		p := New("oidc", "client-id", "client-secret",
			"https://auth.example.com/authorize",
			"https://auth.example.com/token",
			[]string{"openid"},
			nil,
			WithOIDC(OIDCConfig{
				Issuer:      "https://idp.example.com",
				AllowedAlgs: []string{"HS256"},
			}),
		)
		require.Error(t, p.configErr)
		assert.Contains(t, p.configErr.Error(), "algorithm \"HS256\" is not allowed")
	})

	t.Run("allows valid asymmetric algorithms", func(t *testing.T) {
		p := New("oidc", "client-id", "client-secret",
			"https://auth.example.com/authorize",
			"https://auth.example.com/token",
			[]string{"openid"},
			nil,
			WithOIDC(OIDCConfig{
				Issuer:      "https://idp.example.com",
				AllowedAlgs: []string{"RS256", "ES256"},
			}),
		)
		assert.NoError(t, p.configErr)
		assert.True(t, p.oidcEnabled())
	})
}
