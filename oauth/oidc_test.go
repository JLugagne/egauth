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
	t.Run("jwks override with mismatched host rejected", func(t *testing.T) {
		_, err := newOIDCVerifier(OIDCConfig{Issuer: "https://x.example.com", JWKSURL: "https://evil.example.net/jwks"}, "cid")
		require.ErrorIs(t, err, ErrJWKSHostMismatch)
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

func TestWithOIDC_PanicsOnInvalidConfig(t *testing.T) {
	assert.Panics(t, func() {
		Google("cid", "secret", WithOIDC(OIDCConfig{Issuer: "", JWKSURL: ""}))
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

	linker := &stubLinker{user: &identity.User{ID: uuid.New(), Email: "u@example.com"}}
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

	linker := &stubLinker{user: &identity.User{ID: uuid.New()}}
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
