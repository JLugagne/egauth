package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// discoveryServer is a configurable OIDC IdP test double for the SEC-07 discovery + host-binding
// tests. The discovery document's issuer and jwks_uri are independently settable so tests can
// inject the exact mismatch they assert on.
type discoveryServer struct {
	srv         *httptest.Server
	key         *rsa.PrivateKey
	kid         string
	docIssuer   string // value placed in the discovery doc's "issuer" field
	docJWKSURI  string // value placed in the discovery doc's "jwks_uri" field
	omitJWKSURI bool
}

func newDiscoveryServer(t *testing.T) *discoveryServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	d := &discoveryServer{key: key, kid: "disc-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(d.key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(d.key.E)).Bytes())
		_, _ = io.WriteString(w, fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"use":"sig","alg":"RS256","n":%q,"e":%q}]}`, d.kid, n, e))
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if d.omitJWKSURI {
			_, _ = io.WriteString(w, fmt.Sprintf(`{"issuer":%q}`, d.docIssuer))
			return
		}
		_, _ = io.WriteString(w, fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, d.docIssuer, d.docJWKSURI))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	d.srv = srv
	// Default to a self-consistent document bound to the server's own loopback origin.
	d.docIssuer = srv.URL
	d.docJWKSURI = srv.URL + "/jwks"
	return d
}

func (d *discoveryServer) signedToken(t *testing.T, iss, nonce string) string {
	t.Helper()
	return signWithKey(t, d.key, d.kid, baseIDClaims(iss, "cid", nonce))
}

// TestOIDCDiscovery_HappyPath verifies a token whose signing keys are resolved purely via OIDC
// discovery: no JWKSURL is configured, the verifier fetches the openid-configuration, follows
// jwks_uri, and validates the signature.
func TestOIDCDiscovery_HappyPath(t *testing.T) {
	d := newDiscoveryServer(t)
	iss := d.srv.URL

	v, err := newOIDCVerifier(OIDCConfig{
		Issuer:            iss,
		Audience:          "cid",
		HTTPClient:        d.srv.Client(),
		AllowInsecureURLs: true,
	}, "cid")
	require.NoError(t, err)

	info, err := v.verify(context.Background(), d.signedToken(t, iss, "the-nonce"), "the-nonce")
	require.NoError(t, err)
	assert.Equal(t, "oidc-sub-1", info.ProviderID)
	assert.Equal(t, d.srv.URL+"/jwks", v.jwks.url, "verifier must resolve jwks_uri from discovery")
}

// TestOIDCDiscovery_JWKSHostMismatchRejected covers a discovery document whose jwks_uri points at
// a different host than the issuer: the keys must not be trusted.
func TestOIDCDiscovery_JWKSHostMismatchRejected(t *testing.T) {
	d := newDiscoveryServer(t)
	iss := d.srv.URL
	d.docJWKSURI = "https://evil.example.net/jwks" // foreign host

	v, err := newOIDCVerifier(OIDCConfig{
		Issuer:            iss,
		Audience:          "cid",
		HTTPClient:        d.srv.Client(),
		AllowInsecureURLs: true,
	}, "cid")
	require.NoError(t, err)

	_, err = v.verify(context.Background(), d.signedToken(t, iss, "n"), "n")
	require.ErrorIs(t, err, ErrJWKSHostMismatch)
}

// TestOIDCDiscovery_DocIssuerMismatchRejected covers a discovery document whose own "issuer"
// field does not equal the configured issuer (OIDC discovery forbids this).
func TestOIDCDiscovery_DocIssuerMismatchRejected(t *testing.T) {
	d := newDiscoveryServer(t)
	iss := d.srv.URL
	d.docIssuer = "https://someone-else.example.com" // lies about its identity

	v, err := newOIDCVerifier(OIDCConfig{
		Issuer:            iss,
		Audience:          "cid",
		HTTPClient:        d.srv.Client(),
		AllowInsecureURLs: true,
	}, "cid")
	require.NoError(t, err)

	_, err = v.verify(context.Background(), d.signedToken(t, iss, "n"), "n")
	require.ErrorIs(t, err, ErrJWKSHostMismatch)
}

// TestOIDCDiscovery_MissingJWKSURIRejected covers a discovery document with no jwks_uri.
func TestOIDCDiscovery_MissingJWKSURIRejected(t *testing.T) {
	d := newDiscoveryServer(t)
	iss := d.srv.URL
	d.omitJWKSURI = true

	v, err := newOIDCVerifier(OIDCConfig{
		Issuer:            iss,
		Audience:          "cid",
		HTTPClient:        d.srv.Client(),
		AllowInsecureURLs: true,
	}, "cid")
	require.NoError(t, err)

	_, err = v.verify(context.Background(), d.signedToken(t, iss, "n"), "n")
	require.ErrorIs(t, err, ErrIDTokenInvalid)
}

// TestOIDCConfig_ExplicitJWKSHostMismatchRejected covers SEC-07's other arm: an explicitly
// supplied JWKSURL whose host differs from the issuer host is rejected at construction.
func TestOIDCConfig_ExplicitJWKSHostMismatchRejected(t *testing.T) {
	_, err := newOIDCVerifier(OIDCConfig{
		Issuer:   "https://idp.example.com",
		JWKSURL:  "https://evil.example.net/jwks",
		Audience: "cid",
	}, "cid")
	require.ErrorIs(t, err, ErrJWKSHostMismatch)
}

// TestOIDCConfig_ExplicitJWKSHostMatchAccepted covers the supported override: a JWKSURL on the
// same host as the issuer is accepted and used verbatim (no discovery).
func TestOIDCConfig_ExplicitJWKSHostMatchAccepted(t *testing.T) {
	v, err := newOIDCVerifier(OIDCConfig{
		Issuer:   "https://idp.example.com",
		JWKSURL:  "https://idp.example.com/keys",
		Audience: "cid",
	}, "cid")
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example.com/keys", v.jwks.url)
}

// TestOIDCHTTPS_EnforcedByDefault asserts SEC-06: non-https issuer / JWKS URLs are rejected by
// default, and the WithInsecureURLs/AllowInsecureURLs opt-in flips that behaviour.
func TestOIDCHTTPS_EnforcedByDefault(t *testing.T) {
	t.Run("http issuer rejected by default", func(t *testing.T) {
		_, err := newOIDCVerifier(OIDCConfig{Issuer: "http://idp.example.com", Audience: "cid"}, "cid")
		require.ErrorIs(t, err, ErrBlockedURL)
	})
	t.Run("http issuer allowed with opt-in", func(t *testing.T) {
		_, err := newOIDCVerifier(OIDCConfig{Issuer: "http://idp.example.com", Audience: "cid", AllowInsecureURLs: true}, "cid")
		require.NoError(t, err)
	})
	t.Run("http JWKS override rejected by default", func(t *testing.T) {
		_, err := newOIDCVerifier(OIDCConfig{Issuer: "https://idp.example.com", JWKSURL: "http://idp.example.com/jwks", Audience: "cid"}, "cid")
		require.ErrorIs(t, err, ErrBlockedURL)
	})
	t.Run("http JWKS override allowed with opt-in", func(t *testing.T) {
		_, err := newOIDCVerifier(OIDCConfig{Issuer: "http://idp.example.com", JWKSURL: "http://idp.example.com/jwks", Audience: "cid", AllowInsecureURLs: true}, "cid")
		require.NoError(t, err)
	})
}

// TestProviderHTTPS_EnforcedByDefault asserts SEC-06 at the Provider level: a non-https auth or
// token URL is rejected (surfaced by Exchange) unless WithInsecureURLs is set.
func TestProviderHTTPS_EnforcedByDefault(t *testing.T) {
	fetch := func(context.Context, *http.Client, string) (*UserInfo, error) { return &UserInfo{}, nil }

	t.Run("http token url rejected by default", func(t *testing.T) {
		p := New("x", "cid", "secret", "https://idp.example.com/auth", "http://idp.example.com/token", nil, fetch)
		_, err := p.Exchange(context.Background(), "code", "https://app/cb", "")
		require.ErrorIs(t, err, ErrBlockedURL)
	})
	t.Run("http auth url rejected by default", func(t *testing.T) {
		p := New("x", "cid", "secret", "http://idp.example.com/auth", "https://idp.example.com/token", nil, fetch)
		_, err := p.Exchange(context.Background(), "code", "https://app/cb", "")
		require.ErrorIs(t, err, ErrBlockedURL)
	})
	t.Run("http urls allowed with opt-in", func(t *testing.T) {
		p := New("x", "cid", "secret", "http://idp.example.com/auth", "http://idp.example.com/token", nil, fetch, WithInsecureURLs())
		assert.NoError(t, p.configErr)
	})
}
