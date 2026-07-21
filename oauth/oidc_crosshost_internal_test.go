package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOIDCConfig_ExplicitCrossHostJWKS_Accepted is a regression test for the OIDC cross-host bug:
// a spec-compliant issuer (Google) whose jwks_uri lives on a different host than the issuer must
// be accepted as an explicit JWKSURL override, not rejected with ErrJWKSHostMismatch.
func TestOIDCConfig_ExplicitCrossHostJWKS_Accepted(t *testing.T) {
	v, err := newOIDCVerifier(OIDCConfig{
		Issuer:   "https://accounts.google.com",
		JWKSURL:  "https://www.googleapis.com/oauth2/v3/certs",
		Audience: "cid",
	}, "cid")
	require.NotErrorIs(t, err, ErrJWKSHostMismatch)
	require.NoError(t, err)
	assert.Equal(t, "https://www.googleapis.com/oauth2/v3/certs", v.jwks.url)
}

// TestOIDCDiscovery_CrossHostJWKS_Accepted is a regression test for the OIDC cross-host bug on the
// discovery path: when the discovery document's own "issuer" matches the configured issuer
// exactly, a jwks_uri on a different host (as Google publishes) must be trusted and used to
// validate a token end-to-end — not rejected with ErrJWKSHostMismatch.
func TestOIDCDiscovery_CrossHostJWKS_Accepted(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const kid = "cross-key-1"

	const issuer = "http://idp.example.test"
	const jwksURL = "http://keys.example.test/jwks"

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, issuer, jwksURL))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		_, _ = io.WriteString(w, fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"use":"sig","alg":"RS256","n":%q,"e":%q}]}`, kid, n, e))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	backend := srv.Listener.Addr().String()
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, backend)
		},
	}}

	v, err := newOIDCVerifier(OIDCConfig{
		Issuer:            issuer,
		Audience:          "cid",
		HTTPClient:        client,
		AllowInsecureURLs: true,
	}, "cid")
	require.NoError(t, err)

	info, err := v.verify(context.Background(), signWithKey(t, key, kid, baseIDClaims(issuer, "cid", "the-nonce")), "the-nonce")
	require.NotErrorIs(t, err, ErrJWKSHostMismatch)
	require.NoError(t, err)
	assert.Equal(t, "oidc-sub-1", info.ProviderID)
	assert.Equal(t, jwksURL, v.jwks.url)
}
