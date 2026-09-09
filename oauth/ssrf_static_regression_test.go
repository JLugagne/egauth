package oauth

// Regression tests for issue #117: the STATIC OIDC path (WithOIDC with HTTPClient nil) must not
// fall back to a plain redirect-following HTTP client. The default must be SafeHTTPClient — the
// dial-time SSRF guard refuses loopback/internal targets and 3xx responses are never followed —
// with the plain client reserved for the AllowInsecureURLs=true dev opt-in.
import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connCountListener counts accepted connections at the socket level. A dial is counted even when
// the subsequent TLS handshake fails client-side, so it observes "did any fetch even reach this
// listener" independently of certificate trust.
type connCountListener struct {
	net.Listener
	conns *atomic.Int64
}

func (l *connCountListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.conns.Add(1)
	}
	return c, err
}

// TestStaticOIDC_DefaultClientIsSSRFSafe is the primary regression test for issue #117. A static
// provider (WithOIDC, HTTPClient nil, AllowInsecureURLs unset) whose discovery endpoint
// 302-redirects to a second loopback listener must fail closed: the default client is
// SafeHTTPClient, whose dial-time SSRF guard refuses the loopback connection outright and whose
// redirect policy never follows the 302. Before the fix the default was a plain client that
// connected to the listener (and would have followed the redirect had the TLS been trusted), so
// this test failed on both the error kind and the connection count.
func TestStaticOIDC_DefaultClientIsSSRFSafe(t *testing.T) {
	// Second loopback listener: the redirect target.
	redirectHits := &atomic.Int64{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectHits.Add(1)
		_, _ = io.WriteString(w, `{"keys":[]}`)
	}))
	t.Cleanup(target.Close)

	// First listener: TLS issuer/discovery endpoint, wrapped to count accepted connections.
	conns := &atomic.Int64{}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	srv := &httptest.Server{
		Listener: &connCountListener{Listener: l, conns: conns},
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The issue scenario: the discovery endpoint 302-redirects to the second listener.
			http.Redirect(w, r, target.URL+"/jwks", http.StatusFound)
		})},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	// Hostname (not a literal IP): the registration-time gate only blocks literal internal IPs,
	// so "localhost" reaches the fetch layer — where the dial guard is the authority.
	issuer := fmt.Sprintf("https://localhost:%d", port)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	v, err := newOIDCVerifier(OIDCConfig{
		Issuer:   issuer,
		Audience: "cid",
		// HTTPClient nil: the static path's default under test. AllowInsecureURLs unset:
		// secure-by-default.
	}, "cid")
	require.NoError(t, err)

	// verify triggers JWKS resolution → OIDC discovery fetch with the verifier's default client.
	token := signWithKey(t, key, "k1", baseIDClaims(issuer, "cid", "n"))
	_, err = v.verify(context.Background(), token, "n")
	require.Error(t, err, "the fetch must fail closed")
	// The SSRF dial guard refuses the loopback connection. Before the fix the error was a TLS
	// x509 error: the plain client had already dialed the listener.
	assert.ErrorIs(t, err, ErrIDTokenInvalid)
	assert.Contains(t, err.Error(), ErrBlockedAddress.Error(), "want the SSRF dial-guard error")
	assert.Zero(t, conns.Load(), "the SSRF-safe default client must not connect to the loopback issuer")
	assert.Zero(t, redirectHits.Load(), "the 302 redirect target must never be contacted")
}

// TestStaticOIDC_AllowInsecureURLs_DevPathStillWorks guards the documented dev opt-in: with
// AllowInsecureURLs=true and HTTPClient nil the plain client is kept, so a loopback http IdP
// (discovery + JWKS) stays reachable end to end. Must stay green across the fix.
func TestStaticOIDC_AllowInsecureURLs_DevPathStillWorks(t *testing.T) {
	d := newDiscoveryServer(t)
	iss := d.srv.URL

	v, err := newOIDCVerifier(OIDCConfig{
		Issuer:            iss,
		Audience:          "cid",
		AllowInsecureURLs: true,
		// HTTPClient nil: the dev path must still resolve loopback without an injected client.
	}, "cid")
	require.NoError(t, err)

	info, err := v.verify(context.Background(), d.signedToken(t, iss, "the-nonce"), "the-nonce")
	require.NoError(t, err)
	assert.Equal(t, "oidc-sub-1", info.ProviderID)
}

// TestStaticOIDC_FetchesReject3xxNotFollowed verifies (and pins) existing behaviour: the OIDC
// discovery and JWKS fetches reject 3xx responses instead of following them. The client under
// test carries the same CheckRedirect policy as SafeHTTPClient (ErrUseLastResponse); the fetch
// layers must treat the resulting 302 as a failure.
func TestStaticOIDC_FetchesReject3xxNotFollowed(t *testing.T) {
	targetHits := &atomic.Int64{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		_, _ = io.WriteString(w, `{"keys":[]}`)
	}))
	t.Cleanup(target.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/x", http.StatusFound)
	})
	mux.HandleFunc("/redirect-jwks", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/y", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	t.Run("discovery 302 rejected", func(t *testing.T) {
		_, err := discoverJWKSURL(context.Background(), client, srv.URL, true)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrIDTokenInvalid)
		assert.Contains(t, err.Error(), "status 302")
		assert.Zero(t, targetHits.Load(), "redirect must not be followed")
	})

	t.Run("jwks 302 rejected", func(t *testing.T) {
		c := &jwksCache{
			url:                srv.URL + "/redirect-jwks",
			issuer:             srv.URL,
			allowInsecure:      true,
			client:             client,
			ttl:                defaultJWKSCacheTTL,
			negativeTTL:        defaultNegativeTTL,
			minRefreshInterval: minRefreshInterval,
			now:                time.Now,
			negCache:           make(map[string]time.Time),
		}
		err := c.refresh(context.Background())
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrIDTokenInvalid)
		assert.Contains(t, err.Error(), "status 302")
		assert.Zero(t, targetHits.Load(), "redirect must not be followed")
	})
}
