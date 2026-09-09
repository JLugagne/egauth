package providers

// Regression tests for issue #117: the static generic-OIDC constructor path. The default
// discovery client must be the SSRF-safe client (dial-time guard, no redirect following) with the
// plain client reserved for the WithInsecureDiscoveryURLs dev opt-in, and the endpoints resolved
// from the discovery document must pass the https/SSRF gate before they are used.
import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/oauth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// providerConnCountListener counts accepted connections at the socket level, mirroring
// oauth/ssrf_static_regression_test.go. A dial is counted even when the subsequent TLS handshake
// fails client-side, so it observes "did the discovery fetch even reach this listener"
// independently of certificate trust.
type providerConnCountListener struct {
	net.Listener
	conns *atomic.Int64
}

func (l *providerConnCountListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.conns.Add(1)
	}
	return c, err
}

// newLocalhostCert builds a self-signed certificate valid for the "localhost" DNS name and the
// 127.0.0.1 loopback IP, so an https issuer can be addressed as https://localhost:<port> — a
// hostname (which passes the registration-time literal-IP gate) resolving to a loopback address.
func newLocalhostCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newTLSIssuerServer starts an https test double on 127.0.0.1 whose certificate is valid for the
// "localhost" hostname and whose listener counts accepted connections. doc is called with the
// issuer URL (https://localhost:<port>) and must render the response body. The returned client
// trusts the server's certificate, letting tests inject it to reach the loopback issuer past the
// dial-time guard and isolate the URL-validation layer.
func newTLSIssuerServer(t *testing.T, doc func(issuer string) string) (issuer string, conns *atomic.Int64, client *http.Client) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	conns = &atomic.Int64{}
	srv := &httptest.Server{
		Listener: &providerConnCountListener{Listener: l, conns: conns},
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, doc(fmt.Sprintf("https://localhost:%d", port)))
		})},
		TLS: &tls.Config{Certificates: []tls.Certificate{newLocalhostCert(t)}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return fmt.Sprintf("https://localhost:%d", port), conns, srv.Client()
}

// discoveryDoc renders an OIDC discovery document for the given issuer. Empty endpoints are
// omitted from the JSON so their absence matches the spec's optionality.
func discoveryDoc(issuer, auth, token, userinfo string) string {
	doc := map[string]any{"issuer": issuer}
	if auth != "" {
		doc["authorization_endpoint"] = auth
	}
	if token != "" {
		doc["token_endpoint"] = token
	}
	if userinfo != "" {
		doc["userinfo_endpoint"] = userinfo
	}
	b, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// TestFetchOIDCDiscovery_ValidatesDiscoveredEndpoints: endpoints resolved from the discovery
// document are fetched server-side later (auth redirect, token POST carrying the client secret,
// userinfo GET carrying the access token), so each must pass the same https/SSRF gate as the
// issuer before use. Before the fix only the issuer itself was validated, so an internal or
// non-https userinfo_endpoint was accepted (the failing cases).
func TestFetchOIDCDiscovery_ValidatesDiscoveredEndpoints(t *testing.T) {
	cases := []struct {
		name        string
		auth, token string
		userinfo    string
		wantErr     bool
	}{
		{"https external endpoints accepted", "https://idp.example.com/auth", "https://idp.example.com/token", "https://idp.example.com/userinfo", false},
		{"internal userinfo literal rejected", "https://idp.example.com/auth", "https://idp.example.com/token", "http://169.254.169.254/userinfo", true},
		{"rfc1918 token endpoint rejected", "https://idp.example.com/auth", "https://10.0.0.7/token", "https://idp.example.com/userinfo", true},
		{"omitted userinfo accepted (spec-optional)", "https://idp.example.com/auth", "https://idp.example.com/token", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issuer, _, client := newTLSIssuerServer(t, func(iss string) string {
				return discoveryDoc(iss, tc.auth, tc.token, tc.userinfo)
			})
			_, err := fetchOIDCDiscovery(context.Background(), client, issuer, false)
			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, oauth.ErrBlockedURL)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestOIDC_DiscoveryDefaultClientIsSSRFSafe: with no WithDiscoveryHTTPClient override and no
// insecure opt-in, the discovery client must default to oauth.SafeHTTPClient, whose dial-time
// guard refuses the loopback issuer outright. Before the fix the default was a plain client that
// connected to the listener (failing only at the TLS layer afterwards).
func TestOIDC_DiscoveryDefaultClientIsSSRFSafe(t *testing.T) {
	issuer, conns, _ := newTLSIssuerServer(t, func(iss string) string {
		return discoveryDoc(iss, "https://idp.example.com/auth", "https://idp.example.com/token", "https://idp.example.com/userinfo")
	})
	p := OIDC(context.Background(), issuer, "cid", "secret", nil)
	require.NotNil(t, p)
	assert.Zero(t, conns.Load(), "the default discovery client must not connect to a loopback issuer")
	// A failed discovery must fail closed: the deferred error surfaces on first use.
	_, err := p.Exchange(context.Background(), "code", "https://app/cb", "verifier")
	require.Error(t, err)
}

// TestOIDC_InsecureDiscoveryDefaultClient_ReachesLoopbackDevIdP guards the documented dev opt-in
// end to end: with WithInsecureDiscoveryURLs (and AllowInsecureURLs on the OIDCConfig) the plain
// default clients are kept at every layer, so a loopback http IdP stays reachable and a full
// exchange — token POST, OIDC discovery, JWKS fetch, id_token validation — succeeds. Must stay
// green across the fix.
func TestOIDC_InsecureDiscoveryDefaultClient_ReachesLoopbackDevIdP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer := srv.URL

	now := float64(time.Now().Unix())
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuer, "aud": "cid", "sub": "oidc-sub-1",
		"email": "dev@example.com", "exp": now + 3600, "iat": now, "nonce": "n",
	})
	tok.Header["kid"] = "k1"
	idToken, err := tok.SignedString(key)
	require.NoError(t, err)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fmt.Sprintf(
			`{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"userinfo_endpoint":%q,"jwks_uri":%q}`,
			issuer, issuer+"/auth", issuer+"/token", issuer+"/userinfo", issuer+"/jwks"))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fmt.Sprintf(`{"access_token":"at","id_token":%q}`, idToken))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"keys":[{"kty":"RSA","kid":"k1","use":"sig","alg":"RS256","n":%q,"e":%q}]}`,
			base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()))
	})

	p := OIDC(context.Background(), issuer, "cid", "secret",
		[]oauth.ProviderOption{
			oauth.WithOIDC(oauth.OIDCConfig{Issuer: issuer, AllowInsecureURLs: true}),
			oauth.WithInsecureURLs(),
		},
		WithInsecureDiscoveryURLs(),
		// No WithDiscoveryHTTPClient: the dev default (plain) clients are under test at every
		// layer — discovery fetch, token exchange, verifier-side discovery and JWKS fetch.
	)
	info, err := p.Exchange(context.Background(), "code", "https://app/cb", "", oauth.WithExpectedNonce("n"))
	require.NoError(t, err)
	assert.Equal(t, "oidc-sub-1", info.ProviderID)
	assert.Equal(t, "dev@example.com", info.Email)
}
