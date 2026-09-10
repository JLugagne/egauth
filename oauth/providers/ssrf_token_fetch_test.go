package providers_test

// Regression tests for the provider's own outbound fetches: the token exchange that carries the
// client_secret and the userinfo GET that carries the provider access token must use the
// SSRF-hardened client by default, so a hostile or tenant-controlled issuer whose https hostname
// resolves to an internal address never receives the secret or a bearer token. The plain client
// remains reachable only through the explicit oauth.WithInsecureURLs dev opt-in or an injected
// oauth.WithHTTPClient.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/oauth"
	"github.com/JLugagne/egauth/oauth/providers"
)

func localhostCertPEM(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
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
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestOIDC_TokenAndUserinfoFetchesUseSSRFGuard: an issuer serving a discovery document that points
// its token and userinfo endpoints at an https hostname resolving to loopback must not receive the
// client_secret or a provider access token. The discovery leg is injected so the loopback
// stand-in is reachable; the provider's own token/userinfo fetches stay on the default client,
// whose dial-time guard must refuse the internal address.
func TestOIDC_TokenAndUserinfoFetchesUseSSRFGuard(t *testing.T) {
	cert, certPEM := localhostCertPEM(t)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatalf("writing ca file: %v", err)
	}
	// Make a plain (unguarded) http.Client trust the loopback test server, standing in for an
	// attacker-controlled issuer whose certificate is valid for a hostname that resolves to an
	// internal address. A safe client never gets far enough to use it.
	t.Setenv("SSL_CERT_FILE", caFile)
	t.Setenv("SSL_CERT_DIR", t.TempDir())

	const secret = "super-secret-client-secret"
	var tokenHits, userinfoHits atomic.Int64
	var mu sync.Mutex
	var leakedSecret, leakedBearer string

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	issuer := fmt.Sprintf("https://localhost:%d", port)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"userinfo_endpoint":      issuer + "/userinfo",
			"jwks_uri":               issuer + "/jwks",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenHits.Add(1)
		_ = r.ParseForm()
		mu.Lock()
		leakedSecret = r.PostForm.Get("client_secret")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"provider-access-token","token_type":"Bearer"}`)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		userinfoHits.Add(1)
		mu.Lock()
		leakedBearer = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"sub":"attacker-sub","email":"attacker@example.com","email_verified":true}`)
	})
	srv := &httptest.Server{
		Listener: l,
		Config:   &http.Server{Handler: mux},
		TLS:      &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// Discovery is injected (a documented test seam): the issuer itself is a routable public
	// server in the real attack, so the safe client would reach it. The injection only substitutes
	// reachability for this test; it does not touch the provider's own client.
	p := providers.OIDC(context.Background(), issuer, "client-id", secret, nil,
		providers.WithDiscoveryHTTPClient(srv.Client()),
	)
	if p == nil {
		t.Fatal("providers.OIDC returned nil")
	}

	// CONTROL: the SSRF-hardened client refuses to dial the same loopback URL.
	safeReq, err := http.NewRequest(http.MethodPost, issuer+"/token", strings.NewReader(""))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	safeResp, safeErr := oauth.SafeHTTPClient().Do(safeReq)
	if safeErr == nil {
		_ = safeResp.Body.Close()
		t.Fatalf("control failed: oauth.SafeHTTPClient reached %s, want ErrBlockedAddress", issuer)
	}
	if !strings.Contains(safeErr.Error(), oauth.ErrBlockedAddress.Error()) {
		t.Fatalf("control failed: SafeHTTPClient error = %v, want wrapped ErrBlockedAddress", safeErr)
	}

	// The provider's default client must refuse the internal endpoint as well: Exchange fails at
	// the token POST and the internal server never receives the client_secret.
	if _, err := p.Exchange(context.Background(), "attacker-code", "https://app.example.com/cb", ""); err == nil {
		t.Errorf("Exchange reached %s; want the SSRF dial guard to refuse it", issuer)
	}

	mu.Lock()
	gotSecret, gotBearer := leakedSecret, leakedBearer
	mu.Unlock()

	if got := tokenHits.Load(); got != 0 {
		t.Errorf("the token exchange reached the internal loopback token endpoint (%d request(s)); client_secret %q was sent there", got, gotSecret)
	}
	if got := userinfoHits.Load(); got != 0 {
		t.Errorf("the userinfo fetch reached the internal loopback endpoint (%d request(s)); Authorization %q was sent there", got, gotBearer)
	}
	if gotSecret == secret {
		t.Errorf("client_secret reached the internal token endpoint verbatim")
	}
}

// TestOIDC_ExplicitHTTPClientBypassesSSRFGuard guards the documented escape hatch: an explicitly
// injected oauth.WithHTTPClient is used for the token and userinfo fetches even though the default
// would be oauth.SafeHTTPClient, so a loopback dev IdP (or a custom transport) keeps working.
func TestOIDC_ExplicitHTTPClientBypassesSSRFGuard(t *testing.T) {
	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fmt.Sprintf(
			`{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"userinfo_endpoint":%q}`,
			issuer, issuer+"/auth", issuer+"/token", issuer+"/userinfo"))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if got := r.PostFormValue("client_secret"); got != "client-secret" {
			t.Errorf("token endpoint client_secret = %q, want %q", got, "client-secret")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"provider-access-token","token_type":"Bearer"}`)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer provider-access-token" {
			t.Errorf("userinfo Authorization = %q, want %q", got, "Bearer provider-access-token")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"sub":"dev-sub","email":"dev@example.com","email_verified":true}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL

	p := providers.OIDC(context.Background(), issuer, "client-id", "client-secret",
		[]oauth.ProviderOption{
			oauth.WithInsecureURLs(),
			oauth.WithHTTPClient(srv.Client()),
		},
		providers.WithDiscoveryHTTPClient(srv.Client()),
		providers.WithInsecureDiscoveryURLs(),
	)
	info, err := p.Exchange(context.Background(), "code", "https://app.example.com/cb", "")
	if err != nil {
		t.Fatalf("Exchange with an injected client returned %v", err)
	}
	if info.ProviderID != "dev-sub" || info.Email != "dev@example.com" {
		t.Errorf("UserInfo = %+v, want the userinfo response from the injected client", info)
	}
}

// TestKeycloak_LoopbackBaseURLBlockedByDefault covers the caller-supplied base URL constructors: a
// Keycloak https base URL whose hostname resolves to loopback must not receive the client_secret
// on the token POST under the default client, while the explicit opt-in (oauth.WithInsecureURLs /
// oauth.WithHTTPClient) keeps the local-dev escape hatch working.
func TestKeycloak_LoopbackBaseURLBlockedByDefault(t *testing.T) {
	cert, certPEM := localhostCertPEM(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatalf("writing ca file: %v", err)
	}
	// Stand in for a public CA certificate valid for a hostname that resolves to an internal
	// address: the plain client would trust and dial the loopback server; the SSRF guard refuses.
	t.Setenv("SSL_CERT_FILE", caFile)
	t.Setenv("SSL_CERT_DIR", t.TempDir())

	var tokenHits atomic.Int64

	mux := http.NewServeMux()
	mux.HandleFunc("/realms/dev/protocol/openid-connect/token", func(w http.ResponseWriter, _ *http.Request) {
		tokenHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"provider-access-token","token_type":"Bearer"}`)
	})
	mux.HandleFunc("/realms/dev/protocol/openid-connect/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"sub":"kc-sub","email":"dev@example.com","email_verified":true}`)
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	base := fmt.Sprintf("https://localhost:%d", l.Addr().(*net.TCPAddr).Port)
	srv := &httptest.Server{
		Listener: l,
		Config:   &http.Server{Handler: mux},
		TLS:      &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// Default: the SSRF dial guard refuses the internal token endpoint before it is reached.
	p := providers.Keycloak(base, "dev", "client-id", "client-secret")
	if _, err := p.Exchange(context.Background(), "code", "https://app.example.com/cb", ""); err == nil {
		t.Errorf("Exchange reached the internal Keycloak endpoint %s; want the SSRF dial guard to refuse it", base)
	}
	if got := tokenHits.Load(); got != 0 {
		t.Errorf("the token exchange reached the internal Keycloak token endpoint %d time(s)", got)
	}

	// Explicit opt-in: the supplied client performs both the token POST and the userinfo GET.
	p = providers.Keycloak(base, "dev", "client-id", "client-secret",
		oauth.WithInsecureURLs(), oauth.WithHTTPClient(srv.Client()))
	info, err := p.Exchange(context.Background(), "code", "https://app.example.com/cb", "")
	if err != nil {
		t.Fatalf("Exchange with the opt-in client returned %v", err)
	}
	if info.ProviderID != "kc-sub" || info.Email != "dev@example.com" {
		t.Errorf("UserInfo = %+v, want the userinfo response", info)
	}
}
