package oauth

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	cases := []struct {
		name    string
		ip      string
		blocked bool
	}{
		{"ipv4 loopback", "127.0.0.1", true},
		{"ipv4 loopback range", "127.5.6.7", true},
		{"ipv6 loopback", "::1", true},
		{"cloud metadata", "169.254.169.254", true},
		{"ipv4 link-local", "169.254.0.1", true},
		{"ipv6 link-local", "fe80::1", true},
		{"unique-local ipv6", "fc00::1", true},
		{"unique-local ipv6 fd", "fd12:3456::1", true},
		{"rfc1918 10/8", "10.0.0.1", true},
		{"rfc1918 172.16/12", "172.16.5.4", true},
		{"rfc1918 172.31", "172.31.255.255", true},
		{"rfc1918 192.168/16", "192.168.1.1", true},
		{"cgnat 100.64/10", "100.64.1.1", true},
		{"unspecified ipv4", "0.0.0.0", true},
		{"unspecified ipv6", "::", true},
		{"multicast ipv4", "224.0.0.1", true},
		{"public dns", "8.8.8.8", false},
		{"public cloudflare", "1.1.1.1", false},
		{"public ipv6", "2606:4700:4700::1111", false},
		{"just-outside 172.32", "172.32.0.1", false},
		{"just-outside 100.128", "100.128.0.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("could not parse %q", tc.ip)
			}
			if got := isBlockedIP(ip); got != tc.blocked {
				t.Fatalf("isBlockedIP(%s) = %v, want %v", tc.ip, got, tc.blocked)
			}
		})
	}
}

func TestIsBlockedIPNil(t *testing.T) {
	if !isBlockedIP(nil) {
		t.Fatal("isBlockedIP(nil) should be blocked (fail closed)")
	}
}

func TestSafeDialControlBlocksInternal(t *testing.T) {
	blocked := []string{
		"127.0.0.1:80",
		"[::1]:443",
		"169.254.169.254:80",
		"10.0.0.1:443",
		"192.168.1.1:80",
		"[fc00::1]:443",
	}
	for _, addr := range blocked {
		t.Run(addr, func(t *testing.T) {
			err := safeDialControl("tcp", addr, nil)
			if err == nil {
				t.Fatalf("safeDialControl(tcp, %s) = nil, want blocked error", addr)
			}
			if !errors.Is(err, ErrBlockedAddress) {
				t.Fatalf("error = %v, want wrapped ErrBlockedAddress", err)
			}
		})
	}
}

func TestSafeDialControlAllowsPublic(t *testing.T) {
	if err := safeDialControl("tcp", "8.8.8.8:443", nil); err != nil {
		t.Fatalf("safeDialControl(tcp, 8.8.8.8:443) = %v, want nil", err)
	}
}

func TestSafeDialControlRejectsNonTCP(t *testing.T) {
	if err := safeDialControl("udp", "8.8.8.8:53", nil); err == nil {
		t.Fatal("safeDialControl should reject non-tcp networks")
	}
}

func TestValidateExternalURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid https", "https://sso.example.com/jwks", false},
		{"valid https with port", "https://sso.example.com:8443/token", false},
		{"empty", "", true},
		{"http scheme", "http://sso.example.com/jwks", true},
		{"loopback literal http", "http://127.0.0.1/jwks", true},
		{"loopback literal https", "https://127.0.0.1/jwks", true},
		{"metadata literal https", "https://169.254.169.254/", true},
		{"rfc1918 literal https", "https://10.0.0.1/jwks", true},
		{"ipv6 loopback https", "https://[::1]/jwks", true},
		{"no host", "https:///jwks", true},
		{"ftp scheme", "ftp://sso.example.com/x", true},
		{"missing scheme", "sso.example.com/jwks", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateExternalURL(tc.url)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateExternalURL(%q) = nil, want error", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateExternalURL(%q) = %v, want nil", tc.url, err)
			}
			if tc.wantErr && err != nil && !errors.Is(err, ErrBlockedURL) {
				t.Fatalf("ValidateExternalURL(%q) error = %v, want wrapped ErrBlockedURL", tc.url, err)
			}
		})
	}
}

func TestSafeHTTPClientRefusesLoopbackServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := SafeHTTPClient()
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("SafeHTTPClient connected to loopback test server %s, want dial error", srv.URL)
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("error = %v, want wrapped ErrBlockedAddress", err)
	}
}

// TestSafeHTTPClientIgnoresEnvProxy proves the dial-time IP guard inspects the RESOLVED TARGET
// even when HTTP(S)_PROXY is set in the environment. If the safe client honored the env proxy, the
// dial would target the (bogus) proxy host instead of the loopback test server, so the request
// would fail with a proxy dial error rather than the internal-IP SSRF block. Asserting that the
// error wraps ErrBlockedAddress confirms env proxies are not trusted (Proxy: nil).
func TestSafeHTTPClientIgnoresEnvProxy(t *testing.T) {
	// A proxy that, if honored, would intercept the dial before the target IP is ever evaluated.
	t.Setenv("HTTP_PROXY", "http://some-proxy.invalid:3128")
	t.Setenv("HTTPS_PROXY", "http://some-proxy.invalid:3128")
	t.Setenv("http_proxy", "http://some-proxy.invalid:3128")
	t.Setenv("https_proxy", "http://some-proxy.invalid:3128")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := SafeHTTPClient()
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("SafeHTTPClient reached loopback target %s with env proxy set, want SSRF block", srv.URL)
	}
	// The error must be the dial-time internal-IP block (inspecting the resolved 127.0.0.1
	// target), NOT a failed dial to the bogus proxy host.
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("error = %v, want wrapped ErrBlockedAddress (dial-time IP guard, env proxy ignored)", err)
	}
}
