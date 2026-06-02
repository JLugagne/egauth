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
