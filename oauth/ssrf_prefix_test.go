package oauth_test

import (
	"net"
	"net/http"
	"testing"

	"github.com/JLugagne/egauth/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateExternalURL_BlocksEmbeddedIPv4Forms pins the classifier against IPv4 addresses
// written in an IPv6 layout other than the mapped form. net.IP's IsLoopback/IsPrivate/... helpers
// normalise only ::ffff:a.b.c.d (via To4), so IPv4-COMPATIBLE, IPv4-TRANSLATED and RFC 6052 NAT64
// literals used to be reported as public — and the NAT64 form is translated back to the embedded
// IPv4 by a NAT64/DNS64 network, which is exactly where the cloud metadata endpoint is reachable.
func TestValidateExternalURL_BlocksEmbeddedIPv4Forms(t *testing.T) {
	for _, tc := range []struct {
		url string
		why string
	}{
		{"https://[::ffff:127.0.0.1]/", "IPv4-mapped loopback"},
		{"https://[::ffff:169.254.169.254]/", "IPv4-mapped link-local metadata"},
		{"https://[::7f00:1]/", "IPv4-compatible loopback"},
		{"https://[::ffff:0:7f00:1]/", "IPv4-translated (SIIT) loopback"},
		{"https://[64:ff9b::7f00:1]/", "NAT64-embedded loopback"},
		{"https://[64:ff9b::a9fe:a9fe]/latest/meta-data/", "NAT64-embedded metadata endpoint"},
		{"https://[64:ff9b::a00:1]/", "NAT64-embedded RFC1918"},
		{"https://[64:ff9b::c0a8:101]/", "NAT64-embedded RFC1918"},
		{"https://[::ffff:0:169.254.169.254]/", "IPv4-translated metadata"},
		{"https://[fd00::1]/", "unique-local"},
		{"https://[fe80::1]/", "link-local"},
		{"https://[::1]/", "IPv6 loopback"},
		{"https://[::]/", "unspecified"},
		{"https://0.0.0.1/", "0.0.0.0/8"},
		{"https://169.254.169.254/", "link-local metadata"},
		{"https://127.0.0.1/", "loopback"},
		{"https://10.1.2.3/", "RFC1918"},
		{"https://192.168.1.1/", "RFC1918"},
		{"https://172.20.0.1/", "RFC1918"},
		{"https://100.100.100.200/", "CGNAT (Alibaba metadata)"},
		{"https://[2001:db8::1]/", "documentation range"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			assert.ErrorIs(t, oauth.ValidateExternalURL(tc.url), oauth.ErrBlockedURL,
				"%s must be refused", tc.why)
		})
	}
}

// TestValidateExternalURL_AllowsPublicAddresses is the control: the stricter classifier must not
// refuse addresses a deployment legitimately fetches.
func TestValidateExternalURL_AllowsPublicAddresses(t *testing.T) {
	for _, u := range []string{
		"https://8.8.8.8/",
		"https://[2606:4700:4700::1111]/",
		"https://accounts.google.com/.well-known/openid-configuration",
		"https://login.microsoftonline.com/common/v2.0",
	} {
		assert.NoError(t, oauth.ValidateExternalURL(u), "%s should be allowed", u)
	}
}

// TestSafeHTTPClient_RefusesEmbeddedIPv4Loopback exercises the dial-time guard (not just the
// registration-time one) against the same literal forms. The dial guard is the authoritative
// protection because it sees the resolved address, so it must classify these too.
func TestSafeHTTPClient_RefusesEmbeddedIPv4Loopback(t *testing.T) {
	client := oauth.SafeHTTPClient()
	require.NotNil(t, client)

	// isBlockedIP is unexported; drive it through the transport's dial guard by asking the client
	// to connect. Nothing is listening on these addresses, so a reached connection is impossible —
	// the assertion is that the failure is the guard's, not a route or connection error.
	for _, host := range []string{"[::7f00:1]", "[64:ff9b::7f00:1]", "[64:ff9b::a9fe:a9fe]"} {
		req, err := http.NewRequest(http.MethodGet, "http://"+host+":9/", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		require.Error(t, err, "%s must not be reachable", host)
		assert.Contains(t, err.Error(), "blocked address",
			"the dial guard must refuse %s by policy, not by routing", host)
	}
}

// TestIsBlockedIP_ClassificationMatrix documents the classifier's decisions directly, so a future
// refactor that reintroduces a net.IP helper has to confront the table.
func TestIsBlockedIP_ClassificationMatrix(t *testing.T) {
	blocked := []string{
		"0.0.0.0", "0.0.0.1", "127.0.0.1", "127.1.2.3", "10.0.0.1", "172.16.0.1", "172.31.255.255",
		"192.168.0.1", "169.254.169.254", "100.64.0.1", "198.18.0.1", "224.0.0.1", "255.255.255.255",
		"::", "::1", "::ffff:127.0.0.1", "::ffff:0:127.0.0.1", "::7f00:1",
		"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::a00:1", "64:ff9b:1::1",
		"fc00::1", "fd00::1", "fe80::1", "ff02::1", "2001:db8::1", "100::1",
	}
	for _, raw := range blocked {
		ip := net.ParseIP(raw)
		require.NotNil(t, ip, "test data %q must parse", raw)
		assert.True(t, oauth.IsBlockedIPForTest(ip), "%s must be blocked", raw)
	}

	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111", "2001:4860:4860::8888"}
	for _, raw := range allowed {
		ip := net.ParseIP(raw)
		require.NotNil(t, ip)
		assert.False(t, oauth.IsBlockedIPForTest(ip), "%s must be allowed", raw)
	}
}
