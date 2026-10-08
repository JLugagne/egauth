package outbound_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/outbound"
)

func prefixes(t *testing.T, raw ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(raw))
	for _, r := range raw {
		out = append(out, netip.MustParsePrefix(r))
	}
	return out
}

func TestNewAllowanceRejectsDangerousPrefixes(t *testing.T) {
	cases := map[string]string{
		"ipv4 link-local":              "169.254.0.0/16",
		"ipv4 link-local subnet":       "169.254.169.0/24",
		"ipv6 link-local":              "fe80::/10",
		"ipv6 link-local subnet":       "fe80::/64",
		"ipv4 everything":              "0.0.0.0/0",
		"ipv4 shorter than /8":         "10.0.0.0/7",
		"ipv6 everything":              "::/0",
		"ipv6 shorter than /32":        "fd00::/31",
		"cgnat holds alibaba metadata": "100.64.0.0/10",
		"alibaba metadata host":        "100.100.100.200/32",
		"aws ipv6 metadata":            "fd00:ec2::/32",
		"azure wireserver":             "168.63.129.16/32",
		"ipv4 unspecified":             "0.0.0.0/8",
		"ipv6 unspecified":             "::/128",
		"ipv4 multicast":               "224.0.0.0/8",
		"ipv6 multicast":               "ff02::/32",
		"ipv4 mapped":                  "::ffff:10.0.0.0/104",
		"nat64":                        "64:ff9b::/96",
		"ipv4 compatible":              "::a00:0/104",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := outbound.NewAllowance(prefixes(t, raw))
			require.ErrorIs(t, err, outbound.ErrInvalidAllowance)
		})
	}
}

func TestNewAllowanceRejectsZeroPrefix(t *testing.T) {
	_, err := outbound.NewAllowance([]netip.Prefix{{}})
	require.ErrorIs(t, err, outbound.ErrInvalidAllowance)
}

func TestNewAllowanceReportsEveryBadPrefix(t *testing.T) {
	_, err := outbound.NewAllowance(prefixes(t, "10.0.0.0/8", "169.254.0.0/16", "fe80::/10"))
	require.ErrorIs(t, err, outbound.ErrInvalidAllowance)
	require.ErrorContains(t, err, "prefix 1")
	require.ErrorContains(t, err, "prefix 2")
	require.NotContains(t, err.Error(), "prefix 0")
}

func TestNewAllowanceAcceptsPrivatePrefixes(t *testing.T) {
	a, err := outbound.NewAllowance(prefixes(t, "10.0.0.0/8", "192.168.1.0/24", "fd12:3456::/32", "172.16.0.0/12"))
	require.NoError(t, err)
	require.Len(t, a.Prefixes(), 4)
}

func TestNewAllowanceMasksPrefixes(t *testing.T) {
	a, err := outbound.NewAllowance(prefixes(t, "10.1.2.3/8"))
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), a.Prefixes()[0])
}

func TestAllowancePrefixesReturnsACopy(t *testing.T) {
	a, err := outbound.NewAllowance(prefixes(t, "10.0.0.0/8"))
	require.NoError(t, err)
	p := a.Prefixes()
	p[0] = netip.MustParsePrefix("169.254.0.0/16")
	require.False(t, a.Permits(netip.MustParseAddr("169.254.169.254")))
}

func TestLoopbackAllowanceIsAcceptedUnderTest(t *testing.T) {
	a, err := outbound.NewAllowance(prefixes(t, "127.0.0.0/8", "::1/128"))
	require.NoError(t, err)
	require.True(t, a.Permits(netip.MustParseAddr("127.0.0.1")))
	require.True(t, a.Permits(netip.MustParseAddr("::1")))
}

func TestZeroAllowancePermitsOnlyPublicUnicast(t *testing.T) {
	var a outbound.Allowance
	denied := []string{
		"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "100.64.0.1",
		"169.254.169.254", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "64:ff9b:1::a9fe:a9fe",
		"::a9fe:a9fe", "::ffff:0:a9fe:a9fe", "0.0.0.0", "::", "fd00:ec2::254", "fd20:ce::254",
		"100.100.100.200", "168.63.129.16", "fe80::1", "224.0.0.1", "ff02::1", "fc00::1",
		"255.255.255.255", "192.0.0.192", "198.18.0.1", "2001:db8::1",
	}
	for _, s := range denied {
		require.False(t, a.Permits(netip.MustParseAddr(s)), s)
	}
	allowed := []string{"93.184.216.34", "8.8.8.8", "2606:4700:4700::1111", "64:ff9b::808:808"}
	for _, s := range allowed {
		require.True(t, a.Permits(netip.MustParseAddr(s)), s)
	}
	require.False(t, a.Permits(netip.Addr{}))
}

func TestAllowanceOpensOnlyItsPrefixes(t *testing.T) {
	a, err := outbound.NewAllowance(prefixes(t, "10.0.0.0/8"))
	require.NoError(t, err)
	require.True(t, a.Permits(netip.MustParseAddr("10.1.2.3")))
	require.True(t, a.Permits(netip.MustParseAddr("::ffff:10.1.2.3")))
	require.False(t, a.Permits(netip.MustParseAddr("192.168.0.1")))
	require.False(t, a.Permits(netip.MustParseAddr("127.0.0.1")))
	require.False(t, a.Permits(netip.MustParseAddr("169.254.169.254")))
}
