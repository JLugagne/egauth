package outbound

import (
	"errors"
	"flag"
	"net/netip"
	"slices"
	"strconv"
)

var underTest = func() bool { return flag.Lookup("test.v") != nil }

// ErrInvalidAllowance is returned by NewAllowance, joined with one reason per rejected prefix.
var ErrInvalidAllowance = errors.New("outbound: invalid private-network allowance")

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("::ffff:0:0:0/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

var (
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour      = netip.MustParsePrefix("2002::/16")
	teredo         = netip.MustParsePrefix("2001::/32")
)

var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"),
	netip.MustParseAddr("169.254.170.2"),
	netip.MustParseAddr("100.100.100.200"),
	netip.MustParseAddr("168.63.129.16"),
	netip.MustParseAddr("192.0.0.192"),
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("fd20:ce::254"),
}

var loopbackPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

var neverAllowed = []struct {
	prefix netip.Prefix
	reason string
}{
	{netip.MustParsePrefix("169.254.0.0/16"), "overlaps IPv4 link-local"},
	{netip.MustParsePrefix("fe80::/10"), "overlaps IPv6 link-local"},
	{netip.MustParsePrefix("0.0.0.0/8"), "overlaps the unspecified IPv4 network"},
	{netip.MustParsePrefix("::/96"), "overlaps the unspecified or IPv4-compatible IPv6 range"},
	{netip.MustParsePrefix("::ffff:0:0/96"), "overlaps the IPv4-mapped IPv6 range"},
	{netip.MustParsePrefix("::ffff:0:0:0/96"), "overlaps the IPv4-translated IPv6 range"},
	{netip.MustParsePrefix("64:ff9b::/96"), "overlaps the NAT64 well-known prefix"},
	{netip.MustParsePrefix("64:ff9b:1::/48"), "overlaps the NAT64 local-use prefix"},
	{netip.MustParsePrefix("2002::/16"), "overlaps the 6to4 range"},
	{netip.MustParsePrefix("2001::/32"), "overlaps the Teredo range"},
	{netip.MustParsePrefix("224.0.0.0/4"), "overlaps IPv4 multicast"},
	{netip.MustParsePrefix("240.0.0.0/4"), "overlaps reserved IPv4 space"},
	{netip.MustParsePrefix("ff00::/8"), "overlaps IPv6 multicast"},
}

// Allowance is a validated list of private prefixes that outbound calls may reach. The zero value
// allows no private address. Values come only from NewAllowance, so an Allowance never covers a
// link-local or metadata address.
type Allowance struct {
	prefixes []netip.Prefix
}

// NewAllowance validates prefixes as DESIGN §6.2 requires. It rejects invalid, zoned or IPv4-mapped
// prefixes, IPv4 prefixes shorter than /8 and IPv6 prefixes shorter than /32, any prefix containing a
// cloud metadata address or overlapping link-local, unspecified, multicast, NAT64, 6to4, Teredo or
// IPv4-embedding IPv6 ranges, and loopback outside test binaries (binaries whose flag set holds the
// testing flags). Every rejected prefix is reported, joined with ErrInvalidAllowance.
func NewAllowance(prefixes []netip.Prefix) (Allowance, error) {
	var problems []error
	out := make([]netip.Prefix, 0, len(prefixes))
	for i, p := range prefixes {
		reason := prefixProblem(p)
		if reason != "" {
			problems = append(problems, errors.New("prefix "+strconv.Itoa(i)+" ("+p.String()+"): "+reason))
			continue
		}
		out = append(out, p.Masked())
	}
	if len(problems) > 0 {
		return Allowance{}, errors.Join(append([]error{ErrInvalidAllowance}, problems...)...)
	}
	return Allowance{prefixes: out}, nil
}

func prefixProblem(p netip.Prefix) string {
	if !p.IsValid() {
		return "invalid prefix"
	}
	addr := p.Addr()
	if addr.Zone() != "" {
		return "zoned prefix"
	}
	if addr.Is4In6() {
		return "IPv4-mapped prefix; use the IPv4 form"
	}
	p = p.Masked()
	if addr.Is4() && p.Bits() < 8 {
		return "IPv4 prefix shorter than /8"
	}
	if addr.Is6() && p.Bits() < 32 {
		return "IPv6 prefix shorter than /32"
	}
	for _, m := range metadataAddrs {
		if p.Contains(m) {
			return "contains the metadata address " + m.String()
		}
	}
	for _, l := range loopbackPrefixes {
		if !p.Overlaps(l) {
			continue
		}
		if !underTest() {
			return "overlaps loopback"
		}
		if l.Bits() <= p.Bits() {
			return ""
		}
	}
	for _, n := range neverAllowed {
		if p.Overlaps(n.prefix) {
			return n.reason
		}
	}
	return ""
}

// Prefixes returns a copy of the allowed prefixes, masked.
func (a Allowance) Prefixes() []netip.Prefix {
	return slices.Clone(a.prefixes)
}

// Permits reports whether the dial guard lets a connection to addr through under a. Public unicast
// addresses are permitted; private, loopback, link-local, unspecified, multicast and reserved
// addresses only when a prefix of a covers them; metadata addresses never. IPv4-mapped, NAT64
// well-known and 6to4 addresses are judged by the IPv4 address they carry, Teredo addresses by both
// their server and client IPv4 addresses.
func (a Allowance) Permits(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, e := range judgedAddrs(addr) {
		if slices.Contains(metadataAddrs, e) || (isBlocked(e) && !a.covers(e)) {
			return false
		}
	}
	return true
}

func (a Allowance) covers(addr netip.Addr) bool {
	for _, p := range a.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (a Allowance) coversAll(addr netip.Addr) bool {
	for _, e := range judgedAddrs(addr) {
		if !a.covers(e) {
			return false
		}
	}
	return true
}

func judgedAddrs(addr netip.Addr) []netip.Addr {
	addr = addr.WithZone("").Unmap()
	b := addr.As16()
	switch {
	case nat64WellKnown.Contains(addr):
		return []netip.Addr{netip.AddrFrom4([4]byte(b[12:16]))}
	case sixToFour.Contains(addr):
		return []netip.Addr{netip.AddrFrom4([4]byte(b[2:6]))}
	case teredo.Contains(addr):
		return []netip.Addr{
			netip.AddrFrom4([4]byte(b[4:8])),
			netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]}),
		}
	}
	return []netip.Addr{addr}
}

func isBlocked(addr netip.Addr) bool {
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
