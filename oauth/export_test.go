package oauth

import "net"

// IsBlockedIPForTest exposes the library's own address classification so the tests in the external
// test package can assert the decision table directly instead of inferring it from a dial failure.
func IsBlockedIPForTest(ip net.IP) bool { return isBlockedIP(ip) }
