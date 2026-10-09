package egauth

import (
	"crypto/x509"

	"github.com/JLugagne/egauth/internal/clock"
)

type seams struct {
	clock   clock.Clock
	rootCAs *x509.CertPool
}

// TestSeams replaces what a journey test cannot otherwise drive: the clock every component of the
// Auth reads, and the roots its outbound client trusts. The zero value keeps the wall clock and the
// system roots.
type TestSeams struct {
	Clock   TestClock
	RootCAs *x509.CertPool
}

// TestHookNew is New with seams. Like every TestHook it returns an error unless called from
// package egauthtest. The outbound SSRF guard stays in force: reaching a loopback provider still
// needs Insecure.OutboundPrivateNetwork.
func TestHookNew[C any](cfg Config[C], s TestSeams) (*Auth[C], error) {
	if !calledByEgauthtest() {
		return nil, errHookCaller
	}
	return newWith(cfg, seams{clock: s.Clock, rootCAs: s.RootCAs})
}
