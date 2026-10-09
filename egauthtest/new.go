package egauthtest

import (
	"crypto/x509"

	"github.com/JLugagne/egauth"
)

// New is egauth.New for a journey: every component of the Auth reads clk instead of the wall clock,
// which must be the clock the storage was built with (memstore.NewWithClock), and its outbound client
// trusts the certificate of idp. Either may be nil to keep the wall clock or the system roots. The
// SSRF dial guard stays in force, so a loopback provider still needs
// Insecure.OutboundPrivateNetwork in cfg.
func New[C any](cfg egauth.Config[C], clk *Clock, idp *IdP) (*egauth.Auth[C], error) {
	var s egauth.TestSeams
	if clk != nil {
		s.Clock = clk.Library()
	}
	if idp != nil {
		s.RootCAs = x509.NewCertPool()
		s.RootCAs.AddCert(idp.server.Certificate())
	}
	return egauth.TestHookNew(cfg, s)
}
