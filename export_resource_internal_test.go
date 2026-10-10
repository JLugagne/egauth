package egauth

import (
	"net/netip"

	"github.com/JLugagne/egauth/internal/configcheck"
	"github.com/JLugagne/egauth/internal/outbound"
)

func NewLoopbackResourceServer[C any](cfg ResourceConfig, clk TestClock) (*ResourceServer[C], error) {
	allow, err := outbound.NewAllowance([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	if err != nil {
		return nil, err
	}
	return newResourceServer[C](cfg, rsSeams{clock: clk, private: allow})
}

func ResolveResource(cfg ResourceConfig) (*configcheck.Resolved, []*configcheck.Error) {
	return configcheck.Validate(&cfg, resourceOptions())
}

func ResourceOptions() configcheck.Options { return resourceOptions() }
