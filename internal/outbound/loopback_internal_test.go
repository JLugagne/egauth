package outbound

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoopbackAllowanceIsRejectedOutsideTests(t *testing.T) {
	saved := underTest
	underTest = func() bool { return false }
	defer func() { underTest = saved }()

	for _, raw := range []string{"127.0.0.0/8", "127.0.0.1/32", "::1/128"} {
		_, err := NewAllowance([]netip.Prefix{netip.MustParsePrefix(raw)})
		require.ErrorIs(t, err, ErrInvalidAllowance, raw)
	}
	_, err := NewAllowance([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	require.NoError(t, err)
}
