package outbound_test

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/outbound"
)

func TestBlockedDialNamesNoAddress(t *testing.T) {
	srv, _ := okServer(t)
	clients := outbound.New(outbound.Config{})
	_, err := get(t, clients.Tenant(), "https"+srv.URL[len("http"):])
	require.ErrorIs(t, err, outbound.ErrBlockedAddress)
	var op *net.OpError
	require.True(t, errors.As(err, &op))
	require.Equal(t, outbound.ErrBlockedAddress.Error(), op.Err.Error(), "the guard repeats no resolved address")
}
