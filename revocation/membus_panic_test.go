package revocation_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/revocation"
)

// TestMemBus_Publish_HandlerPanicDoesNotAbortFanOut is the F-INFRA-002 regression test. The bus
// documents that "one failing subscriber cannot silently prevent the others from revoking"; a
// panic is a failure mode, so a panicking subscriber must neither unwind into the producer nor
// stop later subscribers from receiving the revocation.
func TestMemBus_Publish_HandlerPanicDoesNotAbortFanOut(t *testing.T) {
	bus := revocation.NewMemBus()
	reached := false
	bus.Subscribe(revocation.TargetUser, revocation.HandlerFunc(func(context.Context, revocation.Revocation) error {
		panic("subscriber bug")
	}))
	bus.Subscribe(revocation.TargetUser, revocation.HandlerFunc(func(context.Context, revocation.Revocation) error {
		reached = true
		return nil
	}))

	var err error
	require.NotPanics(t, func() {
		err = bus.Publish(context.Background(), revocation.Revocation{TargetType: revocation.TargetUser})
	}, "a panicking subscriber must not unwind into the producer")
	assert.True(t, reached, "a panicking subscriber must not prevent later subscribers from revoking")
	assert.Error(t, err, "a recovered panic must be surfaced to the producer")
	assert.Contains(t, err.Error(), "panicked")
}

// TestMemBus_Publish_PanicIsAggregatedWithHandlerErrors pins that the recovered panic is joined
// with ordinary handler errors instead of masking them.
func TestMemBus_Publish_PanicIsAggregatedWithHandlerErrors(t *testing.T) {
	bus := revocation.NewMemBus()
	sentinel := errors.New("handler error")
	bus.Subscribe(revocation.TargetUser, revocation.HandlerFunc(func(context.Context, revocation.Revocation) error {
		panic("subscriber bug")
	}))
	bus.Subscribe(revocation.TargetUser, revocation.HandlerFunc(func(context.Context, revocation.Revocation) error {
		return sentinel
	}))

	err := bus.Publish(context.Background(), revocation.Revocation{TargetType: revocation.TargetUser})
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel, "an ordinary handler error must survive the panic recovery")
	assert.Contains(t, err.Error(), "panicked")
}
