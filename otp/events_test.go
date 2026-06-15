package otp_test

import (
	"context"
	"sync"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/otp"
	otpmemory "github.com/JLugagne/egauth/otp/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type captureSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (c *captureSink) EmitEvent(_ context.Context, e event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureSink) find(t event.Type) (event.Event, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.Type == t {
			return e, true
		}
	}
	return event.Event{}, false
}

func TestOTPEvents_BlockedOnTooManyAttempts(t *testing.T) {
	ctx := context.Background()
	sink := &captureSink{}
	subjectID := uuid.Must(uuid.NewV7())
	const tenantID, purpose = "tenant-1", "phone_verify"

	svc := otp.NewService(otpmemory.NewStore(),
		otp.WithMaxAttempts(3),
		otp.WithEventSink(sink))

	_, err := svc.Issue(ctx, tenantID, subjectID, purpose)
	require.NoError(t, err)

	// Burn all attempts with wrong codes; the final one trips the limit.
	for range 3 {
		err = svc.Verify(ctx, tenantID, subjectID, purpose, "000000")
		require.Error(t, err)
	}

	e, ok := sink.find(event.AccountBlocked)
	require.True(t, ok, "expected an AccountBlocked event after attempts are exhausted")
	assert.Equal(t, tenantID, e.TenantID)
	assert.Equal(t, subjectID.String(), e.UserID)
	assert.Equal(t, "otp_too_many_attempts", e.Reason)
}

func TestOTPEvents_NilSinkSafe(t *testing.T) {
	ctx := context.Background()
	subjectID := uuid.Must(uuid.NewV7())
	svc := otp.NewService(otpmemory.NewStore(), otp.WithMaxAttempts(1))
	_, err := svc.Issue(ctx, "t", subjectID, "p")
	require.NoError(t, err)
	// nil sink must not panic when the limit trips.
	require.Error(t, svc.Verify(ctx, "t", subjectID, "p", "999999"))
}
