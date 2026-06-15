package mfa_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/mfa"
	mfamemory "github.com/JLugagne/egauth/mfa/memory"
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

func (c *captureSink) has(t event.Type) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.Type == t {
			return true
		}
	}
	return false
}

func TestMFAEvents_Lifecycle(t *testing.T) {
	ctx := context.Background()
	sink := &captureSink{}
	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	svc := mfa.NewService(mfamemory.NewStore(),
		mfa.WithEventSink(sink),
		mfa.WithClock(func() time.Time { return at }))

	userID := uuid.Must(uuid.NewV7())

	enr, err := svc.EnrollTOTP(ctx, "", userID, "user@example.com")
	require.NoError(t, err)
	assert.True(t, sink.has(event.MFAEnrolled), "enrollment must emit MFAEnrolled")

	code, err := mfa.GenerateCode(enr.Secret, at, mfa.DefaultDigits, mfa.DefaultPeriod)
	require.NoError(t, err)
	_, err = svc.ConfirmTOTP(ctx, "", userID, code)
	require.NoError(t, err)
	assert.True(t, sink.has(event.MFAConfirmed), "confirmation must emit MFAConfirmed")

	// A bad code must emit MFAVerificationFailed.
	err = svc.VerifyTOTP(ctx, "", userID, "")
	require.ErrorIs(t, err, mfa.ErrInvalidCode)
	assert.True(t, sink.has(event.MFAVerificationFailed), "a failed verification must emit MFAVerificationFailed")

	require.NoError(t, svc.DisableTOTP(ctx, "", userID))
	assert.True(t, sink.has(event.MFADisabled), "disabling must emit MFADisabled")
}
