package passkey_test

import (
	"context"
	"sync"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
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

func newPasskeyServiceWithSink(t *testing.T, sink event.Sink) *passkey.Service {
	t.Helper()
	svc, err := passkey.NewService(passkeymemory.NewStore(), passkey.Config{
		RPID:           testRPID,
		RPDisplayName:  testRPName,
		RPOrigins:      []string{testOrigin},
		CookieKey:      testCookieKey,
		ChallengeStore: passkeymemory.NewChallengeStore(),
		Events:         sink,
	})
	require.NoError(t, err)
	return svc
}

func TestPasskeyEvents_LoginSucceeded(t *testing.T) {
	ctx := context.Background()
	sink := &captureSink{}
	svc := newPasskeyServiceWithSink(t, sink)

	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	_, session, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)

	_, err = svc.FinishLogin(ctx, "", userID, *session,
		auth.loginRequest(t, session.Challenge, userHandleOf(userID)))
	require.NoError(t, err)

	e, ok := sink.find(event.LoginSucceeded)
	require.True(t, ok, "expected a LoginSucceeded event after FinishLogin")
	assert.Equal(t, userID.String(), e.UserID)
	assert.Equal(t, "passkey", e.Reason)
}

func TestPasskeyEvents_NilSinkSafe(t *testing.T) {
	ctx := context.Background()
	// Config.Events left nil: the ceremony must complete without panicking.
	svc := newPasskeyServiceWithSink(t, nil)
	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	_, session, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)
	_, err = svc.FinishLogin(ctx, "", userID, *session,
		auth.loginRequest(t, session.Challenge, userHandleOf(userID)))
	require.NoError(t, err)
}
