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
	// Reason is no longer used for the standard passkey flow; method is carried in Attrs.
	assert.Empty(t, e.Reason)
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

// TestPasskeyLoginAuditMethod asserts that both passkey login paths (standard and
// discoverable) emit login.succeeded carrying amr=["hwk"] and method="passkey" in Attrs,
// in line with the M9 SC-1 uniform audit contract. The discoverable path additionally
// carries Reason="passkey_discoverable" so consumers can distinguish the two flows.
func TestPasskeyLoginAuditMethod(t *testing.T) {
	ctx := context.Background()

	t.Run("standard passkey login carries amr and method", func(t *testing.T) {
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
		require.True(t, ok, "login.succeeded event must be emitted")
		assert.Equal(t, userID.String(), e.UserID)
		// amr must be the RFC 8176 hardware-key value.
		assert.Equal(t, []string{"hwk"}, e.Attrs["amr"], "amr must be [hwk]")
		// method must be the uniform passkey label.
		assert.Equal(t, "passkey", e.Attrs["method"], "method must be passkey")
		// Standard flow does not use Reason; distinction from discoverable is via method only.
		assert.Empty(t, e.Reason, "standard passkey flow must not set Reason")
	})

	t.Run("discoverable passkey login carries amr, method, and discoverable reason", func(t *testing.T) {
		sink := &captureSink{}
		svc := newPasskeyServiceWithSink(t, sink)

		userID := uuid.Must(uuid.NewV7())
		auth := register(t, svc, userID)

		_, session, err := svc.BeginDiscoverableLogin()
		require.NoError(t, err)

		_, resolvedID, err := svc.FinishDiscoverableLogin(ctx, "", *session,
			auth.loginRequest(t, session.Challenge, userHandleOf(userID)))
		require.NoError(t, err)
		assert.Equal(t, userID, resolvedID)

		e, ok := sink.find(event.LoginSucceeded)
		require.True(t, ok, "login.succeeded event must be emitted for discoverable login")
		assert.Equal(t, userID.String(), e.UserID)
		// amr must be the RFC 8176 hardware-key value.
		assert.Equal(t, []string{"hwk"}, e.Attrs["amr"], "amr must be [hwk]")
		// method is the same passkey label regardless of discoverable vs standard.
		assert.Equal(t, "passkey", e.Attrs["method"], "method must be passkey")
		// Reason distinguishes the discoverable flow from the standard passkey flow.
		assert.Equal(t, "passkey_discoverable", e.Reason, "discoverable flow must set Reason=passkey_discoverable")
	})
}
