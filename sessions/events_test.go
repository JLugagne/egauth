package sessions_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/sessions"
	"github.com/JLugagne/egauth/sessions/storetest"
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

func TestSessionsEvents_LogoutOnRevoke(t *testing.T) {
	ctx := context.Background()
	tenantID := "tenant-1"
	userID := uuid.Must(uuid.NewV7())
	sink := &captureSink{}

	store := &storetest.MockStore{
		FindSessionByHashFunc: func(_ context.Context, _ string, _ string) (*sessions.Session, error) {
			return &sessions.Session{ID: uuid.Must(uuid.NewV7()), TenantID: tenantID, UserID: userID, ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
		DeleteSessionFunc: func(_ context.Context, _ string, _ uuid.UUID) error { return nil },
	}

	svc := sessions.NewService(store, sessions.WithEventSink(sink))
	require.NoError(t, svc.RevokeSession(ctx, tenantID, "some-token"))

	e, ok := sink.find(event.Logout)
	require.True(t, ok, "expected a Logout event on RevokeSession")
	assert.Equal(t, tenantID, e.TenantID)
	assert.Equal(t, userID.String(), e.UserID)
}

func TestSessionsEvents_LogoutOnRevokeAll(t *testing.T) {
	ctx := context.Background()
	tenantID := "tenant-1"
	userID := uuid.Must(uuid.NewV7())
	sink := &captureSink{}

	store := &storetest.MockStore{
		DeleteSessionsByUserIDFunc: func(_ context.Context, _ string, _ uuid.UUID) error { return nil },
	}

	svc := sessions.NewService(store, sessions.WithEventSink(sink))
	require.NoError(t, svc.RevokeAllForUser(ctx, tenantID, userID))

	e, ok := sink.find(event.Logout)
	require.True(t, ok, "expected a Logout event on RevokeAllForUser")
	assert.Equal(t, tenantID, e.TenantID)
	assert.Equal(t, userID.String(), e.UserID)
	assert.Equal(t, "all_sessions", e.Reason)
}

func TestSessionsEvents_NilSinkSafe(t *testing.T) {
	ctx := context.Background()
	store := &storetest.MockStore{
		DeleteSessionsByUserIDFunc: func(_ context.Context, _ string, _ uuid.UUID) error { return nil },
	}
	// No WithEventSink: a nil sink must be a no-op, never a panic.
	svc := sessions.NewService(store)
	require.NoError(t, svc.RevokeAllForUser(ctx, "t", uuid.Must(uuid.NewV7())))
}

// TestSessionLogoutAuditIP verifies that both logout paths carry IP and UserAgent
// from a supplied event.RequestContext into the emitted Logout event Attrs.
func TestSessionLogoutAuditIP(t *testing.T) {
	ctx := context.Background()
	tenantID := "tenant-1"
	userID := uuid.Must(uuid.NewV7())
	reqCtx := event.RequestContext{IP: "203.0.113.42", UserAgent: "Mozilla/5.0"}

	t.Run("RevokeSession carries IP and UserAgent", func(t *testing.T) {
		sink := &captureSink{}
		store := &storetest.MockStore{
			FindSessionByHashFunc: func(_ context.Context, _ string, _ string) (*sessions.Session, error) {
				return &sessions.Session{ID: uuid.Must(uuid.NewV7()), TenantID: tenantID, UserID: userID, ExpiresAt: time.Now().Add(time.Hour)}, nil
			},
			DeleteSessionFunc: func(_ context.Context, _ string, _ uuid.UUID) error { return nil },
		}

		svc := sessions.NewService(store, sessions.WithEventSink(sink))
		require.NoError(t, svc.RevokeSession(ctx, tenantID, "some-token", reqCtx))

		e, ok := sink.find(event.Logout)
		require.True(t, ok, "expected a Logout event on RevokeSession")
		assert.Equal(t, "203.0.113.42", e.Attrs["ip"], "Logout event must carry client IP")
		assert.Equal(t, "Mozilla/5.0", e.Attrs["user_agent"], "Logout event must carry User-Agent")
	})

	t.Run("RevokeAllForUser carries IP and UserAgent", func(t *testing.T) {
		sink := &captureSink{}
		store := &storetest.MockStore{
			DeleteSessionsByUserIDFunc: func(_ context.Context, _ string, _ uuid.UUID) error { return nil },
		}

		svc := sessions.NewService(store, sessions.WithEventSink(sink))
		require.NoError(t, svc.RevokeAllForUser(ctx, tenantID, userID, reqCtx))

		e, ok := sink.find(event.Logout)
		require.True(t, ok, "expected a Logout event on RevokeAllForUser")
		assert.Equal(t, "all_sessions", e.Reason)
		assert.Equal(t, "203.0.113.42", e.Attrs["ip"], "Logout event must carry client IP")
		assert.Equal(t, "Mozilla/5.0", e.Attrs["user_agent"], "Logout event must carry User-Agent")
	})

	t.Run("absent RequestContext omits IP attrs", func(t *testing.T) {
		sink := &captureSink{}
		store := &storetest.MockStore{
			DeleteSessionsByUserIDFunc: func(_ context.Context, _ string, _ uuid.UUID) error { return nil },
		}

		svc := sessions.NewService(store, sessions.WithEventSink(sink))
		require.NoError(t, svc.RevokeAllForUser(ctx, tenantID, userID)) // no rc supplied

		e, ok := sink.find(event.Logout)
		require.True(t, ok, "expected a Logout event on RevokeAllForUser")
		assert.Nil(t, e.Attrs, "no RequestContext means Attrs must be nil")
	})
}
