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
	userID := uuid.New()
	sink := &captureSink{}

	store := &storetest.MockStore{
		FindSessionByHashFunc: func(_ context.Context, _ string, _ string) (*sessions.Session, error) {
			return &sessions.Session{ID: uuid.New(), TenantID: tenantID, UserID: userID, ExpiresAt: time.Now().Add(time.Hour)}, nil
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
	userID := uuid.New()
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
	require.NoError(t, svc.RevokeAllForUser(ctx, "t", uuid.New()))
}
