package identity_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/identity/storetest"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureSink records emitted events for assertions (safe for concurrent use).
type captureSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (c *captureSink) EmitEvent(_ context.Context, e event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureSink) count(t event.Type) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.events {
		if e.Type == t {
			n++
		}
	}
	return n
}

func (c *captureSink) has(t event.Type) bool { return c.count(t) > 0 }

// last returns the most recent event of type t (and whether one exists).
func (c *captureSink) last(t event.Type) (event.Event, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.events) - 1; i >= 0; i-- {
		if c.events[i].Type == t {
			return c.events[i], true
		}
	}
	return event.Event{}, false
}

func okPolicy() *mockPolicy {
	return &mockPolicy{VerifyFunc: func(context.Context, string) error { return nil }}
}

func TestEvents_RegisterAndLogin(t *testing.T) {
	ctx := context.Background()
	sink := &captureSink{}
	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{
		HashFunc:    func(context.Context, string) (string, error) { return "h", nil },
		CompareFunc: func(_ context.Context, _, _ string) error { return nil }, // password always matches
	}
	svc := identity.NewService(store, hasher, okPolicy(), identity.WithEventSink(sink))

	user, err := svc.Register(ctx, "", "user@example.com", "pw")
	require.NoError(t, err)
	assert.True(t, sink.has(event.UserRegistered))

	_, err = svc.Authenticate(ctx, "", "password", "user@example.com", "pw")
	require.NoError(t, err)
	assert.True(t, sink.has(event.LoginSucceeded))

	// The login event must carry the user id.
	sink.mu.Lock()
	var loginUserID string
	for _, e := range sink.events {
		if e.Type == event.LoginSucceeded {
			loginUserID = e.UserID
		}
	}
	sink.mu.Unlock()
	assert.Equal(t, user.ID.String(), loginUserID)
}

func TestEvents_LoginFailureAndLockout(t *testing.T) {
	ctx := context.Background()
	sink := &captureSink{}
	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{
		HashFunc:    func(context.Context, string) (string, error) { return "h", nil },
		CompareFunc: func(_ context.Context, _, _ string) error { return errors.New("nope") }, // always wrong
	}
	// Lock after 2 failed attempts.
	svc := identity.NewService(store, hasher, okPolicy(),
		identity.WithEventSink(sink), identity.WithLockout(2, time.Hour))

	_, err := svc.Register(ctx, "", "user@example.com", "pw")
	require.NoError(t, err)

	// First failure: LoginFailed, no lockout yet.
	_, err = svc.Authenticate(ctx, "", "password", "user@example.com", "wrong")
	require.ErrorIs(t, err, identity.ErrInvalidCredentials)
	assert.Equal(t, 1, sink.count(event.LoginFailed))
	assert.False(t, sink.has(event.AccountLocked))

	// Second failure: crosses the threshold -> AccountLocked emitted.
	_, err = svc.Authenticate(ctx, "", "password", "user@example.com", "wrong")
	require.ErrorIs(t, err, identity.ErrInvalidCredentials)
	assert.Equal(t, 2, sink.count(event.LoginFailed))
	assert.True(t, sink.has(event.AccountLocked))
}

func TestEvents_LoginFailureUnknownAccountCarriesNoUserID(t *testing.T) {
	ctx := context.Background()
	sink := &captureSink{}
	hasher := &hashertest.MockHasher{HashFunc: func(context.Context, string) (string, error) { return "h", nil }}
	svc := identity.NewService(identitymemory.NewStore(), hasher, okPolicy(), identity.WithEventSink(sink))

	_, err := svc.Authenticate(ctx, "", "password", "ghost@example.com", "pw")
	require.ErrorIs(t, err, identity.ErrInvalidCredentials)

	sink.mu.Lock()
	defer sink.mu.Unlock()
	require.Len(t, sink.events, 1)
	assert.Equal(t, event.LoginFailed, sink.events[0].Type)
	assert.Empty(t, sink.events[0].UserID, "an unknown account must not resolve a user id")
}

func TestEvents_NoAccountLockedWhenIncrementFails(t *testing.T) {
	ctx := context.Background()
	sink := &captureSink{}
	uid := uuid.Must(uuid.NewV7())
	hash := "h"
	store := &storetest.MockStore{
		FindUserByEmailFunc: func(_ context.Context, _ string, email string) (*identity.User, error) {
			return &identity.User{ID: uid, Email: email}, nil
		},
		FindIdentityByProviderFunc: func(_ context.Context, _ string, provider, providerID string) (*identity.Identity, error) {
			// FailedAttempts=1 so the next attempt would cross a threshold of 2 — but the store
			// increment below errors, so no lock is actually persisted.
			return &identity.Identity{ID: uuid.Must(uuid.NewV7()), UserID: uid, Provider: provider, ProviderID: providerID, PasswordHash: &hash, FailedAttempts: 1}, nil
		},
		IncrementFailedAttemptsFunc: func(context.Context, string, uuid.UUID, int, time.Duration) error {
			return errors.New("store unavailable")
		},
	}
	hasher := &hashertest.MockHasher{
		HashFunc:    func(context.Context, string) (string, error) { return "h", nil },
		CompareFunc: func(context.Context, string, string) error { return errors.New("wrong") },
	}
	svc := identity.NewService(store, hasher, okPolicy(),
		identity.WithEventSink(sink), identity.WithLockout(2, time.Hour))

	_, err := svc.Authenticate(ctx, "", "password", "user@example.com", "wrong")
	require.ErrorIs(t, err, identity.ErrInvalidCredentials)
	assert.True(t, sink.has(event.LoginFailed), "the failed attempt is still recorded")
	assert.False(t, sink.has(event.AccountLocked),
		"AccountLocked must not be emitted when the store never persisted the lock")
}

// failMailer fails every delivery, to exercise the swallowed-delivery-error path.
func newFailMailer(err error) identity.Mailer {
	return identity.Mailer{
		PasswordReset:             func(context.Context, identity.PasswordResetMail) error { return err },
		EmailVerification:         func(context.Context, identity.EmailVerificationMail) error { return err },
		MagicLink:                 func(context.Context, identity.MagicLinkMail) error { return err },
		EmailChange:               func(context.Context, identity.EmailChangeMail) error { return err },
		RecoveryEmailVerification: func(context.Context, identity.RecoveryEmailMail) error { return err },
	}
}

func TestEvents_HandlerEmitsDeliveryFailed(t *testing.T) {
	ctx := context.Background()
	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{HashFunc: func(context.Context, string) (string, error) { return "h", nil }}
	svc := identity.NewService(store, hasher, okPolicy())

	_, err := svc.Register(ctx, "", "user@example.com", "pw")
	require.NoError(t, err)

	sink := &captureSink{}
	handler := identity.RequestPasswordResetHandler(svc, newFailMailer(errors.New("smtp down")),
		identity.WithHandlerEventSink(sink))

	rec := httptest.NewRecorder()
	body := url.Values{"email": {"user@example.com"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/reset", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+req.Host) // same-origin: pass strict-by-default CSRF check
	handler(rec, req)

	// Response is uniform (enumeration-safe) regardless of the delivery outcome.
	require.Equal(t, http.StatusNoContent, rec.Code)
	// Delivery runs off the response path; the swallowed failure surfaces as an event.
	require.Eventually(t, func() bool { return sink.has(event.DeliveryFailed) }, time.Second, 5*time.Millisecond,
		"a Mailer outage must surface as a DeliveryFailed event")
}

// TestAuthRequestContextIP proves that an optional event.RequestContext threaded into
// Authenticate lands the client IP (and User-Agent) in Event.Attrs on both login.succeeded and
// login.failed, and that omitting the context omits those attributes entirely.
func TestAuthRequestContextIP(t *testing.T) {
	const ip, ua = "203.0.113.7", "curl/8.0"

	newSvc := func(sink event.Sink, passwordMatches bool) identity.Service {
		hasher := &hashertest.MockHasher{
			HashFunc: func(context.Context, string) (string, error) { return "h", nil },
			CompareFunc: func(context.Context, string, string) error {
				if passwordMatches {
					return nil
				}
				return errors.New("wrong")
			},
		}
		return identity.NewService(identitymemory.NewStore(), hasher, okPolicy(), identity.WithEventSink(sink))
	}

	t.Run("login succeeded carries IP and UA when supplied", func(t *testing.T) {
		ctx := context.Background()
		sink := &captureSink{}
		svc := newSvc(sink, true)
		_, err := svc.Register(ctx, "", "user@example.com", "pw")
		require.NoError(t, err)

		_, err = svc.Authenticate(ctx, "", "password", "user@example.com", "pw",
			event.RequestContext{IP: ip, UserAgent: ua})
		require.NoError(t, err)

		e, ok := sink.last(event.LoginSucceeded)
		require.True(t, ok, "a successful login must emit login.succeeded")
		assert.Equal(t, ip, e.Attrs[event.AttrIP], "the client IP must land in Attrs")
		assert.Equal(t, ua, e.Attrs[event.AttrUserAgent], "the User-Agent must land in Attrs")
	})

	t.Run("login failed carries IP when supplied", func(t *testing.T) {
		ctx := context.Background()
		sink := &captureSink{}
		svc := newSvc(sink, false)
		_, err := svc.Register(ctx, "", "user@example.com", "pw")
		require.NoError(t, err)

		_, err = svc.Authenticate(ctx, "", "password", "user@example.com", "wrong",
			event.RequestContext{IP: ip})
		require.ErrorIs(t, err, identity.ErrInvalidCredentials)

		e, ok := sink.last(event.LoginFailed)
		require.True(t, ok, "a failed login must emit login.failed")
		assert.Equal(t, ip, e.Attrs[event.AttrIP], "the client IP must land in Attrs on failure too")
		// A UA-less context must not invent a User-Agent attribute.
		_, hasUA := e.Attrs[event.AttrUserAgent]
		assert.False(t, hasUA, "an empty User-Agent must not be written to Attrs")
	})

	t.Run("no IP attribute when no context supplied", func(t *testing.T) {
		ctx := context.Background()
		sink := &captureSink{}
		svc := newSvc(sink, true)
		_, err := svc.Register(ctx, "", "user@example.com", "pw")
		require.NoError(t, err)

		_, err = svc.Authenticate(ctx, "", "password", "user@example.com", "pw")
		require.NoError(t, err)

		e, ok := sink.last(event.LoginSucceeded)
		require.True(t, ok)
		_, hasIP := e.Attrs[event.AttrIP]
		assert.False(t, hasIP, "absent RequestContext must omit the IP attribute")
		_, hasUA := e.Attrs[event.AttrUserAgent]
		assert.False(t, hasUA, "absent RequestContext must omit the User-Agent attribute")
	})
}
