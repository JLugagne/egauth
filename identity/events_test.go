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

	user, err := svc.Register(ctx, "user@example.com", "pw")
	require.NoError(t, err)
	assert.True(t, sink.has(event.UserRegistered))

	_, err = svc.Authenticate(ctx, "password", "user@example.com", "pw")
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

	_, err := svc.Register(ctx, "user@example.com", "pw")
	require.NoError(t, err)

	// First failure: LoginFailed, no lockout yet.
	_, err = svc.Authenticate(ctx, "password", "user@example.com", "wrong")
	require.ErrorIs(t, err, identity.ErrInvalidCredentials)
	assert.Equal(t, 1, sink.count(event.LoginFailed))
	assert.False(t, sink.has(event.AccountLocked))

	// Second failure: crosses the threshold -> AccountLocked emitted.
	_, err = svc.Authenticate(ctx, "password", "user@example.com", "wrong")
	require.ErrorIs(t, err, identity.ErrInvalidCredentials)
	assert.Equal(t, 2, sink.count(event.LoginFailed))
	assert.True(t, sink.has(event.AccountLocked))
}

func TestEvents_LoginFailureUnknownAccountCarriesNoUserID(t *testing.T) {
	ctx := context.Background()
	sink := &captureSink{}
	hasher := &hashertest.MockHasher{HashFunc: func(context.Context, string) (string, error) { return "h", nil }}
	svc := identity.NewService(identitymemory.NewStore(), hasher, okPolicy(), identity.WithEventSink(sink))

	_, err := svc.Authenticate(ctx, "password", "ghost@example.com", "pw")
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
	uid := uuid.New()
	hash := "h"
	store := &storetest.MockStore{
		FindUserByEmailFunc: func(_ context.Context, email string, _ ...identity.Option) (*identity.User, error) {
			return &identity.User{ID: uid, Email: email}, nil
		},
		FindIdentityByProviderFunc: func(_ context.Context, provider, providerID string, _ ...identity.Option) (*identity.Identity, error) {
			// FailedAttempts=1 so the next attempt would cross a threshold of 2 — but the store
			// increment below errors, so no lock is actually persisted.
			return &identity.Identity{ID: uuid.New(), UserID: uid, Provider: provider, ProviderID: providerID, PasswordHash: &hash, FailedAttempts: 1}, nil
		},
		IncrementFailedAttemptsFunc: func(context.Context, uuid.UUID, int, time.Duration, ...identity.Option) error {
			return errors.New("store unavailable")
		},
	}
	hasher := &hashertest.MockHasher{
		HashFunc:    func(context.Context, string) (string, error) { return "h", nil },
		CompareFunc: func(context.Context, string, string) error { return errors.New("wrong") },
	}
	svc := identity.NewService(store, hasher, okPolicy(),
		identity.WithEventSink(sink), identity.WithLockout(2, time.Hour))

	_, err := svc.Authenticate(ctx, "password", "user@example.com", "wrong")
	require.ErrorIs(t, err, identity.ErrInvalidCredentials)
	assert.True(t, sink.has(event.LoginFailed), "the failed attempt is still recorded")
	assert.False(t, sink.has(event.AccountLocked),
		"AccountLocked must not be emitted when the store never persisted the lock")
}

// failMailer fails every delivery, to exercise the swallowed-delivery-error path.
type failMailer struct{ err error }

func (m failMailer) SendPasswordReset(context.Context, *identity.User, string) error     { return m.err }
func (m failMailer) SendEmailVerification(context.Context, *identity.User, string) error { return m.err }
func (m failMailer) SendMagicLink(context.Context, *identity.User, string) error         { return m.err }
func (m failMailer) SendEmailChange(context.Context, *identity.User, string, string) error {
	return m.err
}

func TestEvents_HandlerEmitsDeliveryFailed(t *testing.T) {
	ctx := context.Background()
	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{HashFunc: func(context.Context, string) (string, error) { return "h", nil }}
	svc := identity.NewService(store, hasher, okPolicy())

	_, err := svc.Register(ctx, "user@example.com", "pw")
	require.NoError(t, err)

	sink := &captureSink{}
	handler := identity.RequestPasswordResetHandler(svc, failMailer{err: errors.New("smtp down")},
		identity.WithHandlerEventSink(sink))

	rec := httptest.NewRecorder()
	body := url.Values{"email": {"user@example.com"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/reset", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler(rec, req)

	// Response is uniform (enumeration-safe) regardless of the delivery outcome.
	require.Equal(t, http.StatusNoContent, rec.Code)
	// Delivery runs off the response path; the swallowed failure surfaces as an event.
	require.Eventually(t, func() bool { return sink.has(event.DeliveryFailed) }, time.Second, 5*time.Millisecond,
		"a Mailer outage must surface as a DeliveryFailed event")
}
