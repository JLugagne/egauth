package authflow_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth/authflow"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/sessions"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSessionService implements sessions.Service for tests exercising StatefulSessionMinter,
// which only calls CreateSession.
type mockSessionService struct{}

func (m *mockSessionService) CreateSession(_ context.Context, tenantID string, userID uuid.UUID, _ string, _ string, d time.Duration) (*sessions.Session, string, error) {
	return &sessions.Session{ID: uuid.New(), TenantID: tenantID, UserID: userID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(d)}, "session-token", nil
}

func (m *mockSessionService) ValidateSession(_ context.Context, _ string, _ string) (*sessions.Session, error) {
	return nil, errors.New("not implemented")
}

func (m *mockSessionService) Touch(_ context.Context, _ string, _ string, _ time.Duration) (*sessions.Session, error) {
	return nil, errors.New("not implemented")
}

func (m *mockSessionService) Rotate(_ context.Context, _ string, _ string, _ time.Duration) (*sessions.Session, string, error) {
	return nil, "", errors.New("not implemented")
}

func (m *mockSessionService) BindUser(_ context.Context, _ string, _ string, _ uuid.UUID, _ time.Duration) (*sessions.Session, string, error) {
	return nil, "", errors.New("not implemented")
}

func (m *mockSessionService) RevokeSession(_ context.Context, _ string, _ string, _ ...event.RequestContext) error {
	return errors.New("not implemented")
}

func (m *mockSessionService) RevokeAllForUser(_ context.Context, _ string, _ uuid.UUID, _ ...event.RequestContext) error {
	return errors.New("not implemented")
}

// cookieByName returns the cookie named name from the recorded response, failing the test when
// it was never set.
func cookieByName(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cookie %q was never set", name)
	return nil
}

// TestAuthFlow_CookiesSecureByDefault proves that every cookie authflow writes carries the
// Secure attribute under the DEFAULT wiring, against httptest requests whose r.TLS is nil —
// the TLS-terminating reverse-proxy deployment the library documents as legitimate. The old
// auto-detection (Secure: r != nil && r.TLS != nil) dropped Secure exactly there.
func TestAuthFlow_CookiesSecureByDefault(t *testing.T) {
	ctx := context.Background()
	secret := []byte("01234567890123456789012345678901")
	user := &identity.User{ID: uuid.New(), TenantID: "tenant-1", Email: "user@example.com"}
	minter := authflow.NewStatefulSessionMinter(&mockSessionService{}, time.Hour)

	t.Run("stateful minter session cookie", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		flow := &authflow.FlowContext{FlowID: "flow-1", TenantID: user.TenantID, UserID: user.ID, State: authflow.StateCompleted}
		require.NoError(t, minter.Mint(ctx, rec, req, flow))

		c := cookieByName(t, rec, sessions.DefaultSessionCookieName)
		assert.True(t, c.Secure, "session cookie must be Secure even when r.TLS is nil")
	})

	t.Run("flow cookie on the MFA-challenged path", func(t *testing.T) {
		gate := &mockMFAGate{isEnrolledFunc: func(context.Context, string, uuid.UUID) (bool, error) { return true, nil }}
		engine, err := authflow.NewEngine(secret, authflow.WithMFAGate(gate), authflow.WithMinter(&mockSessionMinter{}))
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		rec := httptest.NewRecorder()
		result, err := engine.ProcessPrimaryAuth(ctx, rec, req, user, "password", []string{tokens.AMRPassword}, false)
		require.NoError(t, err)
		require.Equal(t, authflow.StateMFAChallenged, result.State)

		c := cookieByName(t, rec, authflow.DefaultFlowCookieName)
		assert.True(t, c.Secure, "flow cookie must be Secure even when r.TLS is nil")
	})

	t.Run("cleared flow cookie on the completed path", func(t *testing.T) {
		gate := &mockMFAGate{isEnrolledFunc: func(context.Context, string, uuid.UUID) (bool, error) { return false, nil }}
		engine, err := authflow.NewEngine(secret, authflow.WithMFAGate(gate), authflow.WithMinter(minter))
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		rec := httptest.NewRecorder()
		result, err := engine.ProcessPrimaryAuth(ctx, rec, req, user, "password", []string{tokens.AMRPassword}, false)
		require.NoError(t, err)
		require.Equal(t, authflow.StateCompleted, result.State)

		cleared := cookieByName(t, rec, authflow.DefaultFlowCookieName)
		assert.Equal(t, -1, cleared.MaxAge, "flow cookie must be expired on the completed path")
		assert.True(t, cleared.Secure, "cleared flow cookie must be Secure even when r.TLS is nil")

		session := cookieByName(t, rec, sessions.DefaultSessionCookieName)
		assert.True(t, session.Secure, "session cookie minted through the engine must be Secure even when r.TLS is nil")
	})
}

// recordingSink captures events emitted by an engine, for misuse-warning assertions.
type recordingSink struct {
	events []event.Event
}

// misuseEvents returns the recorded events of type InsecureCookieMisuse (the engine also emits
// ordinary business events such as login.succeeded, which are irrelevant to the guard).
func (s *recordingSink) misuseEvents() []event.Event {
	var out []event.Event
	for _, e := range s.events {
		if e.Type == event.InsecureCookieMisuse {
			out = append(out, e)
		}
	}
	return out
}

func (s *recordingSink) EmitEvent(_ context.Context, e event.Event) {
	s.events = append(s.events, e)
}

// TestAuthFlow_InsecureOptOut_DropsSecureOnlyForNonHostNames proves that WithInsecureCookies
// removes the Secure attribute for plain (non-__Host-) cookie names — the documented local-HTTP
// development escape hatch — on both cookie writers the authflow package owns: the engine's flow
// cookie (with a plain name chosen via WithCookieName; the default name is __Host- prefixed and
// therefore always Secure) and the stateful session minter (custom non-__Host- name).
func TestAuthFlow_InsecureOptOut_DropsSecureOnlyForNonHostNames(t *testing.T) {
	ctx := context.Background()
	secret := []byte("01234567890123456789012345678901")
	user := &identity.User{ID: uuid.New(), TenantID: "tenant-1", Email: "user@example.com"}

	t.Run("flow cookie with explicit plain name", func(t *testing.T) {
		gate := &mockMFAGate{isEnrolledFunc: func(context.Context, string, uuid.UUID) (bool, error) { return true, nil }}
		engine, err := authflow.NewEngine(secret, authflow.WithMFAGate(gate), authflow.WithMinter(&mockSessionMinter{}), authflow.WithCookieName("auth_flow_token"), authflow.WithInsecureCookies())
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "http://api.example.com/login", nil)
		rec := httptest.NewRecorder()
		result, err := engine.ProcessPrimaryAuth(ctx, rec, req, user, "password", []string{tokens.AMRPassword}, false)
		require.NoError(t, err)
		require.Equal(t, authflow.StateMFAChallenged, result.State)

		c := cookieByName(t, rec, "auth_flow_token")
		assert.False(t, c.Secure, "WithInsecureCookies must drop Secure on the plain flow-cookie name")
	})

	t.Run("session cookie with custom non-__Host- name", func(t *testing.T) {
		minter := authflow.NewStatefulSessionMinter(&mockSessionService{}, time.Hour, "session_token").WithInsecureCookies()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://api.example.com/login", nil)
		flow := &authflow.FlowContext{FlowID: "flow-1", TenantID: user.TenantID, UserID: user.ID, State: authflow.StateCompleted}
		require.NoError(t, minter.Mint(ctx, rec, req, flow))

		c := cookieByName(t, rec, "session_token")
		assert.False(t, c.Secure, "WithInsecureCookies must drop Secure on a custom non-__Host- session-cookie name")
	})
}

// TestAuthFlow_InsecureOptOut_KeepsSecureForHostPrefixedNames proves the escape hatch is
// bounded: when the cookie name carries the browser-enforced __Host- prefix, Secure is kept
// even with WithInsecureCookies — browsers refuse __Host- cookies without Secure, so the
// opt-out must not be able to produce a cookie the browser will silently discard.
func TestAuthFlow_InsecureOptOut_KeepsSecureForHostPrefixedNames(t *testing.T) {
	ctx := context.Background()
	secret := []byte("01234567890123456789012345678901")
	user := &identity.User{ID: uuid.New(), TenantID: "tenant-1", Email: "user@example.com"}

	t.Run("flow cookie with __Host- name", func(t *testing.T) {
		gate := &mockMFAGate{isEnrolledFunc: func(context.Context, string, uuid.UUID) (bool, error) { return true, nil }}
		engine, err := authflow.NewEngine(secret,
			authflow.WithMFAGate(gate), authflow.WithMinter(&mockSessionMinter{}),
			authflow.WithInsecureCookies(), authflow.WithCookieName("__Host-auth_flow_token"))
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "http://api.example.com/login", nil)
		rec := httptest.NewRecorder()
		result, err := engine.ProcessPrimaryAuth(ctx, rec, req, user, "password", []string{tokens.AMRPassword}, false)
		require.NoError(t, err)
		require.Equal(t, authflow.StateMFAChallenged, result.State)

		c := cookieByName(t, rec, "__Host-auth_flow_token")
		assert.True(t, c.Secure, "Secure must stay on for a __Host- flow-cookie name even with WithInsecureCookies")
	})

	t.Run("session cookie with default __Host- name", func(t *testing.T) {
		minter := authflow.NewStatefulSessionMinter(&mockSessionService{}, time.Hour).WithInsecureCookies()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://api.example.com/login", nil)
		flow := &authflow.FlowContext{FlowID: "flow-1", TenantID: user.TenantID, UserID: user.ID, State: authflow.StateCompleted}
		require.NoError(t, minter.Mint(ctx, rec, req, flow))

		c := cookieByName(t, rec, sessions.DefaultSessionCookieName)
		assert.True(t, c.Secure, "Secure must stay on for the __Host- session-cookie name even with WithInsecureCookies")
	})
}

// TestAuthFlow_InsecureMisuseWarning proves the misuse guard: WithInsecureCookies serving a
// non-loopback Host over plaintext (r.TLS == nil) — the shape of a production-like deployment —
// emits exactly one event.InsecureCookieMisuse on the engine's sink, while the legitimate
// configurations (loopback HTTP dev, Secure-by-default) stay silent.
// TestAuthFlow_InsecureMisuseWarning proves the misuse guard: WithInsecureCookies serving a
// non-loopback Host over plaintext (r.TLS == nil) — the shape of a production-like deployment —
// emits exactly one event.InsecureCookieMisuse on the engine's sink, while the legitimate
// configurations (loopback HTTP dev, Secure-by-default) stay silent.
func TestAuthFlow_InsecureMisuseWarning(t *testing.T) {
	ctx := context.Background()
	secret := []byte("01234567890123456789012345678901")
	user := &identity.User{ID: uuid.New(), TenantID: "tenant-1", Email: "user@example.com"}

	runLogin := func(engine *authflow.Engine, host string) {
		req := httptest.NewRequest(http.MethodPost, "http://"+host+"/login", nil)
		rec := httptest.NewRecorder()
		_, err := engine.ProcessPrimaryAuth(ctx, rec, req, user, "password", []string{tokens.AMRPassword}, false)
		require.NoError(t, err)
	}

	t.Run("non-loopback plaintext host warns exactly once", func(t *testing.T) {
		sink := &recordingSink{}
		gate := &mockMFAGate{isEnrolledFunc: func(context.Context, string, uuid.UUID) (bool, error) { return false, nil }}
		engine, err := authflow.NewEngine(secret,
			authflow.WithMFAGate(gate), authflow.WithMinter(&mockSessionMinter{}),
			authflow.WithInsecureCookies(), authflow.WithEventSink(sink))
		require.NoError(t, err)

		runLogin(engine, "api.example.com")
		runLogin(engine, "api.example.com")

		warns := sink.misuseEvents()
		require.Len(t, warns, 1, "misuse warning must fire at most once per engine instance")
		ev := warns[0]
		assert.Equal(t, event.InsecureCookieMisuse, ev.Type)
		assert.Equal(t, "non_loopback_plaintext_host", ev.Reason)
		assert.Equal(t, "api.example.com", ev.Attrs["host"])
	})

	t.Run("loopback host stays silent", func(t *testing.T) {
		sink := &recordingSink{}
		gate := &mockMFAGate{isEnrolledFunc: func(context.Context, string, uuid.UUID) (bool, error) { return false, nil }}
		engine, err := authflow.NewEngine(secret,
			authflow.WithMFAGate(gate), authflow.WithMinter(&mockSessionMinter{}),
			authflow.WithInsecureCookies(), authflow.WithEventSink(sink))
		require.NoError(t, err)

		runLogin(engine, "localhost:8080")
		runLogin(engine, "127.0.0.1:8080")

		assert.Empty(t, sink.misuseEvents(), "loopback HTTP dev must not trigger the misuse warning")
	})

	t.Run("secure default stays silent", func(t *testing.T) {
		sink := &recordingSink{}
		gate := &mockMFAGate{isEnrolledFunc: func(context.Context, string, uuid.UUID) (bool, error) { return false, nil }}
		engine, err := authflow.NewEngine(secret,
			authflow.WithMFAGate(gate), authflow.WithMinter(&mockSessionMinter{}),
			authflow.WithEventSink(sink))
		require.NoError(t, err)

		runLogin(engine, "api.example.com")

		assert.Empty(t, sink.misuseEvents(), "the Secure-by-default wiring must never trigger the misuse warning")
	})
}
