// TestLoginMethodUniform is the IC-1 integration proof for milestone M9.
//
// It proves via a capturing event.Sink that all three login paths — password, passkey, and
// magic-link — emit login.succeeded carrying Attrs["amr"] (a []string RFC 8176 list) and
// Attrs["method"] (a short human-readable summary), and that the client IP is recorded in
// Attrs["ip"] wherever the caller supplies a RequestContext.
//
// It also asserts that the removed magic_link.login event type is NEVER emitted, confirming
// that the magic-link path was unified into the login.succeeded stream (M9 SC-2).
package internal_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/JLugagne/egauth/passkey/passkeytest"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loginMethodSink is a minimal capturing Sink for TestLoginMethodUniform.
// It is distinct from auditSink in audit_trail_integration_test.go to keep each
// integration-test file self-contained with no implicit coupling between tests.
type loginMethodSink struct {
	auditSink // embed the shared helper for EmitEvent / reset / find / findReason
}

// uniformLoginPolicy is a permissive password policy for integration tests:
// the audit behaviour, not password strength, is the subject of these tests.
type uniformLoginPolicy struct{}

func (uniformLoginPolicy) Verify(_ context.Context, _ string) error { return nil }

// newUniformIdentityService wires a minimal identity.Service with the given sink and a
// stub hasher that optionally matches or rejects the password.
func newUniformIdentityService(t *testing.T, sink event.Sink, passwordMatches bool) identity.Service {
	t.Helper()
	hasher := &hashertest.MockHasher{
		HashFunc: func(_ context.Context, _ string) (string, error) { return "h", nil },
		CompareFunc: func(_ context.Context, _, _ string) error {
			if passwordMatches {
				return nil
			}
			return errWrongPassword
		},
	}
	return identity.NewService(
		identitymemory.NewStore(),
		hasher,
		uniformLoginPolicy{},
		identity.WithEventSink(sink),
	)
}

// errWrongPassword is a sentinel used by the stub hasher when the password must not match.
var errWrongPassword = &wrongPasswordError{}

type wrongPasswordError struct{}

func (*wrongPasswordError) Error() string { return "wrong password" }

// newUniformPasskeyService builds a passkey.Service with in-memory stores, suitable for
// running full registration + login ceremonies in tests.
func newUniformPasskeyService(t *testing.T, sink event.Sink) *passkey.Service {
	t.Helper()
	const rpID = "example.com"
	const rpOrigin = "https://example.com"
	svc, err := passkey.NewService(passkeymemory.NewStore(), passkey.Config{
		RPID:           rpID,
		RPDisplayName:  "Example Inc",
		RPOrigins:      []string{rpOrigin},
		CookieKey:      []byte("login-method-test-cookie-key----"), // 32 bytes
		ChallengeStore: passkeymemory.NewChallengeStore(),
		Events:         sink,
	})
	require.NoError(t, err)
	return svc
}

// registerPasskey performs a full registration ceremony using the soft authenticator and returns
// the authenticator instance for driving login ceremonies.
func registerPasskey(t *testing.T, svc *passkey.Service, userID uuid.UUID) *passkeytest.SoftAuthenticator {
	t.Helper()
	const rpID = "example.com"
	const rpOrigin = "https://example.com"
	ctx := context.Background()
	auth := passkeytest.NewSoftAuthenticator(t, rpID, rpOrigin)

	cc, session, err := svc.BeginRegistration(ctx, "", userID, "user@example.com", "User")
	require.NoError(t, err)
	require.NotNil(t, cc)

	_, err = svc.FinishRegistration(ctx, "", userID, "user@example.com", "User", *session,
		auth.RegistrationRequest(t, session.Challenge))
	require.NoError(t, err)
	return auth
}

// TestLoginMethodUniform is the IC-1 integration proof for M9.
//
// It uses only in-memory stores and real egauth services so it needs no external dependencies.
// Three sub-tests cover the three login paths; a fourth asserts the removed magic_link.login
// type is never emitted by any code path.
func TestLoginMethodUniform(t *testing.T) {
	ctx := context.Background()
	const clientIP = "203.0.113.88"

	// -------------------------------------------------------------------------
	// Password login: login.succeeded must carry method="password", amr=["pwd"], and IP.
	// -------------------------------------------------------------------------

	t.Run("password login emits login.succeeded with amr, method, and IP", func(t *testing.T) {
		sink := &auditSink{}
		svc := newUniformIdentityService(t, sink, true)

		_, err := svc.Register(ctx, "", "user@example.com", "pw")
		require.NoError(t, err)

		// Reset: assert only the authenticate event.
		sink.reset()

		_, err = svc.Authenticate(ctx, "", "password", "user@example.com", "pw",
			event.RequestContext{IP: clientIP})
		require.NoError(t, err)

		e, ok := sink.find(event.LoginSucceeded)
		require.True(t, ok, "password login must emit login.succeeded")
		assert.Equal(t, "password", e.Attrs["method"],
			"login.succeeded must carry method=password")
		amr, _ := e.Attrs["amr"].([]string)
		assert.Equal(t, []string{"pwd"}, amr,
			"login.succeeded must carry amr=[pwd] for a password login (first-factor only)")
		assert.Equal(t, clientIP, e.Attrs[event.AttrIP],
			"login.succeeded must carry the client IP from RequestContext")
	})

	// -------------------------------------------------------------------------
	// Passkey login: login.succeeded must carry method="passkey" and amr=["hwk"].
	// -------------------------------------------------------------------------

	t.Run("passkey login emits login.succeeded with amr=[hwk] and method=passkey", func(t *testing.T) {
		sink := &auditSink{}
		svc := newUniformPasskeyService(t, sink)

		userID := uuid.Must(uuid.NewV7())
		auth := registerPasskey(t, svc, userID)
		sink.reset()

		_, session, err := svc.BeginLogin(ctx, "", userID)
		require.NoError(t, err)

		_, err = svc.FinishLogin(ctx, "", userID, *session,
			auth.LoginRequest(t, session.Challenge, passkeytest.UserHandleOf(userID)))
		require.NoError(t, err)

		e, ok := sink.find(event.LoginSucceeded)
		require.True(t, ok, "passkey login must emit login.succeeded")
		assert.Equal(t, "passkey", e.Attrs["method"],
			"login.succeeded must carry method=passkey")
		amr, _ := e.Attrs["amr"].([]string)
		assert.Equal(t, []string{"hwk"}, amr,
			"login.succeeded must carry amr=[hwk] for a passkey login (hardware-key per RFC 8176)")
	})

	// -------------------------------------------------------------------------
	// Magic-link login: login.succeeded must carry method="magic_link" and amr=["otp"].
	// magic_link.login must NEVER be emitted.
	// -------------------------------------------------------------------------

	t.Run("magic-link login emits login.succeeded with method=magic_link and amr=[otp]", func(t *testing.T) {
		sink := &auditSink{}
		svc := newUniformIdentityService(t, sink, true)

		_, err := svc.Register(ctx, "", "user@example.com", "pw")
		require.NoError(t, err)

		token, _, err := svc.RequestMagicLink(ctx, "", "user@example.com")
		require.NoError(t, err)
		require.NotEmpty(t, token)

		sink.reset()

		_, err = svc.LoginWithMagicLink(ctx, "", token, event.RequestContext{IP: clientIP})
		require.NoError(t, err)

		e, ok := sink.find(event.LoginSucceeded)
		require.True(t, ok, "magic-link login must emit login.succeeded")
		assert.Equal(t, "magic_link", e.Attrs["method"],
			"login.succeeded must carry method=magic_link")
		amr, _ := e.Attrs["amr"].([]string)
		assert.Equal(t, []string{"otp"}, amr,
			"login.succeeded must carry amr=[otp] for a magic-link login (mailbox possession per RFC 8176)")
		assert.Equal(t, clientIP, e.Attrs[event.AttrIP],
			"login.succeeded must carry the client IP from RequestContext")

		// Confirm the removed magic_link.login type is never emitted.
		_, found := sink.find(event.Type("magic_link.login"))
		assert.False(t, found,
			"the removed magic_link.login event type must never be emitted; magic-link login now uses login.succeeded")
	})

	// -------------------------------------------------------------------------
	// Negative: magic_link.login must not be emitted even without a RequestContext.
	// -------------------------------------------------------------------------

	t.Run("magic-link login without RequestContext omits IP but never emits magic_link.login", func(t *testing.T) {
		sink := &auditSink{}
		svc := newUniformIdentityService(t, sink, true)

		_, err := svc.Register(ctx, "", "user@example.com", "pw")
		require.NoError(t, err)

		token, _, err := svc.RequestMagicLink(ctx, "", "user@example.com")
		require.NoError(t, err)

		sink.reset()

		_, err = svc.LoginWithMagicLink(ctx, "", token) // no RequestContext
		require.NoError(t, err)

		e, ok := sink.find(event.LoginSucceeded)
		require.True(t, ok, "magic-link login must emit login.succeeded regardless of RequestContext")
		_, hasIP := e.Attrs[event.AttrIP]
		assert.False(t, hasIP,
			"absent RequestContext must not write an IP attribute to the event")

		_, found := sink.find(event.Type("magic_link.login"))
		assert.False(t, found,
			"the removed magic_link.login type must never be emitted")
	})
}
