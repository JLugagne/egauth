package passkey_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lifecycle is a minimal in-test stand-in for an identity user record: it tracks the
// disabled / soft-deleted state of one account and exposes it as an AccountGate closure.
type lifecycle struct {
	disabled bool
	deleted  bool
}

func (l *lifecycle) gate() passkey.AccountGate {
	return func(_ context.Context, _ string, _ uuid.UUID) error {
		switch {
		case l.deleted:
			return passkey.ErrAccountDeleted
		case l.disabled:
			return passkey.ErrAccountDisabled
		default:
			return nil
		}
	}
}

// newGatedPasskeyService builds a Service wired with the given lifecycle gate and event sink.
func newGatedPasskeyService(t *testing.T, gate passkey.AccountGate, sink event.Sink) *passkey.Service {
	t.Helper()
	svc, err := passkey.NewService(passkeymemory.NewStore(), passkey.Config{
		RPID:           testRPID,
		RPDisplayName:  testRPName,
		RPOrigins:      []string{testOrigin},
		CookieKey:      testCookieKey,
		ChallengeStore: passkeymemory.NewChallengeStore(),
		Events:         sink,
		AccountGate:    gate,
	})
	require.NoError(t, err)
	return svc
}

// TestAccountGate_DisabledAccountRefused is the regression test for the lifecycle gap: an
// administratively disabled account (identity.DisableUser) whose passkey enrollment survives
// the suspension must not complete a passkey login. Begin must refuse to start a ceremony for
// the suspended account, and Finish must refuse an otherwise-valid assertion instead of
// minting a session — with the distinct disabled outcome, not a generic failure.
func TestAccountGate_DisabledAccountRefused(t *testing.T) {
	ctx := context.Background()
	lc := &lifecycle{}
	sink := &captureSink{}
	svc := newGatedPasskeyService(t, lc.gate(), sink)

	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	// A ceremony begun while the account is still active must not become a session once the
	// admin suspends the account mid-ceremony (DisableUser preserves passkeys by design).
	_, session, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)

	lc.disabled = true

	_, err = svc.FinishLogin(ctx, "", userID, *session,
		auth.loginRequest(t, session.Challenge, userHandleOf(userID)))
	require.ErrorIs(t, err, passkey.ErrAccountDisabled,
		"a disabled account must not complete FinishLogin")

	// The blocked attempt must not mint a login event, and must be auditable as a block.
	_, ok := sink.find(event.LoginSucceeded)
	assert.False(t, ok, "a disabled account must not produce a login.succeeded event")
	blocked, ok := sink.find(event.AccountBlocked)
	require.True(t, ok, "the refused login must be auditable")
	assert.Equal(t, "account_disabled", blocked.Reason)

	// Defense in depth: after the suspension, Begin refuses to start a new ceremony.
	_, _, err = svc.BeginLogin(ctx, "", userID)
	require.ErrorIs(t, err, passkey.ErrAccountDisabled)
}

// TestAccountGate_DisabledAccountDiscoverableRefused covers the usernameless flow: the
// account is resolved from the credential's user handle at Finish, so the suspension must be
// caught there (Begin has no user to gate).
func TestAccountGate_DisabledAccountDiscoverableRefused(t *testing.T) {
	ctx := context.Background()
	lc := &lifecycle{}
	sink := &captureSink{}
	svc := newGatedPasskeyService(t, lc.gate(), sink)

	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)
	lc.disabled = true

	_, session, err := svc.BeginDiscoverableLogin()
	require.NoError(t, err, "BeginDiscoverableLogin has no user to gate")

	_, _, err = svc.FinishDiscoverableLogin(ctx, "", *session,
		auth.loginRequest(t, session.Challenge, userHandleOf(userID)))
	require.ErrorIs(t, err, passkey.ErrAccountDisabled,
		"a disabled account must not complete FinishDiscoverableLogin")

	_, ok := sink.find(event.LoginSucceeded)
	assert.False(t, ok, "a disabled account must not produce a login.succeeded event")
}

// TestAccountGate_DeletedAccountRefused covers the soft-deleted case: an account whose
// passkey eraser was not registered must not authenticate through the surviving credential.
func TestAccountGate_DeletedAccountRefused(t *testing.T) {
	ctx := context.Background()
	lc := &lifecycle{}
	sink := &captureSink{}
	svc := newGatedPasskeyService(t, lc.gate(), sink)

	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	_, session, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)

	lc.deleted = true

	// Identified flow: Begin refuses up front...
	_, _, err = svc.BeginLogin(ctx, "", userID)
	require.ErrorIs(t, err, passkey.ErrAccountDeleted)

	// ...and the in-flight Finish is refused with the deleted outcome.
	_, err = svc.FinishLogin(ctx, "", userID, *session,
		auth.loginRequest(t, session.Challenge, userHandleOf(userID)))
	require.ErrorIs(t, err, passkey.ErrAccountDeleted)

	// Discoverable flow: refused at Finish, where the account is resolved.
	_, dSession, err := svc.BeginDiscoverableLogin()
	require.NoError(t, err)
	_, _, err = svc.FinishDiscoverableLogin(ctx, "", *dSession,
		auth.loginRequest(t, dSession.Challenge, userHandleOf(userID)))
	require.ErrorIs(t, err, passkey.ErrAccountDeleted)

	_, ok := sink.find(event.LoginSucceeded)
	assert.False(t, ok, "a deleted account must not produce a login.succeeded event")
	blocked, ok := sink.find(event.AccountBlocked)
	require.True(t, ok)
	assert.Equal(t, "account_deleted", blocked.Reason)
}

// TestAccountGate_EnabledAccountUnaffected pins the happy path: a live account with the gate
// wired completes both login flows exactly as before.
func TestAccountGate_EnabledAccountUnaffected(t *testing.T) {
	ctx := context.Background()
	lc := &lifecycle{}
	sink := &captureSink{}
	svc := newGatedPasskeyService(t, lc.gate(), sink)

	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	_, session, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)
	_, err = svc.FinishLogin(ctx, "", userID, *session,
		auth.loginRequest(t, session.Challenge, userHandleOf(userID)))
	require.NoError(t, err, "an active account must complete the identified flow")

	_, dSession, err := svc.BeginDiscoverableLogin()
	require.NoError(t, err)
	_, resolved, err := svc.FinishDiscoverableLogin(ctx, "", *dSession,
		auth.loginRequest(t, dSession.Challenge, userHandleOf(userID)))
	require.NoError(t, err, "an active account must complete the discoverable flow")
	assert.Equal(t, userID, resolved)

	_, ok := sink.find(event.LoginSucceeded)
	assert.True(t, ok, "the active logins must still be audited as successes")
}

// TestAccountGate_GateFailureRefusedClosed pins the failure semantics: a gate error that is
// neither ErrAccountDisabled nor ErrAccountDeleted is a gate/infrastructure failure and must
// fail the login closed (handlers map it to 500), never leak through as a success.
func TestAccountGate_GateFailureRefusedClosed(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("lifecycle store unavailable")
	current := error(nil)
	svc := newGatedPasskeyService(t, func(_ context.Context, _ string, _ uuid.UUID) error {
		return current
	}, nil)

	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID)

	_, session, err := svc.BeginLogin(ctx, "", userID)
	require.NoError(t, err)

	current = boom

	_, err = svc.FinishLogin(ctx, "", userID, *session,
		auth.loginRequest(t, session.Challenge, userHandleOf(userID)))
	require.ErrorIs(t, err, boom, "a gate infrastructure failure must fail the login closed")
	assert.NotErrorIs(t, err, passkey.ErrAccountDisabled)
	assert.NotErrorIs(t, err, passkey.ErrAccountDeleted)
}

// TestNewIdentityAccountGate exercises the ready-made adapter against a real identity user
// store: active → allowed, disabled → ErrAccountDisabled, re-enabled → allowed again,
// soft-deleted → ErrAccountDeleted, unknown/missing user → ErrAccountDeleted.
func TestNewIdentityAccountGate(t *testing.T) {
	ctx := context.Background()
	store := identitymemory.NewStore()
	user, err := store.CreateUser(ctx, "", "gate@example.com")
	require.NoError(t, err)

	gate := passkey.NewIdentityAccountGate(store)

	require.NoError(t, gate(ctx, "", user.ID), "an active account must pass the gate")

	require.NoError(t, store.DisableUser(ctx, "", user.ID, time.Now()))
	require.ErrorIs(t, gate(ctx, "", user.ID), passkey.ErrAccountDisabled)

	require.NoError(t, store.EnableUser(ctx, "", user.ID))
	require.NoError(t, gate(ctx, "", user.ID), "a re-enabled account must pass the gate again")

	require.NoError(t, store.DeleteUser(ctx, "", user.ID))
	require.ErrorIs(t, gate(ctx, "", user.ID), passkey.ErrAccountDeleted)

	require.ErrorIs(t, gate(ctx, "", uuid.Must(uuid.NewV7())), passkey.ErrAccountDeleted,
		"a user the store cannot find must be refused as deleted")
}

// TestAccountGate_IdentityWiringEndToEnd exercises the wiring examples/fullstack uses: a
// passkey Service whose AccountGate is passkey.NewIdentityAccountGate(idStore) refuses a
// passkey login the moment identity.DisableUser suspends the account, and allows it again
// after identity.EnableUser.
func TestAccountGate_IdentityWiringEndToEnd(t *testing.T) {
	ctx := context.Background()
	idStore := identitymemory.NewStore()
	user, err := idStore.CreateUser(ctx, "", "passkey-user@example.com")
	require.NoError(t, err)

	svc, err := passkey.NewService(passkeymemory.NewStore(), passkey.Config{
		RPID:           testRPID,
		RPDisplayName:  testRPName,
		RPOrigins:      []string{testOrigin},
		CookieKey:      testCookieKey,
		ChallengeStore: passkeymemory.NewChallengeStore(),
		AccountGate:    passkey.NewIdentityAccountGate(idStore),
	})
	require.NoError(t, err)

	auth := register(t, svc, user.ID)

	_, session, err := svc.BeginLogin(ctx, "", user.ID)
	require.NoError(t, err)

	require.NoError(t, idStore.DisableUser(ctx, "", user.ID, time.Now()))

	_, _, err = svc.BeginLogin(ctx, "", user.ID)
	require.ErrorIs(t, err, passkey.ErrAccountDisabled)
	_, err = svc.FinishLogin(ctx, "", user.ID, *session,
		auth.loginRequest(t, session.Challenge, userHandleOf(user.ID)))
	require.ErrorIs(t, err, passkey.ErrAccountDisabled)

	// Re-enabling restores the login.
	require.NoError(t, idStore.EnableUser(ctx, "", user.ID))
	_, session, err = svc.BeginLogin(ctx, "", user.ID)
	require.NoError(t, err)
	_, err = svc.FinishLogin(ctx, "", user.ID, *session,
		auth.loginRequest(t, session.Challenge, userHandleOf(user.ID)))
	require.NoError(t, err)
}

// TestAccountGate_HandlerSurfaces403 pins the HTTP contract of the lifecycle refusal: the
// login handlers surface it as 403 with the distinct machine-readable codes account_disabled
// / account_deleted (never a 5xx, never a generic verification failure), so UX can explain
// the refusal to the suspended principal.
func TestAccountGate_HandlerSurfaces403(t *testing.T) {
	lc := &lifecycle{}
	svc := newGatedPasskeyService(t, lc.gate(), nil)

	userID := uuid.Must(uuid.NewV7())
	auth := register(t, svc, userID) // enrolled under tenant ""

	opts := []passkey.HandlerOption{
		passkey.WithUserResolver(func(*http.Request) (uuid.UUID, string, string, string, bool) {
			return userID, "alice", "Alice", "", true // same tenant "" as the enrollment
		}),
		passkey.WithCookieKey(testCookieKey),
	}

	// Capture a valid ceremony (cookie + finish body) while the account is still active.
	beginRec := httptest.NewRecorder()
	passkey.BeginLoginHandler(svc, opts...)(beginRec, httptest.NewRequest(http.MethodPost, "/login/begin", nil))
	require.Equal(t, http.StatusOK, beginRec.Code)
	cookie := findCookie(beginRec.Result().Cookies(), passkey.DefaultSessionCookieName)
	require.NotNil(t, cookie)
	challenge := challengeFromAssertion(t, beginRec.Body.Bytes())
	body := drainBody(t, auth.assertionAtCount(t, challenge, userHandleOf(userID), 0))

	lc.disabled = true

	// BeginLoginHandler refuses up front with 403 account_disabled.
	beginRec2 := httptest.NewRecorder()
	passkey.BeginLoginHandler(svc, opts...)(beginRec2, httptest.NewRequest(http.MethodPost, "/login/begin", nil))
	assert.Equal(t, http.StatusForbidden, beginRec2.Code)
	assert.Contains(t, beginRec2.Body.String(), "account_disabled")

	// FinishLoginHandler refuses the cryptographically valid assertion with 403 account_disabled.
	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	passkey.FinishLoginHandler(svc, opts...)(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"a disabled account must be refused by the handler, not minted a session")
	assert.Contains(t, rec.Body.String(), "account_disabled")

	// A deleted account carries the distinct deleted code.
	lc.disabled = false
	lc.deleted = true
	beginRec3 := httptest.NewRecorder()
	passkey.BeginLoginHandler(svc, opts...)(beginRec3, httptest.NewRequest(http.MethodPost, "/login/begin", nil))
	assert.Equal(t, http.StatusForbidden, beginRec3.Code)
	assert.Contains(t, beginRec3.Body.String(), "account_deleted")
}
