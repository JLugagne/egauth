package identity_test

import (
	"context"
	"errors"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDisableUser_BlocksPasswordLogin is the bug-confirming test: an account that has been
// administratively disabled must no longer authenticate with its (otherwise valid) password,
// and the failure must be the dedicated ErrAccountDisabled rather than ErrInvalidCredentials.
func TestDisableUser_BlocksPasswordLogin(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "suspended@example.com"
	const password = "OldPassw0rd!"
	user, err := svc.Register(ctx, "", email, password)
	require.NoError(t, err)

	// Sanity: the credentials work while the account is active.
	_, err = svc.Authenticate(ctx, "", "password", email, password)
	require.NoError(t, err)

	// Disable the account.
	require.NoError(t, svc.DisableUser(ctx, "", user.ID))

	// The correct password no longer authenticates; the error is ErrAccountDisabled.
	_, err = svc.Authenticate(ctx, "", "password", email, password)
	assert.ErrorIs(t, err, identity.ErrAccountDisabled,
		"a disabled account must be rejected with ErrAccountDisabled, not logged in")
}

// TestEnableUser_RestoresLogin verifies the suspension is reversible: re-enabling an account
// makes its password authenticate again, and disable/enable are idempotent.
func TestEnableUser_RestoresLogin(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "reactivated@example.com"
	const password = "OldPassw0rd!"
	user, err := svc.Register(ctx, "", email, password)
	require.NoError(t, err)

	require.NoError(t, svc.DisableUser(ctx, "", user.ID))
	// Idempotent re-disable.
	require.NoError(t, svc.DisableUser(ctx, "", user.ID))

	_, err = svc.Authenticate(ctx, "", "password", email, password)
	require.ErrorIs(t, err, identity.ErrAccountDisabled)

	require.NoError(t, svc.EnableUser(ctx, "", user.ID))
	// Idempotent re-enable.
	require.NoError(t, svc.EnableUser(ctx, "", user.ID))

	_, err = svc.Authenticate(ctx, "", "password", email, password)
	assert.NoError(t, err, "re-enabling the account must restore login")
}

// TestDisableUser_RevokesMagicLink verifies that disabling an account revokes a magic-link login
// that was already minted: consuming the token after suspension is refused.
func TestDisableUser_RevokesMagicLink(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "magic@example.com"
	user, err := svc.Register(ctx, "", email, "OldPassw0rd!")
	require.NoError(t, err)

	token, _, err := svc.RequestMagicLink(ctx, "", email)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	require.NoError(t, svc.DisableUser(ctx, "", user.ID))

	// The pending magic-link token must not grant a session for a disabled account.
	_, err = svc.LoginWithMagicLink(ctx, "", token)
	assert.Error(t, err, "a disabled account's pending magic link must be revoked")
}

// TestDisableUser_RunsDisableRevokers verifies that DisableUser invokes every registered
// AccountRevoker (WithDisableRevokers) with the disabled user's tenant and id, AFTER the account
// has been stamped disabled — this is the seam that cascades into the tokens/sessions modules to
// kill a disabled user's refresh tokens, API keys and sessions.
func TestDisableUser_RunsDisableRevokers(t *testing.T) {
	ctx := context.Background()

	type call struct {
		tenantID string
		userID   uuid.UUID
	}
	var calls []call
	revoker := identity.AccountRevoker(func(_ context.Context, tenantID string, userID uuid.UUID) error {
		calls = append(calls, call{tenantID, userID})
		return nil
	})

	svc, _ := newVerificationService(t, identity.WithDisableRevokers(revoker, revoker))

	user, err := svc.Register(ctx, "", "revoke-hook@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	require.NoError(t, svc.DisableUser(ctx, "", user.ID))

	require.Len(t, calls, 2, "every registered disable revoker must run, in order")
	for _, c := range calls {
		assert.Equal(t, "", c.tenantID)
		assert.Equal(t, user.ID, c.userID)
	}
}

// TestDisableUser_RevokerErrorIsReturnedButAccountStaysDisabled verifies the fail-closed contract:
// a revoker failure is surfaced (joined across revokers) yet the account is authoritatively
// disabled regardless, so a downstream revocation hiccup never leaves a still-active account.
func TestDisableUser_RevokerErrorIsReturnedButAccountStaysDisabled(t *testing.T) {
	ctx := context.Background()

	boom := errors.New("token store unavailable")
	failing := identity.AccountRevoker(func(_ context.Context, _ string, _ uuid.UUID) error { return boom })

	svc, _ := newVerificationService(t, identity.WithDisableRevokers(failing))

	const email = "revoke-fail@example.com"
	const password = "OldPassw0rd!"
	user, err := svc.Register(ctx, "", email, password)
	require.NoError(t, err)

	err = svc.DisableUser(ctx, "", user.ID)
	require.ErrorIs(t, err, boom, "a revoker failure must be surfaced to the caller")

	// Despite the revoker error, the account is disabled (fail-closed).
	_, err = svc.Authenticate(ctx, "", "password", email, password)
	assert.ErrorIs(t, err, identity.ErrAccountDisabled,
		"the account must stay disabled even when a revoker fails")
}

// TestDisableUser_UnknownUser reports ErrUserNotFound for an unknown account.
func TestDisableUser_UnknownUser(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	assert.ErrorIs(t, svc.DisableUser(ctx, "", uuid.Must(uuid.NewV7())), identity.ErrUserNotFound)
	assert.ErrorIs(t, svc.EnableUser(ctx, "", uuid.Must(uuid.NewV7())), identity.ErrUserNotFound)
}

// TestDisableEnableUser_EmitsEvents verifies the security events are emitted.
func TestDisableEnableUser_EmitsEvents(t *testing.T) {
	ctx := context.Background()

	var got []event.Type
	sink := event.SinkFunc(func(_ context.Context, e event.Event) {
		got = append(got, e.Type)
	})
	svc, _ := newVerificationService(t, identity.WithEventSink(sink))

	user, err := svc.Register(ctx, "", "events@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	require.NoError(t, svc.DisableUser(ctx, "", user.ID))
	require.NoError(t, svc.EnableUser(ctx, "", user.ID))

	assert.Contains(t, got, event.AccountDisabled)
	assert.Contains(t, got, event.AccountEnabled)
}

// TestDisableUser_BlocksOAuthRelink is the bug-confirming test for TASK-056: an account that
// has been administratively disabled must not be able to re-complete the social-login flow
// through its already-linked OAuth identity. LinkOrCreateIdentity's already-linked branch must
// gate on DisabledAt and return ErrAccountDisabled rather than handing back the suspended user
// (which the OAuth callback would turn into a fresh access+refresh session).
func TestDisableUser_BlocksOAuthRelink(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	// JIT-provision a user with a linked OAuth identity (google, sub-disabled).
	user, err := svc.LinkOrCreateIdentity(ctx, "", "google", "sub-disabled", "relink@example.com", true)
	require.NoError(t, err)
	require.NotNil(t, user)

	// Sanity: the already-linked path resolves the same user while the account is active.
	again, err := svc.LinkOrCreateIdentity(ctx, "", "google", "sub-disabled", "relink@example.com", true)
	require.NoError(t, err)
	require.Equal(t, user.ID, again.ID)

	// Administratively suspend the account.
	require.NoError(t, svc.DisableUser(ctx, "", user.ID))

	// Re-completing the social login through the already-linked identity must now be refused
	// with ErrAccountDisabled, not silently return the suspended user.
	_, err = svc.LinkOrCreateIdentity(ctx, "", "google", "sub-disabled", "relink@example.com", true)
	assert.ErrorIs(t, err, identity.ErrAccountDisabled,
		"a disabled account must not regain a session via its linked OAuth identity")
}

// TestDeletedAccount_DoesNotRegainSessionViaOAuth is the successor of the TASK-069 regression test.
// The invariant it protects is unchanged — a soft-deleted account must never regain a session
// through its previously-linked OAuth identity — but the mechanism changed with identity/TEN-6:
// deletion now RELEASES the provider identity instead of keeping it, so the same provider account
// signs up again into a brand-new account rather than being refused forever. The old expectation
// (ErrUserNotFound on every later social login) was wrong: it locked a user who deleted their
// account out of that social login permanently. What must still hold is that the DELETED user is
// never handed back.
func TestDeletedAccount_DoesNotRegainSessionViaOAuth(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	// JIT-provision a user with a linked OAuth identity.
	user, err := svc.LinkOrCreateIdentity(ctx, "", "google", "sub-deleted", "deleted-relink@example.com", true)
	require.NoError(t, err)
	require.NotNil(t, user)

	// Sanity: the already-linked path resolves the same user while the account is active.
	again, err := svc.LinkOrCreateIdentity(ctx, "", "google", "sub-deleted", "deleted-relink@example.com", true)
	require.NoError(t, err)
	require.Equal(t, user.ID, again.ID)

	// Soft-delete the account (GDPR erasure / account deletion).
	require.NoError(t, svc.DeleteAccount(ctx, "", user.ID))

	// The deleted user must not come back: the social login provisions a NEW account.
	fresh, err := svc.LinkOrCreateIdentity(ctx, "", "google", "sub-deleted", "deleted-relink@example.com", true)
	require.NoError(t, err)
	assert.NotEqual(t, user.ID, fresh.ID,
		"a soft-deleted account must never be handed back through its previously-linked OAuth identity")
}
