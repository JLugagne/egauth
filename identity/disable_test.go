package identity_test

import (
	"context"
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

// TestDisableUser_UnknownUser reports ErrUserNotFound for an unknown account.
func TestDisableUser_UnknownUser(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	assert.ErrorIs(t, svc.DisableUser(ctx, "", uuid.New()), identity.ErrUserNotFound)
	assert.ErrorIs(t, svc.EnableUser(ctx, "", uuid.New()), identity.ErrUserNotFound)
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

// TestDeletedAccount_BlocksOAuthRelink is the regression test for TASK-069: a soft-deleted
// account must not be able to re-complete the social-login flow through its already-linked OAuth
// identity. LinkOrCreateIdentity's already-linked branch calls FindUserByID, which intentionally
// still returns soft-deleted users (inspection contract), so the liveness gate after that call
// must be present and effective. Without the DeletedAt check the deleted user would be returned,
// allowing an OAuth callback to issue a fresh session for a non-existent account.
func TestDeletedAccount_BlocksOAuthRelink(t *testing.T) {
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

	// Re-completing the social login through the already-linked identity must be refused with
	// ErrUserNotFound: a soft-deleted account must not produce a session. FindUserByID still
	// returns the row (store inspection contract), so the service-layer liveness gate is the
	// sole barrier — this test pins it against silent regression.
	_, err = svc.LinkOrCreateIdentity(ctx, "", "google", "sub-deleted", "deleted-relink@example.com", true)
	assert.ErrorIs(t, err, identity.ErrUserNotFound,
		"a soft-deleted account must not regain a session via its linked OAuth identity")
}
