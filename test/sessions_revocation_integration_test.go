package internal_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	identitymem "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/JLugagne/egauth/sessions"
	sessionsmem "github.com/JLugagne/egauth/sessions/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeleteAccount_RevokesLiveSessions is the cross-module integration test for the
// sessions ↔ identity.WithAccountErasers revocation fan-out (road-to-v1.md §4).
//
// It proves that when DeleteAccount is called with a real sessions.Service wired as an
// AccountEraser, existing live sessions become invalid: ValidateSession returns
// sessions.ErrSessionNotFound rather than returning a valid session.
//
// This is distinct from TestDeleteAccount_RunsErasersThenDeletes in identity/ which only
// verifies that erasers are *called* (using stub lambdas). This test verifies that the real
// sessions.Service.RevokeAllForUser is called AND produces the expected effect.
func TestDeleteAccount_RevokesLiveSessions(t *testing.T) {
	ctx := context.Background()

	// Wire real in-memory stores for both modules.
	identityStore := identitymem.NewStore()
	sessionsStore := sessionsmem.NewStore()

	// Build the sessions service.
	sessionsSvc := sessions.NewService(sessionsStore)

	// Build the identity service, wiring sessions revocation as an AccountEraser.
	sessionEraser := identity.AccountEraser(func(ctx context.Context, tenantID string, userID uuid.UUID) error {
		return sessionsSvc.RevokeAllForUser(ctx, tenantID, userID)
	})
	identitySvc := identity.NewService(
		identityStore,
		argon2.NewHasher(),
		policy.NewDefaultPolicy(),
		identity.WithAccountErasers(sessionEraser),
	)

	const (
		tenant   = ""
		email    = "revoke-test@example.com"
		password = "StrongP@ss1!"
	)

	// Register a user.
	user, err := identitySvc.Register(ctx, tenant, email, password)
	require.NoError(t, err)

	// Create a live session for that user.
	_, token, err := sessionsSvc.CreateSession(ctx, tenant, user.ID, "test-agent", "127.0.0.1", time.Hour)
	require.NoError(t, err)

	// Sanity: the session is valid before deletion.
	sess, err := sessionsSvc.ValidateSession(ctx, tenant, token)
	require.NoError(t, err, "session must be valid before account deletion")
	assert.Equal(t, user.ID, sess.UserID)

	// Delete the account — this must revoke the live session via the eraser.
	err = identitySvc.DeleteAccount(ctx, tenant, user.ID)
	require.NoError(t, err, "DeleteAccount must succeed")

	// The session must now be gone: ValidateSession returns ErrSessionNotFound.
	_, err = sessionsSvc.ValidateSession(ctx, tenant, token)
	assert.True(t, errors.Is(err, sessions.ErrSessionNotFound),
		"session must be invalidated after DeleteAccount; got: %v", err)
}

// TestDisableAccount_WithSessionRevocation verifies the caller-driven disable-account flow:
// disable the identity account AND revoke sessions in sequence from the caller. This remains a
// valid pattern; the wired-in alternative is to register sessionsSvc.RevokeAllForUser via
// identity.WithDisableRevokers so DisableUser cascades the revocation automatically (see
// TestDisableUser_RevokesRefreshTokensAndAPIKeys for the wired tokens equivalent).
//
// This confirms that RevokeAllForUser can be called independently from the sessions service
// and sessions created before the call become invalid.
func TestDisableAccount_WithSessionRevocation(t *testing.T) {
	ctx := context.Background()

	identityStore := identitymem.NewStore()
	sessionsStore := sessionsmem.NewStore()
	sessionsSvc := sessions.NewService(sessionsStore)
	identitySvc := identity.NewService(
		identityStore,
		argon2.NewHasher(),
		policy.NewDefaultPolicy(),
	)

	const (
		tenant   = ""
		email    = "disable-revoke@example.com"
		password = "StrongP@ss2!"
	)

	user, err := identitySvc.Register(ctx, tenant, email, password)
	require.NoError(t, err)

	// Create two sessions.
	_, tok1, err := sessionsSvc.CreateSession(ctx, tenant, user.ID, "agent-1", "10.0.0.1", time.Hour)
	require.NoError(t, err)
	_, tok2, err := sessionsSvc.CreateSession(ctx, tenant, user.ID, "agent-2", "10.0.0.2", time.Hour)
	require.NoError(t, err)

	// Disable the account.
	require.NoError(t, identitySvc.DisableUser(ctx, tenant, user.ID))

	// Revoke all sessions for the user (caller-driven, not via eraser).
	require.NoError(t, sessionsSvc.RevokeAllForUser(ctx, tenant, user.ID))

	// Both tokens must now be invalid.
	_, err = sessionsSvc.ValidateSession(ctx, tenant, tok1)
	assert.True(t, errors.Is(err, sessions.ErrSessionNotFound),
		"first session must be invalid after RevokeAllForUser; got: %v", err)

	_, err = sessionsSvc.ValidateSession(ctx, tenant, tok2)
	assert.True(t, errors.Is(err, sessions.ErrSessionNotFound),
		"second session must be invalid after RevokeAllForUser; got: %v", err)

	// The account itself is disabled (login blocked).
	_, err = identitySvc.Authenticate(ctx, tenant, "password", email, password)
	assert.ErrorIs(t, err, identity.ErrAccountDisabled,
		"a disabled account must reject valid credentials")
}
