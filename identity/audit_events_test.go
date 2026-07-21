package identity_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEvents_AdminOperations is a regression test: privileged admin credential operations must be
// audited like every other mutating identity operation. Before the fix SetTemporaryPassword and
// AdminCreateUser emitted no event, leaving admin-initiated credential overrides / provisioning
// invisible to a SIEM.
func TestEvents_AdminOperations(t *testing.T) {
	ctx := context.Background()
	hasher := &hashertest.MockHasher{HashFunc: func(context.Context, string) (string, error) { return "h", nil }}

	t.Run("AdminCreateUser emits UserRegistered", func(t *testing.T) {
		sink := &captureSink{}
		svc := identity.NewService(identitymemory.NewStore(), hasher, okPolicy(), identity.WithEventSink(sink))
		user, err := svc.AdminCreateUser(ctx, "", "admin-made@example.com", "Temp0rary!")
		require.NoError(t, err)
		e, ok := sink.last(event.UserRegistered)
		require.True(t, ok, "AdminCreateUser must emit a UserRegistered audit event")
		assert.Equal(t, user.ID.String(), e.UserID)
		assert.Equal(t, "admin_created", e.Reason)
	})

	t.Run("SetTemporaryPassword emits PasswordChanged", func(t *testing.T) {
		sink := &captureSink{}
		svc := identity.NewService(identitymemory.NewStore(), hasher, okPolicy(), identity.WithEventSink(sink))
		user, err := svc.Register(ctx, "", "user@example.com", "pw")
		require.NoError(t, err)
		require.NoError(t, svc.SetTemporaryPassword(ctx, "", user.ID, "Temp0rary!"))
		e, ok := sink.last(event.PasswordChanged)
		require.True(t, ok, "SetTemporaryPassword must emit a PasswordChanged audit event")
		assert.Equal(t, user.ID.String(), e.UserID)
		assert.Equal(t, "admin_temporary_password", e.Reason)
	})
}

// TestEvents_OAuthLinkOrCreate is a regression test: the OAuth login chokepoint must emit audit
// events for its outcomes, mirroring the password login path. Before the fix the entire OAuth
// login/registration flow was invisible to a SIEM (no file in oauth/ imports event).
func TestEvents_OAuthLinkOrCreate(t *testing.T) {
	ctx := context.Background()
	hasher := &hashertest.MockHasher{HashFunc: func(context.Context, string) (string, error) { return "h", nil }}

	t.Run("JIT-provision emits UserRegistered and LoginSucceeded", func(t *testing.T) {
		sink := &captureSink{}
		svc := identity.NewService(identitymemory.NewStore(), hasher, okPolicy(), identity.WithEventSink(sink))
		user, err := svc.LinkOrCreateIdentity(ctx, "", "google", "google-sub-1", "new@example.com", true)
		require.NoError(t, err)
		assert.True(t, sink.has(event.UserRegistered), "JIT provisioning must emit UserRegistered")
		e, ok := sink.last(event.LoginSucceeded)
		require.True(t, ok, "a successful OAuth login must emit LoginSucceeded")
		assert.Equal(t, user.ID.String(), e.UserID)
		assert.Equal(t, "oauth", e.Attrs["method"])
	})

	t.Run("already-linked login emits LoginSucceeded, not a second registration", func(t *testing.T) {
		sink := &captureSink{}
		svc := identity.NewService(identitymemory.NewStore(), hasher, okPolicy(), identity.WithEventSink(sink))
		_, err := svc.LinkOrCreateIdentity(ctx, "", "google", "sub-1", "u@example.com", true)
		require.NoError(t, err)
		_, err = svc.LinkOrCreateIdentity(ctx, "", "google", "sub-1", "u@example.com", true)
		require.NoError(t, err)
		assert.Equal(t, 1, sink.count(event.UserRegistered), "the second (already-linked) login must not re-register")
		assert.Equal(t, 2, sink.count(event.LoginSucceeded), "both calls are successful logins")
	})

	t.Run("disabled account OAuth login emits LoginFailed{account_disabled}", func(t *testing.T) {
		sink := &captureSink{}
		svc := identity.NewService(identitymemory.NewStore(), hasher, okPolicy(), identity.WithEventSink(sink))
		user, err := svc.LinkOrCreateIdentity(ctx, "", "google", "sub-1", "u@example.com", true)
		require.NoError(t, err)
		require.NoError(t, svc.DisableUser(ctx, "", user.ID))

		_, err = svc.LinkOrCreateIdentity(ctx, "", "google", "sub-1", "u@example.com", true)
		require.ErrorIs(t, err, identity.ErrAccountDisabled)
		e, ok := sink.last(event.LoginFailed)
		require.True(t, ok, "a disabled account's OAuth login attempt must emit LoginFailed (parity with the password path)")
		assert.Equal(t, "account_disabled", e.Reason)
		assert.Equal(t, user.ID.String(), e.UserID)
	})
}
