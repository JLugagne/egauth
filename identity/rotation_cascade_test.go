package identity_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredentialRotation_CascadeSurvivesClientCancellation is the bug-confirming test for
// identity/TEN-3 and http/HTTP-2: the credential-rotating flows write the new password hash first
// and then revoke the account's sessions and refresh families. When that revocation cascade runs on
// the CLIENT-CANCELLABLE request context, a client that aborts mid-request leaves the new password
// active AND every old session alive — the exact opposite of the intended outcome on the
// compromise-recovery path. The cascade must therefore run on a detached context.
func TestCredentialRotation_CascadeSurvivesClientCancellation(t *testing.T) {
	const email = "cascade-cancel@example.com"

	cases := []struct {
		name   string
		rotate func(t *testing.T, ctx context.Context, svc identity.Service, userID uuid.UUID) error
	}{
		{
			name: "ResetPassword",
			rotate: func(t *testing.T, ctx context.Context, svc identity.Service, _ uuid.UUID) error {
				t.Helper()
				token, _, err := svc.RequestPasswordReset(context.Background(), "", email)
				require.NoError(t, err)
				require.NotEmpty(t, token)
				return svc.ResetPassword(ctx, "", token, "NewPassw0rd!")
			},
		},
		{
			name: "ChangePassword",
			rotate: func(_ *testing.T, ctx context.Context, svc identity.Service, userID uuid.UUID) error {
				return svc.ChangePassword(ctx, "", userID, "OldPassw0rd!", "NewPassw0rd!")
			},
		},
		{
			name: "SetTemporaryPassword",
			rotate: func(_ *testing.T, ctx context.Context, svc identity.Service, userID uuid.UUID) error {
				return svc.SetTemporaryPassword(ctx, "", userID, "NewPassw0rd!")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var (
				sessionsRevoked bool
				tokensRevoked   bool
				tokensEraserErr error
			)
			// The first eraser stands in for the client aborting the request while the cascade is
			// half-done: the sessions are revoked, the refresh families are not yet.
			sessionsEraser := func(_ context.Context, _ string, _ uuid.UUID) error {
				sessionsRevoked = true
				cancel()
				return nil
			}
			refreshEraser := func(c context.Context, _ string, _ uuid.UUID) error {
				tokensRevoked = true
				// Recorded at call time: the cascade's context is released when it returns.
				tokensEraserErr = c.Err()
				return nil
			}

			svc, _ := newVerificationService(t, identity.WithAccountErasers(sessionsEraser, refreshEraser))

			user, err := svc.Register(context.Background(), "", email, "OldPassw0rd!")
			require.NoError(t, err)

			require.NoError(t, tc.rotate(t, ctx, svc, user.ID),
				"a client abort must not fail a rotation whose credential is already committed")

			assert.True(t, sessionsRevoked, "the first eraser must have run")
			require.True(t, tokensRevoked,
				"the refresh-family eraser must still run after the client aborts: the new password is already live")
			assert.NoError(t, tokensEraserErr,
				"the cascade must run on a detached context, not the cancelled request context")

			// The account is authoritatively re-keyed either way.
			_, err = svc.Authenticate(context.Background(), "", "password", email, "OldPassw0rd!")
			assert.ErrorIs(t, err, identity.ErrInvalidCredentials, "the old password must no longer authenticate")
		})
	}
}

// TestCredentialRotation_RevocationFailureStaysVisible pins that detaching the cascade did not make
// a revocation outage silent: an eraser that fails AFTER the client aborted still surfaces its
// error, so the caller knows to retry rather than believing the recovery completed.
func TestCredentialRotation_RevocationFailureStaysVisible(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	boom := errors.New("session store down")
	aborting := func(_ context.Context, _ string, _ uuid.UUID) error {
		cancel()
		return nil
	}
	failing := func(_ context.Context, _ string, _ uuid.UUID) error { return boom }
	svc, _ := newVerificationService(t, identity.WithAccountErasers(aborting, failing))

	const email = "cascade-visible@example.com"
	user, err := svc.Register(context.Background(), "", email, "OldPassw0rd!")
	require.NoError(t, err)

	err = svc.ChangePassword(ctx, "", user.ID, "OldPassw0rd!", "NewPassw0rd!")
	assert.ErrorIs(t, err, boom, "a revocation failure must surface, aborted client or not")
}

// TestCredentialRotation_CascadeIsBounded pins that the detached cascade still carries a deadline:
// ignoring the caller's cancellation must not mean an eraser can pin the call forever.
func TestCredentialRotation_CascadeIsBounded(t *testing.T) {
	hung := func(ctx context.Context, _ string, _ uuid.UUID) error {
		<-ctx.Done()
		return ctx.Err()
	}
	svc, _ := newVerificationService(t,
		identity.WithAccountErasers(hung),
		identity.WithRevocationTimeout(50*time.Millisecond))

	const email = "cascade-bounded@example.com"
	user, err := svc.Register(context.Background(), "", email, "OldPassw0rd!")
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		done <- svc.ChangePassword(context.Background(), "", user.ID, "OldPassw0rd!", "NewPassw0rd!")
	}()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.DeadlineExceeded, "the bounded cascade must report its deadline")
	case <-time.After(5 * time.Second):
		require.FailNow(t, "the detached cascade was not bounded by the revocation timeout")
	}
}
