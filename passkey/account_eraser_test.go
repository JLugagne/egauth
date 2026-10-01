// Regression tests for F-COMP-002: passkey credentials must be erasable by account recovery.
// The identity service runs registered identity.AccountEraser hooks on password reset /
// account deletion; this package must expose one that deletes the user's passkeys, or an
// attacker-enrolled credential survives the victim's recovery and keeps minting sessions.
package passkey_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestService_AccountEraser_DeletesCredentialsAndLoginFails is the composed-recovery
// invariant: after invoking the eraser, the user has no credentials and cannot begin a login.
func TestService_AccountEraser_DeletesCredentialsAndLoginFails(t *testing.T) {
	ctx := context.Background()
	store := passkeymemory.NewStore()
	svc, err := passkey.NewService(store, passkey.Config{
		RPID: testRPID, RPDisplayName: testRPName, RPOrigins: []string{testOrigin},
		CookieKey: testCookieKey, ChallengeStore: passkeymemory.NewChallengeStore(),
	})
	require.NoError(t, err)

	uid := uuid.Must(uuid.NewV7())
	_ = registerTenant(t, svc, "t1", uid)
	creds, err := svc.ListCredentials(ctx, "t1", uid)
	require.NoError(t, err)
	require.Len(t, creds, 1, "precondition: the user has an enrolled credential")

	// The returned value must be assignable to identity.AccountEraser without this package
	// importing identity (the modules stay decoupled).
	eraser := svc.AccountEraser()
	require.NoError(t, eraser(ctx, "t1", uid))

	creds, err = svc.ListCredentials(ctx, "t1", uid)
	require.NoError(t, err)
	require.Empty(t, creds, "the eraser must delete every credential of the user")
	_, _, err = svc.BeginLogin(ctx, "t1", uid)
	require.ErrorIs(t, err, passkey.ErrNoCredentials, "login must fail after the eraser ran")

	// Erasure may be retried after a partial failure, so it must be idempotent.
	require.NoError(t, eraser(ctx, "t1", uid), "a second erasure must not error")
}

// TestService_AccountEraser_ScopedToTenant proves the eraser cannot delete another tenant's
// credentials, including for the same user ID.
func TestService_AccountEraser_ScopedToTenant(t *testing.T) {
	ctx := context.Background()
	store := passkeymemory.NewStore()
	svc, err := passkey.NewService(store, passkey.Config{
		RPID: testRPID, RPDisplayName: testRPName, RPOrigins: []string{testOrigin},
		CookieKey: testCookieKey, ChallengeStore: passkeymemory.NewChallengeStore(),
	})
	require.NoError(t, err)

	uid := uuid.Must(uuid.NewV7())
	_ = registerTenant(t, svc, "tenant-a", uid)
	_ = registerTenant(t, svc, "tenant-b", uid)

	require.NoError(t, svc.AccountEraser()(ctx, "tenant-a", uid))

	a, err := svc.ListCredentials(ctx, "tenant-a", uid)
	require.NoError(t, err)
	require.Empty(t, a)
	b, err := svc.ListCredentials(ctx, "tenant-b", uid)
	require.NoError(t, err)
	require.Len(t, b, 1, "the eraser must not touch another tenant's credentials")
}
