package egauth_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/keys"
)

func TestTenantsImportKeyIsRefusedToSessionAdmins(t *testing.T) {
	w := newFacadeWorld(t, tenantKeys)
	ctx := context.Background()
	tn := principal.TenantID{}
	sys := w.system("provisioning")
	require.NoError(t, w.a.Tenants().RenewKeys(ctx, sys, egauth.RenewKeysRequest{Tenant: tn, Lifetime: defaultExpiry(), Overlap: defaultExpiry()}))
	before, err := w.st.Keys.ActiveKey(ctx, tn)
	require.NoError(t, err)
	_, admin, _ := w.admin("root@example.com")

	seed := sha256.Sum256([]byte("caller-known tenant key"))
	err = w.a.Tenants().ImportKey(ctx, admin, egauth.ImportKeyRequest{
		Tenant: tn, KeyID: "evil-1", Alg: "EdDSA", Material: seed[:], Lifetime: keys.NeverExpire(), Overlap: defaultExpiry(),
	})
	require.ErrorIs(t, err, egauth.ErrForbidden, "a session admin holding the signing key could forge any claims")
	after, err := w.st.Keys.ActiveKey(ctx, tn)
	require.NoError(t, err)
	require.Equal(t, before.KeyID, after.KeyID)
	require.NoError(t, w.a.Tenants().RenewKeys(ctx, admin, egauth.RenewKeysRequest{Tenant: tn, Lifetime: defaultExpiry(), Overlap: defaultExpiry()}),
		"generated keys never leave the library, so a session admin may still renew")
}

func TestSystemCallerRefusalsAreAudited(t *testing.T) {
	w := newFacadeWorld(t, perRequestTenancy)
	w.tenant = "globex"
	other := w.tenantID()
	w.tenant = "acme"
	sys := w.system("acme-job")
	require.ErrorIs(t, w.a.Tenants().Erase(context.Background(), sys, other), egauth.ErrTenantMismatch)
	uses := w.systemUses()
	require.Len(t, uses, 1)
	require.Contains(t, uses[0].Err.Text(), egauth.ErrTenantMismatch.Error())
	require.Equal(t, "acme-job", uses[0].Reason)
}

func passwordless(c *egauth.Config[gateClaims]) {
	c.Modules.Password = nil
	c.Modules.MagicLink = &egauth.MagicLinkModule{}
	c.Pages.MagicLink = "/magic"
}

func TestAccountsTemporaryPasswordNeedsThePasswordModule(t *testing.T) {
	w := newFacadeWorld(t, passwordless)
	bob := w.seedUser("bob@example.com", false)
	ctx := context.Background()
	sys := w.system("onboarding")
	before, err := w.st.Identity.CurrentEpoch(ctx, bob)
	require.NoError(t, err)

	tp, err := w.a.Accounts().SetTemporaryPassword(ctx, sys, bob.User)
	require.ErrorIs(t, err, egauth.ErrFacadeUnavailable)
	require.True(t, tp.IsZero())
	after, err := w.st.Identity.CurrentEpoch(ctx, bob)
	require.NoError(t, err)
	require.Equal(t, before, after, "nothing was rotated")

	_, err = w.a.Accounts().Create(ctx, sys, egauth.CreateAccountRequest{Email: "new@example.com", TemporaryPassword: true})
	require.ErrorIs(t, err, egauth.ErrFacadeUnavailable)
	_, err = w.st.Identity.FindUser(ctx, principal.TenantID{}, mustEmail(t, "new@example.com"))
	require.ErrorIs(t, err, store.ErrNotFound, "no account was created")
	_, err = w.a.Accounts().Create(ctx, sys, egauth.CreateAccountRequest{Email: "new@example.com"})
	require.NoError(t, err, "an account without a password needs no password module")
}

func TestAccountsSetTemporaryPasswordChecksTheTargetBeforeHashing(t *testing.T) {
	var checks atomic.Int32
	w := newFacadeWorld(t, func(c *egauth.Config[gateClaims]) {
		c.Modules.Password = &egauth.PasswordModule{Breach: passwords.BreachCheckerFunc(func(context.Context, string) (bool, error) {
			checks.Add(1)
			return false, nil
		})}
	})
	bob := w.seedUser("bob@example.com", false)
	gone := w.seedUser("gone@example.com", false)
	ctx := context.Background()
	sys := w.system("support")
	require.NoError(t, w.a.Accounts().Delete(ctx, sys, gone.User))

	for name, user := range map[string]uuid.UUID{"unknown": uuid.New(), "deleted": gone.User} {
		_, err := w.a.Accounts().SetTemporaryPassword(ctx, sys, user)
		require.True(t, errors.Is(err, store.ErrNotFound), "%s: %v", name, err)
	}
	require.Zero(t, checks.Load(), "no password was generated for a missing target")
	_, err := w.a.Accounts().SetTemporaryPassword(ctx, sys, bob.User)
	require.NoError(t, err)
	require.NotZero(t, checks.Load())
}

func TestSystemCallerMintedByAnotherAuthIsRefusedForATenantThisAuthCannotServe(t *testing.T) {
	single := newFacadeWorld(t)
	foreign := single.system("single-tenant-job")
	multi := newFacadeWorld(t, perRequestTenancy)
	ctx := context.Background()

	_, err := multi.a.Accounts().Create(ctx, foreign, egauth.CreateAccountRequest{Email: "x@example.com"})
	require.ErrorIs(t, err, egauth.ErrTenantNotServed)
	_, err = multi.st.Identity.FindUser(ctx, principal.TenantID{}, mustEmail(t, "x@example.com"))
	require.ErrorIs(t, err, store.ErrNotFound, "no account exists in a tenant the deployment never serves")
	uses := multi.systemUses()
	require.Len(t, uses, 1)
	require.Contains(t, uses[0].Err.Text(), egauth.ErrTenantNotServed.Error())
}

func TestAccountsCreateIsRefusedInAnErasedTenant(t *testing.T) {
	w := newFacadeWorld(t, tenantKeys, perRequestTenancy)
	w.tenant = "acme"
	ctx := context.Background()
	sys := w.system("offboarding")
	require.NoError(t, w.a.Tenants().Erase(ctx, sys, w.tenantID()))

	_, err := w.a.Accounts().Create(ctx, sys, egauth.CreateAccountRequest{Email: "late@acme.example"})
	require.ErrorIs(t, err, keys.ErrTenantTombstoned)
	_, err = w.st.Identity.FindUser(ctx, w.tenantID(), mustEmail(t, "late@acme.example"))
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestAccountsCreateRacingTenantEraseLeavesNoLiveAccount(t *testing.T) {
	var w *facadeWorld
	var erased atomic.Bool
	w = newFacadeWorld(t, tenantKeys, perRequestTenancy, func(c *egauth.Config[gateClaims]) {
		c.Modules.Password = &egauth.PasswordModule{Breach: passwords.BreachCheckerFunc(func(context.Context, string) (bool, error) {
			if erased.CompareAndSwap(false, true) {
				require.NoError(t, w.a.Tenants().Erase(context.Background(), w.system("offboarding"), w.tenantID()))
			}
			return false, nil
		})}
	})
	w.tenant = "acme"
	ctx := context.Background()

	_, err := w.a.Accounts().Create(ctx, w.system("onboarding"), egauth.CreateAccountRequest{Email: "late@acme.example", TemporaryPassword: true})
	require.True(t, erased.Load(), "the erasure ran between the tombstone check and the insert")
	require.ErrorIs(t, err, keys.ErrTenantTombstoned)
	u, err := w.st.Identity.FindUser(ctx, w.tenantID(), mustEmail(t, "late@acme.example"))
	if err == nil {
		require.False(t, u.DeletedAt.IsZero(), "the account created after the erasure is deleted again")
	} else {
		require.ErrorIs(t, err, store.ErrNotFound)
	}
}
