package egauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/mfa"
)

func TestAccountsAPIKeyCallerIsRefusedByEveryFacadeMethod(t *testing.T) {
	w := newFacadeWorld(t)
	owner, admin, _ := w.admin("root@example.com")
	target := w.seedUser("bob@example.com", false)
	key := w.apiKeyCaller(owner)
	for _, c := range w.everyFacadeCall(target) {
		require.ErrorIs(t, c.call(context.Background(), key), egauth.ErrAPIKeyCaller, c.name)
	}
	require.NoError(t, w.a.Accounts().Disable(context.Background(), admin, target.User), "the owner's own session still may")
}

func TestAccountsNonAdminSessionCannotActOnAnotherUser(t *testing.T) {
	w := newFacadeWorld(t)
	_, by, _ := w.user("alice@example.com")
	target, _, victim := w.user("bob@example.com")
	ctx := context.Background()
	for _, c := range w.everyFacadeCall(target) {
		if strings.HasPrefix(c.name, "APIKeys.") {
			continue
		}
		require.ErrorIs(t, c.call(ctx, by), egauth.ErrForbidden, c.name)
	}
	require.Equal(t, http.StatusOK, w.status(victim))
}

func TestAccountsSelfServiceOnlyRefusesEverySessionAdmin(t *testing.T) {
	w := newFacadeWorld(t, func(c *egauth.Config[gateClaims]) { c.Admin = egauth.SelfServiceOnly() })
	_, admin, _ := w.admin("root@example.com")
	target := w.seedUser("bob@example.com", false)
	ctx := context.Background()
	require.ErrorIs(t, w.a.Accounts().Disable(ctx, admin, target.User), egauth.ErrForbidden)
	require.ErrorIs(t, w.a.Tenants().Erase(ctx, admin, principal.TenantID{}), egauth.ErrForbidden)
	require.NoError(t, w.a.Accounts().Disable(ctx, w.system("offboarding"), target.User))
}

func TestAccountsAdminMustBeFreshAndMultiFactorWhenEnrolled(t *testing.T) {
	w := newFacadeWorld(t)
	sub, admin, _ := w.admin("root@example.com")
	target := w.seedUser("bob@example.com", false)
	ctx := context.Background()

	w.clk.Advance(egauth.ConfigOf(w.a).Policy.ReauthWindow + time.Second)
	require.ErrorIs(t, w.a.Accounts().Disable(ctx, admin, target.User), egauth.ErrReauthRequired)

	admin, _ = w.caller("root@example.com")
	require.NoError(t, w.a.Accounts().Disable(ctx, admin, target.User))
	w.enrollTOTP(sub)
	require.ErrorIs(t, w.a.Accounts().Enable(ctx, admin, target.User), egauth.ErrReauthRequired,
		"a password-only session of an enrolled admin lacks the second factor")
}

func TestAccountsSessionPredatingASecurityChangeIsRefused(t *testing.T) {
	w := newFacadeWorld(t)
	sub, admin, _ := w.admin("root@example.com")
	target := w.seedUser("bob@example.com", false)
	w.disable(sub, true)
	w.disable(sub, false)
	require.ErrorIs(t, w.a.Accounts().Disable(context.Background(), admin, target.User), egauth.ErrReauthRequired)
}

func TestAccountsDisabledOrMustChangeCallerIsRefused(t *testing.T) {
	w := newFacadeWorld(t)
	sub, admin, _ := w.admin("root@example.com")
	target := w.seedUser("bob@example.com", false)
	ctx := context.Background()
	_, err := w.st.Identity.Apply(ctx, identity.SetMustChange{Subject: sub, MustChange: true})
	require.NoError(t, err)
	require.ErrorIs(t, w.a.Accounts().Disable(ctx, admin, target.User), egauth.ErrForbidden)
}

func TestAccountsDisableEnableDeleteRunTheMutationPath(t *testing.T) {
	w := newFacadeWorld(t)
	_, admin, _ := w.admin("root@example.com")
	target, _, victim := w.user("bob@example.com")
	ctx := context.Background()
	before, err := w.st.Identity.CurrentEpoch(ctx, target)
	require.NoError(t, err)

	require.NoError(t, w.a.Accounts().Disable(ctx, admin, target.User))
	after, err := w.st.Identity.CurrentEpoch(ctx, target)
	require.NoError(t, err)
	require.Greater(t, after, before, "Disable bumps the security epoch")
	require.Equal(t, http.StatusUnauthorized, w.status(victim), "every session of the disabled user ended")
	require.Len(t, w.sink.of(event.AccountDisabled), 1)

	require.NoError(t, w.a.Accounts().Enable(ctx, admin, target.User))
	u, err := w.st.Identity.GetUser(ctx, target)
	require.NoError(t, err)
	require.True(t, u.DisabledAt.IsZero())
	require.Equal(t, http.StatusUnauthorized, w.status(victim), "Enable brings no ended session back")

	require.NoError(t, w.a.Accounts().Delete(ctx, admin, target.User))
	_, err = w.st.Identity.FindUser(ctx, target.Tenant, mustEmail(t, "bob@example.com"))
	require.ErrorIs(t, err, store.ErrNotFound, "the tombstone frees the email")
	require.Error(t, w.a.Accounts().Disable(ctx, admin, target.User), "a deleted account is not reachable")
	require.ErrorIs(t, w.a.Accounts().Disable(ctx, admin, uuid.Nil), egauth.ErrInvalidRequest)
	require.ErrorIs(t, w.a.Accounts().Disable(ctx, admin, uuid.New()), store.ErrNotFound)
}

func TestAccountsCreateWithATemporaryPasswordForcesAChange(t *testing.T) {
	w := newFacadeWorld(t)
	_, admin, _ := w.admin("root@example.com")
	ctx := context.Background()

	created, err := w.a.Accounts().Create(ctx, admin, egauth.CreateAccountRequest{Email: "  New.User@Example.COM ", TemporaryPassword: true})
	require.NoError(t, err)
	require.False(t, created.TemporaryPassword.IsZero())
	pw := created.TemporaryPassword.Reveal()
	require.GreaterOrEqual(t, len(pw), 24)
	u, err := w.st.Identity.GetUser(ctx, created.Subject)
	require.NoError(t, err)
	require.True(t, u.MustChange)
	require.False(t, u.EmailVerifiedAt.IsZero())
	cred, err := w.st.Identity.GetPassword(ctx, created.Subject)
	require.NoError(t, err)
	require.NoError(t, argon2.NewHasher().Compare(ctx, passwords.PHC(cred.PHC.PHC()), pw))
	require.Equal(t, http.StatusOK, w.loginWith("new.user@example.com", pw).code)

	_, err = w.a.Accounts().Create(ctx, admin, egauth.CreateAccountRequest{Email: "new.user@example.com"})
	require.ErrorIs(t, err, identity.ErrIdentifierTaken)
	_, err = w.a.Accounts().Create(ctx, admin, egauth.CreateAccountRequest{Email: "not an email"})
	require.ErrorIs(t, err, egauth.ErrInvalidRequest)

	plain, err := w.a.Accounts().Create(ctx, w.system("import"), egauth.CreateAccountRequest{Email: "plain@example.com"})
	require.NoError(t, err)
	require.True(t, plain.TemporaryPassword.IsZero())
	_, err = w.st.Identity.GetPassword(ctx, plain.Subject)
	require.ErrorIs(t, err, store.ErrNotFound, "an account created without a temporary password has none")
}

func TestAccountsTemporaryPasswordIsRedacted(t *testing.T) {
	w := newFacadeWorld(t)
	_, admin, _ := w.admin("root@example.com")
	target := w.seedUser("bob@example.com", false)
	tp, err := w.a.Accounts().SetTemporaryPassword(context.Background(), admin, target.User)
	require.NoError(t, err)
	secret := tp.Reveal()
	require.NotEmpty(t, secret)
	created := egauth.CreatedAccount{Subject: target, TemporaryPassword: tp}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("x", "tp", tp, "created", created)
	js, err := json.Marshal(created)
	require.NoError(t, err)
	for _, out := range []string{
		fmt.Sprint(tp), fmt.Sprintf("%v %+v %#v %s %q", tp, tp, tp, tp, tp), fmt.Sprintf("%v %+v %#v", created, created, created),
		string(js), logged.String(),
	} {
		require.NotContains(t, out, secret)
	}
}

func TestAccountsSetTemporaryPasswordEndsSessionsAndForcesAChange(t *testing.T) {
	w := newFacadeWorld(t)
	_, admin, _ := w.admin("root@example.com")
	target, _, victim := w.user("bob@example.com")
	ctx := context.Background()
	tp, err := w.a.Accounts().SetTemporaryPassword(ctx, admin, target.User)
	require.NoError(t, err)
	u, err := w.st.Identity.GetUser(ctx, target)
	require.NoError(t, err)
	require.True(t, u.MustChange)
	require.Equal(t, http.StatusUnauthorized, w.status(victim))
	require.Equal(t, http.StatusUnauthorized, w.loginWith("bob@example.com", gatePassword).code, "the old password is gone")
	require.Equal(t, http.StatusOK, w.loginWith("bob@example.com", tp.Reveal()).code)
	changed := w.sink.of(event.PasswordChanged)
	require.NotEmpty(t, changed)
	require.Equal(t, "temporary_password", changed[len(changed)-1].Attrs[string(event.KeyRotationReason)])
}

func TestAccountsUnlockMFAClearsBothLockouts(t *testing.T) {
	w := newFacadeWorld(t)
	_, admin, _ := w.admin("root@example.com")
	target := w.seedUser("bob@example.com", false)
	w.enrollTOTP(target)
	ctx := context.Background()
	lock := mfa.Lockout{Subject: target, Now: w.clk.Now(), Max: 3, Duration: time.Hour}
	for range 3 {
		_, err := w.st.MFA.IncrementTOTPAttempts(ctx, lock)
		require.NoError(t, err)
		_, err = w.st.MFA.IncrementRecoveryAttempts(ctx, lock)
		require.NoError(t, err)
	}
	require.NoError(t, w.a.Accounts().UnlockMFA(ctx, admin, target.User))
	e, err := w.st.MFA.GetTOTP(ctx, target)
	require.NoError(t, err)
	require.Zero(t, e.FailedAttempts)
	n, err := w.st.MFA.IncrementRecoveryAttempts(ctx, lock)
	require.NoError(t, err)
	require.Equal(t, 1, n, "the recovery counter restarted")
	require.Len(t, w.sink.of(event.MFAUnlocked), 1)
	require.ErrorIs(t, w.a.Accounts().UnlockMFA(ctx, admin, uuid.New()), store.ErrNotFound)
}

func TestAccountsRevokeSessionsOnSelfNeedsNoAdminRole(t *testing.T) {
	for name, opt := range map[string]func(*egauth.Config[gateClaims]){"jwt": func(*egauth.Config[gateClaims]) {}, "stateful": stateful} {
		t.Run(name, func(t *testing.T) {
			w := newFacadeWorld(t, opt)
			me, by, mine := w.user("alice@example.com")
			other, _, theirs := w.user("bob@example.com")
			ctx := context.Background()
			require.ErrorIs(t, w.a.Accounts().RevokeSessions(ctx, by, other.User), egauth.ErrForbidden)
			require.NoError(t, w.a.Accounts().RevokeSessions(ctx, by, me.User))
			require.Equal(t, http.StatusUnauthorized, w.status(mine))
			require.Equal(t, http.StatusOK, w.status(theirs))
		})
	}
}

func TestAccountsActOnlyInTheCallersTenant(t *testing.T) {
	w := newFacadeWorld(t, perRequestTenancy)
	w.tenant = "globex"
	victim, _, theirs := w.user("bob@globex.example")
	w.tenant = "acme"
	_, admin, _ := w.admin("root@acme.example")
	ctx := context.Background()
	require.ErrorIs(t, w.a.Accounts().Disable(ctx, admin, victim.User), store.ErrNotFound)
	require.ErrorIs(t, w.a.Accounts().RevokeSessions(ctx, admin, victim.User), store.ErrNotFound)
	w.tenant = "globex"
	require.Equal(t, http.StatusOK, w.status(theirs))
}

func (w *facadeWorld) loginWith(email, password string) credentials {
	w.t.Helper()
	body, err := json.Marshal(map[string]string{"identifier": email, "password": password})
	require.NoError(w.t, err)
	req := httptest.NewRequest(http.MethodPost, gateOrigin+"/auth/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", gateOrigin)
	req.Header.Set("Accept", "application/json")
	rec := w.serve(w.h, req)
	return credentials{cookies: rec.Result().Cookies(), code: rec.Code}
}

func mustEmail(t *testing.T, raw string) identity.Identifier {
	t.Helper()
	id, err := identity.NewIdentifier(identity.IdentifierEmail, raw)
	require.NoError(t, err)
	return id
}
