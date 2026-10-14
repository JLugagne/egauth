package journeytest_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/journeytest"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/sessions"
	"github.com/JLugagne/egauth/store/tokens"
	"github.com/JLugagne/egauth/webauthntest"
)

func TestScenarioClockPastRecheckEveryLeavesAttrsUnchanged(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		for _, remember := range []bool{true, false} {
			a := newAccount(t, w, s, "recheck")
			sess := a.signIn(remember)
			before := sess.view()
			lineage := sess.lineage()
			for range 3 {
				res := sess.renew()
				require.Less(t, res.Status, http.StatusBadRequest, journeytest.Describe(res))
				require.Equal(t, before, sess.view(), "renewal changed the session attributes")
				require.Equal(t, lineage, sess.lineage(), "renewal changed the lineage")
			}
		}
	})
}

func TestScenarioRememberMeSurvivesEveryRotation(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		for _, remember := range []bool{true, false} {
			a := newAccount(t, w, s, "remember")
			sess := a.signIn(remember)
			initial := map[string]int{}
			for _, k := range sess.login.Cookies {
				if isSessionCookie(k.Name) {
					initial[k.Name] = k.MaxAge
				}
			}
			if !s.bearer {
				require.NotEmpty(t, initial, "a cookies sign-in set no session cookie")
				for name, age := range initial {
					require.Equal(t, remember, age > 0, "cookie %s Max-Age %d at sign-in with remember=%t", name, age, remember)
				}
			}
			for i := range 6 {
				res := sess.renew()
				require.Less(t, res.Status, http.StatusBadRequest, "rotation %d: %s", i, journeytest.Describe(res))
				for _, k := range res.Cookies {
					if !isSessionCookie(k.Name) || k.MaxAge < 0 {
						continue
					}
					want, known := initial[k.Name]
					require.True(t, known, "rotation %d set the unexpected session cookie %s", i, k.Name)
					require.Equal(t, want, k.MaxAge, "rotation %d changed the Max-Age of %s (remember=%t)", i, k.Name, remember)
				}
				require.Equal(t, remember, sess.view().RememberMe, "rotation %d", i)
			}
		}
	})
}

func TestScenarioLogoutKillsTheOldCredentials(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		a := newAccount(t, w, s, "logout")
		sess := a.signIn(false)
		stolen := sess.fork()
		require.Equal(t, http.StatusOK, stolen.status())
		res := sess.post(egauth.PathLogout, map[string]any{})
		require.Less(t, res.Status, http.StatusBadRequest, journeytest.Describe(res))
		if s.backend == journeytest.Stateful {
			require.Equal(t, http.StatusUnauthorized, stolen.status(), "the copied session token still works after logout")
		}
		if s.bearer && s.backend == journeytest.JWT {
			require.Equal(t, http.StatusUnauthorized, stolen.refreshBearer().Status, "the refresh token survived logout")
		}
		settle(w)
		w.Clock.Advance(w.RecheckEvery() + time.Second)
		require.Equal(t, http.StatusUnauthorized, stolen.status(), "the credentials copied before logout still work within PollBound")
		if got, ran := stolen.protect(); got.Status != http.StatusUnauthorized || ran {
			t.Fatalf("a Protect route served the credentials of a logged-out session: %s", journeytest.Describe(got))
		}
	})
}

func TestScenarioLogoutEverywhereWorksFromAStaleSession(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		a := newAccount(t, w, s, "everywhere")
		stale := a.signIn(false)
		other := a.signIn(false)
		w.Clock.Advance(w.ReauthWindow() + time.Minute)
		if s.bearer && s.backend == journeytest.JWT {
			require.Less(t, stale.refreshBearer().Status, http.StatusBadRequest)
			require.Less(t, other.refreshBearer().Status, http.StatusBadRequest)
		}
		sensitive := stale.post(egauth.PathMFATOTPEnroll, nil)
		require.Equal(t, http.StatusForbidden, sensitive.Status, "the session is not stale: "+journeytest.Describe(sensitive))
		res := stale.post(egauth.PathLogoutEverywhere, map[string]any{})
		require.Less(t, res.Status, http.StatusBadRequest, journeytest.Describe(res))
		require.Equal(t, http.StatusUnauthorized, stale.status())
		settle(w)
		require.Equal(t, http.StatusUnauthorized, other.status(), "logout-everywhere left another session alive")
		fresh := a.signIn(false)
		require.Equal(t, http.StatusOK, fresh.status(), "the account can sign in again")
	})
}

func TestScenarioDisableGivesUnauthorizedWithinPollBound(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		a := newAccount(t, w, s, "disable")
		sess := a.signIn(true)
		second := a.signIn(false)
		require.Equal(t, http.StatusOK, sess.status())
		w.SetDisabled(a.Sub, true)
		settle(w)
		for name, x := range map[string]*session{"first": sess, "second": second} {
			require.Equal(t, http.StatusUnauthorized, x.status(), name)
			if got, ran := x.protect(); got.Status != http.StatusUnauthorized || ran {
				t.Fatalf("%s: a Protect route served a disabled account: %s", name, journeytest.Describe(got))
			}
		}
		res := a.w.NewClient().LoginPassword(journeytest.Credentials{Email: a.Email, Password: journeytest.Password}, s.bearer)
		require.Equal(t, http.StatusUnauthorized, res.Status)
		require.False(t, res.Established())
	})
}

type deletionHook struct {
	mu    sync.Mutex
	calls []principal.Subject
}

func (h *deletionHook) accountDeleted(_ context.Context, _ uuid.UUID, s principal.Subject) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, s)
	return nil
}

func (h *deletionHook) subjects() []principal.Subject {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]principal.Subject(nil), h.calls...)
}

func TestScenarioDeleteErasesFactorsCallsTheHookAndRemovesTheTombstone(t *testing.T) {
	for _, s := range shapes() {
		t.Run(s.String(), func(t *testing.T) {
			hook := &deletionHook{}
			set := s.settings().Configure(func(c *egauth.Config[journeytest.Claims]) { c.Hooks.AccountDeleted = hook.accountDeleted })
			w := journeytest.NewWorld(t, set)
			a := newAccount(t, w, s, "delete")
			setup := a.signIn(false)
			secret, _ := setup.c.EnrollTOTP(w)
			sess := a.multiFactorSession(secret)
			sess.registerPasskey(webauthntest.New(w.Origin))
			ctx := context.Background()
			enrolled, err := w.Storage.MFA.HasConfirmedTOTP(ctx, a.Sub)
			require.NoError(t, err)
			require.True(t, enrolled)
			require.True(t, hasPasskey(t, w, a.Sub), "the passkey was not enrolled")

			mark := w.Events.Mark()
			res := sess.post(egauth.PathAccountDelete, map[string]any{})
			require.Equal(t, http.StatusOK, res.Status, journeytest.Describe(res))
			w.Clock.Advance(time.Minute)

			waitFor(t, "the account deleted hook", func() bool { return len(hook.subjects()) > 0 })
			require.Equal(t, []principal.Subject{a.Sub}, hook.subjects()[:1])
			waitFor(t, "the account tombstone to be removed", func() bool {
				_, err := w.Storage.Identity.GetUser(ctx, a.Sub)
				return err != nil
			})
			_, err = w.Storage.Identity.GetUser(ctx, a.Sub)
			require.ErrorIs(t, err, store.ErrNotFound)
			waitFor(t, "the second factors to be erased", func() bool {
				ok, err := w.Storage.MFA.HasConfirmedTOTP(ctx, a.Sub)
				return err == nil && !ok
			})
			_, err = w.Storage.MFA.GetTOTP(ctx, a.Sub)
			require.ErrorIs(t, err, store.ErrNotFound)
			waitFor(t, "the passkeys to be erased", func() bool { return !hasPasskey(t, w, a.Sub) })
			require.Contains(t, w.Events.Since(mark), event.AccountDeleted)
			require.Equal(t, http.StatusUnauthorized, sess.status())
			id, err := identity.NewIdentifier(identity.IdentifierEmail, a.Email)
			require.NoError(t, err)
			_, err = w.Storage.Identity.FindUser(ctx, w.Tenant, id)
			require.ErrorIs(t, err, store.ErrNotFound)
			require.Equal(t, http.StatusUnauthorized, w.NewClient().LoginPassword(journeytest.Credentials{Email: a.Email, Password: journeytest.Password}, s.bearer).Status)
		})
	}
}

func TestScenarioPasswordChangeKillsOtherSessionsAndKeepsTheCurrentOne(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		a := newAccount(t, w, s, "pwchange")
		current := a.signIn(true)
		other := a.signIn(false)
		before := current.view()
		lineage := current.lineage()
		res := current.post(egauth.PathPasswordChange, map[string]any{egauth.FieldPassword: journeytest.Password, egauth.FieldNewPassword: strongPassword})
		require.Equal(t, http.StatusOK, res.Status, journeytest.Describe(res))
		require.Equal(t, "password_changed", res.Code())
		if s.bearer {
			current.c.Bearer = res.Token()
			if rt := res.Refresh(); rt != "" {
				current.refresh = rt
			}
		}
		settle(w)
		if s.bearer && s.backend == journeytest.JWT {
			require.Less(t, current.refreshBearer().Status, http.StatusBadRequest)
		}
		require.Equal(t, http.StatusOK, current.status(), "the session that changed the password died")
		after := current.view()
		require.Equal(t, before.Factors, after.Factors)
		require.Equal(t, before.AMR, after.AMR)
		require.Equal(t, before.RememberMe, after.RememberMe)
		require.Equal(t, lineage, current.lineage(), "the lineage changed")
		require.Equal(t, http.StatusUnauthorized, other.status(), "another session survived the password change")
		old := w.NewClient().LoginPassword(journeytest.Credentials{Email: a.Email, Password: journeytest.Password}, s.bearer)
		require.Equal(t, http.StatusUnauthorized, old.Status)
		fresh := w.NewClient().LoginPassword(journeytest.Credentials{Email: a.Email, Password: strongPassword}, s.bearer)
		require.True(t, fresh.Established(), journeytest.Describe(fresh))
	})
}

func TestScenarioPasswordResetIssuesNoSessionKillsEverySessionAndKeepsFactors(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		a := newAccount(t, w, s, "pwreset")
		setup := a.signIn(false)
		secret, _ := setup.c.EnrollTOTP(w)
		first := a.multiFactorSession(secret)
		second := a.multiFactorSession(secret)
		require.Equal(t, http.StatusOK, first.status())
		first.registerPasskey(webauthntest.New(w.Origin))
		require.True(t, hasPasskey(t, w, a.Sub))

		c, fields := a.forgot()
		res := c.Post(egauth.PathPasswordReset, fields)
		require.Equal(t, http.StatusOK, res.Status, journeytest.Describe(res))
		require.Equal(t, "password_reset", res.Code())
		require.False(t, res.Established(), "the reset issued a session")
		require.False(t, c.HasSessionCookie())
		require.Empty(t, c.Bearer)
		require.Equal(t, http.StatusUnauthorized, c.Session().Status)

		settle(w)
		for name, x := range map[string]*session{"setup": setup, "first": first, "second": second} {
			require.Equal(t, http.StatusUnauthorized, x.status(), "%s survived the password reset", name)
		}
		enrolled, err := w.Storage.MFA.HasConfirmedTOTP(context.Background(), a.Sub)
		require.NoError(t, err)
		require.True(t, enrolled, "the password reset erased the TOTP enrollment")
		require.True(t, hasPasskey(t, w, a.Sub), "the password reset erased the passkeys")
		login := w.NewClient().LoginPassword(journeytest.Credentials{Email: a.Email, Password: strongPassword}, s.bearer)
		require.Equal(t, "mfa_required", login.Code(), "the second factor must still be asked after a reset: "+journeytest.Describe(login))
		require.False(t, login.Established())
	})
}

func TestScenarioLinksRequestedBeforeAnEmailChangeAreDeadAfterIt(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		a := newAccount(t, w, s, "c17")
		resetClient, resetFields := a.forgot()
		magicClient, magicFields := a.magicLink()
		sess := a.signIn(false)
		newEmail := w.FreshEmail("moved")
		res := a.changeEmail(sess, newEmail)
		require.Equal(t, http.StatusOK, res.Status, journeytest.Describe(res))
		require.Equal(t, "email_changed", res.Code())
		settle(w)

		got := resetClient.Post(egauth.PathPasswordReset, resetFields)
		require.GreaterOrEqual(t, got.Status, http.StatusBadRequest, "a reset link requested before the email change still works: "+journeytest.Describe(got))
		require.False(t, got.Established())
		magic := magicClient.Post(egauth.PathMagicLink, magicFields)
		require.GreaterOrEqual(t, magic.Status, http.StatusBadRequest, "a magic link requested before the email change still works: "+journeytest.Describe(magic))
		require.False(t, magic.Established())
		require.Equal(t, http.StatusUnauthorized, w.NewClient().LoginPassword(journeytest.Credentials{Email: a.Email, Password: strongPassword}, s.bearer).Status, "the reset applied despite the refusal")
		moved := w.NewClient().LoginPassword(journeytest.Credentials{Email: newEmail, Password: journeytest.Password}, s.bearer)
		require.True(t, moved.Established(), "the account must sign in with the new email and the old password: "+journeytest.Describe(moved))
	})
}

func TestScenarioIdentifierChangeNotifiesTheOldAddressAndRevertWorks(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		a := newAccount(t, w, s, "revert")
		sess := a.signIn(false)
		newEmail := w.FreshEmail("attacker")
		require.Equal(t, http.StatusOK, a.changeEmail(sess, newEmail).Status)

		var notice egauthtest.Mail
		waitFor(t, "the security notice to the old address", func() bool {
			for _, m := range w.Mailbox.Messages() {
				if m.Kind == "SecurityNotice" && m.To == a.Email && m.RevertLink != "" {
					notice = m
					return true
				}
			}
			return false
		})
		for _, m := range w.Mailbox.Messages() {
			if m.Kind == "SecurityNotice" {
				require.NotEqual(t, newEmail, m.To, "the notice went to the new address")
			}
		}
		u, err := w.Storage.Identity.GetUser(context.Background(), a.Sub)
		require.NoError(t, err)
		require.Equal(t, newEmail, u.Email.Value())

		stranger := w.NewClient()
		res := stranger.Post(egauth.PathSecurityRevert, map[string]any{egauth.FieldToken: queryParam(notice.RevertLink, egauth.FieldToken)})
		require.Equal(t, http.StatusOK, res.Status, journeytest.Describe(res))
		require.Equal(t, "security_reverted", res.Code())
		u, err = w.Storage.Identity.GetUser(context.Background(), a.Sub)
		require.NoError(t, err)
		require.Equal(t, a.Email, u.Email.Value(), "the revert did not restore the old address")
		require.Equal(t, http.StatusUnauthorized, w.NewClient().LoginPassword(journeytest.Credentials{Email: newEmail, Password: journeytest.Password}, s.bearer).Status)
		again := w.NewClient().Post(egauth.PathSecurityRevert, map[string]any{egauth.FieldToken: queryParam(notice.RevertLink, egauth.FieldToken)})
		require.GreaterOrEqual(t, again.Status, http.StatusBadRequest, "a revert link is single use: "+journeytest.Describe(again))
	})
}

func TestScenarioTOTPEnrollmentKillsOtherSessionsAndKeepsTheSensitiveGateClosed(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		a := newAccount(t, w, s, "enroll")
		enrolling := a.signIn(false)
		other := a.signIn(false)
		lineage := enrolling.lineage()
		secret := enrolling.enrollTOTP()
		settle(w)
		if s.bearer && s.backend == journeytest.JWT {
			require.Less(t, enrolling.refreshBearer().Status, http.StatusBadRequest)
		}
		require.Equal(t, http.StatusUnauthorized, other.status(), "another session survived the enrollment")
		require.Equal(t, http.StatusOK, enrolling.status(), "the enrolling session died")
		require.Equal(t, lineage, enrolling.lineage())

		gate := func() *journeytest.Resp {
			return enrolling.post(egauth.PathEmailChange, map[string]any{egauth.FieldEmail: w.FreshEmail("gate")})
		}
		res := gate()
		require.Equal(t, http.StatusForbidden, res.Status, journeytest.Describe(res))
		require.Equal(t, "reauth_required", res.Code(), "enrollment alone satisfied the sensitive gate")

		reauth := enrolling.post(egauth.PathReauth, map[string]any{egauth.FieldPassword: journeytest.Password})
		require.Equal(t, "mfa_required", reauth.Code(), journeytest.Describe(reauth))
		stillClosed := gate()
		require.Equal(t, http.StatusForbidden, stillClosed.Status, "a password-only reauth opened the gate of an enrolled account: "+journeytest.Describe(stillClosed))

		w.Clock.Advance(30 * time.Second)
		verify := enrolling.post(egauth.PathReauth, map[string]any{
			egauth.FieldPassword: journeytest.Password, egauth.FieldFactor: "totp", egauth.FieldCode: journeytest.TOTPCode(secret, w.Clock.Now()),
		})
		require.Less(t, verify.Status, http.StatusBadRequest, journeytest.Describe(verify))
		enrolling.adopt(verify)
		settle(w)
		open := gate()
		require.Equal(t, http.StatusAccepted, open.Status, "re-verification did not open the sensitive gate: "+journeytest.Describe(open))
	})
}

func TestScenarioMustChangeSessionIsHeldUntilThePasswordChanges(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		email := w.FreshEmail("must")
		w.SeedUser(email, true)
		a := &account{w: w, s: s, t: t, Email: email}
		sess := a.signIn(false)
		got, ran := sess.protect()
		require.Equal(t, http.StatusForbidden, got.Status, journeytest.Describe(got))
		require.Equal(t, "password_change_required", got.Code())
		require.False(t, ran, "a Protect handler served a must-change session")
		require.True(t, sess.view().PasswordChangeRequired, "GET /session must report the pending password change")

		wrong := sess.post(egauth.PathPasswordChange, map[string]any{egauth.FieldPassword: "not the password", egauth.FieldNewPassword: strongPassword})
		require.Equal(t, http.StatusUnauthorized, wrong.Status, journeytest.Describe(wrong))
		got, ran = sess.protect()
		require.Equal(t, http.StatusForbidden, got.Status, "a refused change released the session: "+journeytest.Describe(got))
		require.False(t, ran)
		require.True(t, sess.view().PasswordChangeRequired)

		res := sess.post(egauth.PathPasswordChange, map[string]any{egauth.FieldPassword: journeytest.Password, egauth.FieldNewPassword: strongPassword})
		require.Equal(t, http.StatusOK, res.Status, journeytest.Describe(res))
		if s.bearer {
			sess.c.Bearer = res.Token()
		}
		settle(w)
		require.False(t, sess.view().PasswordChangeRequired)
		got, ran = sess.protect()
		require.Equal(t, http.StatusOK, got.Status, journeytest.Describe(got))
		require.True(t, ran)
		fresh := w.NewClient().LoginPassword(journeytest.Credentials{Email: email, Password: strongPassword}, s.bearer)
		require.True(t, fresh.Established())
	})
}

func TestScenarioReturnToSurvivesEveryCeremony(t *testing.T) {
	for _, carrier := range []journeytest.Carrier{journeytest.Cookies, journeytest.Bearer} {
		for _, p := range journeytest.Primaries() {
			cell := journeytest.Cell{Primary: p, MFA: journeytest.MFANone, Backend: journeytest.Stateful, Carrier: carrier, Tenancy: journeytest.Single}
			t.Run(cell.String(), func(t *testing.T) {
				if _, skipped := journeytest.Exempted(cell); skipped {
					t.Skip("exempt cell")
				}
				for _, remember := range []bool{true, false} {
					r, c := journeytest.EstablishCellRemembering(t, cell, remember)
					res := c.Session()
					require.Equal(t, http.StatusOK, res.Status, journeytest.Describe(res))
					require.Equal(t, journeytest.JourneyReturnTo, res.Field("return_to"), "ceremony %s lost return_to", p)
					r.World.Clock.Advance(r.World.RecheckEvery() + time.Second)
					res = c.Session()
					require.Equal(t, http.StatusOK, res.Status, journeytest.Describe(res))
					require.Equal(t, journeytest.JourneyReturnTo, res.Field("return_to"), "renewal lost return_to")
				}
			})
		}
	}
}

func TestScenarioReturnToSurvivesTheMultiFactorDetour(t *testing.T) {
	for _, mfa := range []journeytest.MFA{journeytest.MFATOTP, journeytest.MFARecoveryCode, journeytest.MFAPasskeyStepUp} {
		cell := journeytest.Cell{Primary: journeytest.PrimaryPassword, MFA: mfa, Backend: journeytest.JWT, Carrier: journeytest.Cookies, Tenancy: journeytest.Single}
		t.Run(cell.String(), func(t *testing.T) {
			_, c := journeytest.EstablishCell(t, cell)
			require.Equal(t, journeytest.JourneyReturnTo, c.Session().Field("return_to"))
		})
	}
}

func TestScenarioATenantCredentialOnAnotherTenantHostIsRefused(t *testing.T) {
	for _, s := range shapes() {
		t.Run(s.String(), func(t *testing.T) {
			set := s.settings()
			set.Tenancy = journeytest.Subdomain
			w := journeytest.NewWorld(t, set)
			a := newAccount(t, w, s, "tenant")
			sess := a.signIn(false)
			require.Equal(t, http.StatusOK, sess.status())
			foreign := journeytest.OtherTenant + "." + journeytest.BaseDomain
			for _, path := range []string{"/auth" + egauth.PathSession, journeytest.ProtectRoute, journeytest.OptionalRoute} {
				before := w.Seen.Count()
				res := sess.c.Do(journeytest.Req{Path: path, Host: foreign})
				ranAnonymous := false
				if p, ok := w.Seen.Last(); ok && w.Seen.Count() > before {
					ranAnonymous = p.Kind() == egauth.Anonymous
				}
				if path == journeytest.OptionalRoute {
					require.True(t, res.Status == http.StatusUnauthorized || ranAnonymous, "%s on another tenant host: %s", path, journeytest.Describe(res))
					continue
				}
				require.Equal(t, http.StatusUnauthorized, res.Status, "%s on another tenant host: %s", path, journeytest.Describe(res))
				require.Equal(t, before, w.Seen.Count(), "%s ran a handler for a foreign credential", path)
			}
			settle(w)
			require.Equal(t, http.StatusOK, sess.status(), "the refused cross-tenant requests killed the credential on its own host")
			if s.backend == journeytest.JWT {
				w.Clock.Advance(w.RecheckEvery() + time.Second)
				res := sess.c.Do(journeytest.Req{Path: "/auth" + egauth.PathSession, Host: foreign})
				require.Equal(t, http.StatusUnauthorized, res.Status, "a renewal on another tenant host must be refused: "+journeytest.Describe(res))
			}
		})
	}
}

type tenantErasedHook struct {
	mu      sync.Mutex
	tenants []principal.TenantID
}

func (h *tenantErasedHook) erased(_ context.Context, _ uuid.UUID, t principal.TenantID) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tenants = append(h.tenants, t)
	return nil
}

func (h *tenantErasedHook) seen() []principal.TenantID {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]principal.TenantID(nil), h.tenants...)
}

func TestScenarioTenantsEraseRemovesTheTenantAndNothingElse(t *testing.T) {
	for _, backend := range []journeytest.Backend{journeytest.JWT, journeytest.Stateful} {
		t.Run(backend.String(), func(t *testing.T) {
			hook := &tenantErasedHook{}
			s := shape{backend: backend}
			set := s.settings()
			set.Tenancy = journeytest.Subdomain
			set = set.Configure(func(c *egauth.Config[journeytest.Claims]) { c.Hooks.TenantErased = hook.erased })
			w := journeytest.NewWorld(t, set)
			ctx := context.Background()

			a := newAccount(t, w, s, "erased")
			setup := a.signIn(false)
			secret := setup.enrollTOTP()
			sess := a.multiFactorSession(secret)
			require.Equal(t, http.StatusOK, sess.status())
			sess.registerPasskey(webauthntest.New(w.Origin))
			require.True(t, hasPasskey(t, w, a.Sub))

			otherTenant, err := principal.ParseTenantID(journeytest.OtherTenant)
			require.NoError(t, err)
			neighbour := seedForeignAccount(t, w, otherTenant, w.FreshEmail("neighbour"))
			neighbourClient := w.NewClient()
			neighbourClient.Host, neighbourClient.Origin = journeytest.OtherTenant+"."+journeytest.BaseDomain, "https://"+journeytest.OtherTenant+"."+journeytest.BaseDomain
			login := neighbourClient.LoginPassword(journeytest.Credentials{Email: neighbour.email, Password: journeytest.Password}, false)
			require.True(t, login.Established(), journeytest.Describe(login))

			sys, err := w.Auth.System(w.Tenant, "scenario: erase the tenant")
			require.NoError(t, err)
			require.NoError(t, w.Auth.Tenants().Erase(ctx, sys, w.Tenant))
			settle(w)

			waitFor(t, "the TenantErased hook", func() bool { return len(hook.seen()) > 0 })
			require.Equal(t, []principal.TenantID{w.Tenant}, hook.seen()[:1])
			for name, x := range map[string]*session{"setup": setup, "multi-factor": sess} {
				require.Equal(t, http.StatusUnauthorized, x.status(), "%s session survived the tenant erasure", name)
			}
			waitFor(t, "the accounts of the tenant to be erased", func() bool {
				_, err := w.Storage.Identity.GetUser(ctx, a.Sub)
				return errors.Is(err, store.ErrNotFound)
			})
			enrolled, err := w.Storage.MFA.HasConfirmedTOTP(ctx, a.Sub)
			require.NoError(t, err)
			require.False(t, enrolled, "the second factor outlived its tenant")
			require.False(t, hasPasskey(t, w, a.Sub), "the passkeys outlived their tenant")
			res := w.NewClient().LoginPassword(journeytest.Credentials{Email: a.Email, Password: journeytest.Password}, false)
			require.False(t, res.Established(), "an erased tenant accepted a login: "+journeytest.Describe(res))

			_, err = w.Storage.Identity.GetUser(ctx, neighbour.subject)
			require.NoError(t, err, "the erasure removed an account of another tenant")
			require.Equal(t, http.StatusOK, neighbourClient.Session().Status, "the erasure killed a session of another tenant")
		})
	}
}

type foreignAccount struct {
	email   string
	subject principal.Subject
}

func seedForeignAccount(t testing.TB, w *journeytest.World, tenant principal.TenantID, email string) foreignAccount {
	t.Helper()
	ctx := context.Background()
	phc, err := argon2.NewHasher().Hash(ctx, journeytest.Password)
	require.NoError(t, err)
	id, err := identity.NewIdentifier(identity.IdentifierEmail, email)
	require.NoError(t, err)
	applied, err := w.Storage.Identity.Apply(ctx, identity.CreateVerified{Tenant: tenant, Email: id, PHC: identity.NewPasswordHash(phc)})
	require.NoError(t, err)
	return foreignAccount{email: email, subject: applied.Subject}
}

type flakyMailer struct {
	*egauthtest.Mailbox
	failing  atomic.Bool
	attempts atomic.Int32
}

func (f *flakyMailer) SecurityNotice(ctx context.Context, n egauth.SecurityNoticeMessage) error {
	f.attempts.Add(1)
	if f.failing.Load() {
		return errors.New("injected subscriber failure")
	}
	return f.Mailbox.SecurityNotice(ctx, n)
}

type failingTokens struct {
	tokens.Store
	calls atomic.Int32
}

func (f *failingTokens) RevokeForSubject(context.Context, principal.Subject, uuid.UUID) error {
	f.calls.Add(1)
	return errors.New("injected token revocation failure")
}

type failingSessions struct {
	sessions.Store
	calls atomic.Int32
}

func (f *failingSessions) RevokeForSubject(context.Context, principal.Subject, uuid.UUID) error {
	f.calls.Add(1)
	return errors.New("injected session revocation failure")
}

type failingCeremonies struct {
	ceremony.Store
	calls atomic.Int32
}

func (f *failingCeremonies) DeleteForScope(context.Context, principal.TenantID, []byte, ...ceremony.Kind) (int64, error) {
	f.calls.Add(1)
	return 0, errors.New("injected ceremony purge failure")
}

func TestScenarioFailingSubscribersDoNotKeepSessionsAliveAfterAPasswordReset(t *testing.T) {
	for _, s := range shapes() {
		t.Run(s.String(), func(t *testing.T) {
			flaky := &flakyMailer{}
			flaky.failing.Store(true)
			toks, sess, cer := &failingTokens{}, &failingSessions{}, &failingCeremonies{}
			w := journeytest.NewWorld(t, s.settings().Configure(func(c *egauth.Config[journeytest.Claims]) {
				c.Email = flaky
				if c.Storage.Tokens != nil {
					toks.Store = c.Storage.Tokens
					c.Storage.Tokens = toks
				}
				if c.Storage.Sessions != nil {
					sess.Store = c.Storage.Sessions
					c.Storage.Sessions = sess
				}
				cer.Store = c.Storage.Ceremonies
				c.Storage.Ceremonies = cer
			}))
			flaky.Mailbox = w.Mailbox
			a := newAccount(t, w, s, "flaky")
			first, second := a.signIn(true), a.signIn(false)
			require.Equal(t, http.StatusOK, first.status())

			c, fields := a.forgot()
			res := c.Post(egauth.PathPasswordReset, fields)
			require.Equal(t, http.StatusOK, res.Status, journeytest.Describe(res))
			waitFor(t, "the failing notice subscriber to be called", func() bool { return flaky.attempts.Load() > 0 })
			waitFor(t, "the failing revocation subscribers to be called", func() bool { return toks.calls.Load()+sess.calls.Load() > 0 })
			require.Empty(t, notices(w, a.Email), "the injected failure did not fail the notice")

			settle(w)
			require.Equal(t, http.StatusUnauthorized, first.status(), "a session survived the reset while the notice subscriber failed")
			require.Equal(t, http.StatusUnauthorized, second.status())
			login := w.NewClient().LoginPassword(journeytest.Credentials{Email: a.Email, Password: strongPassword}, s.bearer)
			require.True(t, login.Established(), journeytest.Describe(login))
		})
	}
}

func notices(w *journeytest.World, to string) []egauthtest.Mail {
	var out []egauthtest.Mail
	for _, m := range w.Mailbox.Messages() {
		if m.Kind == "SecurityNotice" && m.To == to {
			out = append(out, m)
		}
	}
	return out
}
