package journeytest_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/internal/journeytest"
	"github.com/JLugagne/egauth/webauthntest"
)

const mailboxThiefPassword = "tapir-granite-velvet-orbit-29-attacker"

func revertNotice(t *testing.T, w *journeytest.World, email string) egauthtest.Mail {
	t.Helper()
	var notice egauthtest.Mail
	waitFor(t, "a security notice with a revert link", func() bool {
		for _, m := range w.Mailbox.Messages() {
			if m.Kind == "SecurityNotice" && m.To == email && m.RevertLink != "" {
				notice = m
				return true
			}
		}
		return false
	})
	return notice
}

func mailboxThiefSignsIn(t *testing.T, w *journeytest.World, email string, notice egauthtest.Mail) *journeytest.Resp {
	t.Helper()
	thief := w.NewClient()
	resets := w.MailCount("PasswordResetLink")
	rev := thief.Post(egauth.PathSecurityRevert, map[string]any{egauth.FieldToken: queryParam(notice.RevertLink, egauth.FieldToken)})
	require.Equal(t, http.StatusOK, rev.Status, journeytest.Describe(rev))
	if rev.Code() == "account_disabled" {
		forgot := thief.Post(egauth.PathPasswordForgot, map[string]any{egauth.FieldIdentifier: email})
		require.Less(t, forgot.Status, http.StatusInternalServerError, journeytest.Describe(forgot))
		w.Clock.Advance(time.Second)
		time.Sleep(200 * time.Millisecond)
		require.Equal(t, resets, w.MailCount("PasswordResetLink"), "a disabled account received a reset link")
		return thief.LoginPassword(journeytest.Credentials{Email: email, Password: journeytest.Password}, false)
	}
	reset := w.WaitMail("PasswordResetLink", resets+1)
	require.Equal(t, email, reset.To)
	done := thief.Post(egauth.PathPasswordReset, map[string]any{
		egauth.FieldToken: queryParam(reset.Link, egauth.FieldToken), egauth.FieldNewPassword: mailboxThiefPassword,
	})
	require.Equal(t, http.StatusOK, done.Status, journeytest.Describe(done))
	return thief.LoginPassword(journeytest.Credentials{Email: email, Password: mailboxThiefPassword}, false)
}

func TestRevertLinkNeverGivesTheMailboxHolderASessionPastTheSecondFactor(t *testing.T) {
	t.Run("TOTP stripped by its own enrollment notice", func(t *testing.T) {
		w := journeytest.NewWorld(t, journeytest.Settings{})
		email := w.FreshEmail("totp")
		w.SeedUser(email, false)
		owner := w.NewClient()
		owner.Login(email, false)
		enroll := owner.Post(egauth.PathMFATOTPEnroll, nil)
		require.Equal(t, http.StatusOK, enroll.Status, journeytest.Describe(enroll))
		w.Clock.Advance(40 * time.Second)
		confirm := owner.Post(egauth.PathMFATOTPConfirm, map[string]any{egauth.FieldCode: journeytest.TOTPCode(enroll.Field("secret"), w.Clock.Now())})
		require.Equal(t, http.StatusOK, confirm.Status, journeytest.Describe(confirm))
		w.Clock.Advance(72 * time.Hour)
		notice := revertNotice(t, w, email)

		login := mailboxThiefSignsIn(t, w, email, notice)
		require.False(t, login.Established(), "mailbox access alone yielded a session on a TOTP account: "+journeytest.Describe(login))
	})

	t.Run("passkey stripped by its own enrollment notice", func(t *testing.T) {
		w := journeytest.NewWorld(t, journeytest.Settings{})
		email := w.FreshEmail("passkey")
		w.SeedUser(email, false)
		owner := w.NewClient()
		owner.Login(email, false)
		key := webauthntest.New(w.Origin)
		begin := owner.Post(egauth.PathPasskeyRegisterBegin, nil)
		require.Equal(t, http.StatusOK, begin.Status, journeytest.Describe(begin))
		b := decodeOptions(t, begin)
		finish := owner.Post(egauth.PathPasskeyRegisterFinish, mergeFields(t, key.Register(t, b.Options), map[string]any{egauth.FieldHandle: b.Handle}))
		require.Equal(t, http.StatusOK, finish.Status, journeytest.Describe(finish))
		w.Clock.Advance(6 * 24 * time.Hour)
		notice := revertNotice(t, w, email)

		login := mailboxThiefSignsIn(t, w, email, notice)
		require.False(t, login.Established(), "mailbox access alone yielded a session on a passkey account: "+journeytest.Describe(login))
	})

	t.Run("TOTP enrolled after an earlier password-change notice is removed with it", func(t *testing.T) {
		w := journeytest.NewWorld(t, journeytest.Settings{})
		email := w.FreshEmail("anchor")
		sub := w.SeedUser(email, false)
		owner := w.NewClient()
		owner.Login(email, false)
		const ownerPassword = "owner-chosen pass phrase 4471!"
		ch := owner.Post(egauth.PathPasswordChange, map[string]any{egauth.FieldPassword: journeytest.Password, egauth.FieldNewPassword: ownerPassword})
		require.Equal(t, http.StatusOK, ch.Status, journeytest.Describe(ch))
		notice := revertNotice(t, w, email)

		w.Clock.Advance(48 * time.Hour)
		owner = w.NewClient()
		again := owner.LoginPassword(journeytest.Credentials{Email: email, Password: ownerPassword}, false)
		require.True(t, again.Established(), journeytest.Describe(again))
		enroll := owner.Post(egauth.PathMFATOTPEnroll, nil)
		require.Equal(t, http.StatusOK, enroll.Status, journeytest.Describe(enroll))
		w.Clock.Advance(5 * time.Minute)
		confirm := owner.Post(egauth.PathMFATOTPConfirm, map[string]any{egauth.FieldCode: journeytest.TOTPCode(enroll.Field("secret"), w.Clock.Now())})
		require.Equal(t, http.StatusOK, confirm.Status, journeytest.Describe(confirm))
		w.Clock.Advance(24 * time.Hour)

		login := mailboxThiefSignsIn(t, w, email, notice)
		require.False(t, login.Established(), "a revert link of an earlier password-change notice yielded a session past the second factor: "+journeytest.Describe(login))
		confirmed, err := w.Storage.MFA.HasConfirmedTOTP(context.Background(), sub)
		require.NoError(t, err)
		require.False(t, confirmed, "the revert of a password change kept a TOTP enrolled after it")
	})
}
