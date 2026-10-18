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

func revertNotices(w *journeytest.World, email string) []egauthtest.Mail {
	var out []egauthtest.Mail
	for _, m := range w.Mailbox.Messages() {
		if m.Kind == "SecurityNotice" && m.To == email && m.RevertLink != "" {
			out = append(out, m)
		}
	}
	return out
}

func TestRevertOfAnEarlierNoticeRemovesThePasskeyAHijackerAddedAfterIt(t *testing.T) {
	w := journeytest.NewWorld(t, journeytest.Settings{})
	email := w.FreshEmail("hijack")
	sub := w.SeedUser(email, false)

	hijacker := w.NewClient()
	hijacker.Login(email, false)
	const hijackerPassword = "hijacker chosen pass phrase 5520!"
	ch := hijacker.Post(egauth.PathPasswordChange, map[string]any{egauth.FieldPassword: journeytest.Password, egauth.FieldNewPassword: hijackerPassword})
	require.Equal(t, http.StatusOK, ch.Status, journeytest.Describe(ch))
	waitFor(t, "password-change notice", func() bool { return len(revertNotices(w, email)) == 1 })
	passwordNotice := revertNotices(w, email)[0]

	w.Clock.Advance(5 * time.Minute)
	hijacker = w.NewClient()
	again := hijacker.LoginPassword(journeytest.Credentials{Email: email, Password: hijackerPassword}, false)
	require.True(t, again.Established(), journeytest.Describe(again))
	key := webauthntest.New(w.Origin)
	begin := hijacker.Post(egauth.PathPasskeyRegisterBegin, nil)
	require.Equal(t, http.StatusOK, begin.Status, journeytest.Describe(begin))
	b := decodeOptions(t, begin)
	finish := hijacker.Post(egauth.PathPasskeyRegisterFinish, mergeFields(t, key.Register(t, b.Options), map[string]any{egauth.FieldHandle: b.Handle}))
	require.Equal(t, http.StatusOK, finish.Status, journeytest.Describe(finish))
	waitFor(t, "passkey-added notice", func() bool { return len(revertNotices(w, email)) == 2 })

	w.Clock.Advance(time.Hour)
	rev := w.NewClient().Post(egauth.PathSecurityRevert, map[string]any{egauth.FieldToken: queryParam(passwordNotice.RevertLink, egauth.FieldToken)})
	require.Equal(t, http.StatusOK, rev.Status, journeytest.Describe(rev))

	creds, err := w.Storage.Passkeys.List(context.Background(), sub)
	require.NoError(t, err)
	require.Empty(t, creds, "the revert of the password change kept the passkey the hijacker added after it")
}
