package journeytest_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/journeytest"
)

func TestTheRevertRevokesTheAPIKeysCreatedSinceItsNoticeAndKeepsTheOwnersOlderKey(t *testing.T) {
	w := journeytest.NewWorld(t, journeytest.Settings{})
	email := w.FreshEmail("revertkey")
	sub := w.SeedUser(email, false)
	ownerKey := w.SeedAPIKey(sub, journeytest.APIKeyKind, []string{"user"}, nil)

	w.Clock.Advance(time.Hour)
	hijacker := w.NewClient()
	hijacker.Login(email, false)
	const hijackerPassword = "hijacker chosen pass phrase 5521!"
	ch := hijacker.Post(egauth.PathPasswordChange, map[string]any{egauth.FieldPassword: journeytest.Password, egauth.FieldNewPassword: hijackerPassword})
	require.Equal(t, http.StatusOK, ch.Status, journeytest.Describe(ch))
	waitFor(t, "password-change notice", func() bool { return len(revertNotices(w, email)) == 1 })
	notice := revertNotices(w, email)[0]

	w.Clock.Advance(5 * time.Minute)
	hijacker = w.NewClient()
	again := hijacker.LoginPassword(journeytest.Credentials{Email: email, Password: hijackerPassword}, false)
	require.True(t, again.Established(), journeytest.Describe(again))
	created := hijacker.Do(journeytest.Req{Method: http.MethodPost, Path: journeytest.FacadeKeyRoute + "?role=user", Remote: hijacker.FreshRemote()})
	require.Equal(t, http.StatusOK, created.Status, journeytest.Describe(created))
	hijackerKey := w.SeedAPIKey(sub, journeytest.APIKeyKind, []string{"user"}, nil)

	w.Clock.Advance(time.Hour)
	rev := w.NewClient().Post(egauth.PathSecurityRevert, map[string]any{egauth.FieldToken: queryParam(notice.RevertLink, egauth.FieldToken)})
	require.Equal(t, http.StatusOK, rev.Status, journeytest.Describe(rev))

	keys, err := w.Storage.Tokens.ListAPIKeys(context.Background(), sub)
	require.NoError(t, err)
	require.Len(t, keys, 3)
	live := 0
	for _, k := range keys {
		if k.RevokedAt.IsZero() {
			live++
		}
	}
	require.Equal(t, 1, live, "only the key created before the notice survives the revert")

	call := func(secret string) int {
		return w.NewClient().Do(journeytest.Req{Method: http.MethodGet, Path: journeytest.APIRoute, NoJar: true,
			Header: http.Header{"Authorization": {"Bearer " + secret}}}).Status
	}
	require.NotEqual(t, http.StatusOK, call(hijackerKey), "the hijacker's key no longer authenticates as the owner")
	require.Equal(t, http.StatusOK, call(ownerKey), "the owner's key from before the notice keeps working")
}
