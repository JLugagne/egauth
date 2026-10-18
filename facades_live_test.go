package egauth_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
)

func TestFacadesRefuseTheCallerOfASessionEndedOnThisInstanceAtOnce(t *testing.T) {
	for name, opts := range map[string][]func(*egauth.Config[gateClaims]){"jwt": nil, "stateful": {stateful}} {
		for _, end := range []string{"/auth/logout", "/auth/logout-everywhere"} {
			t.Run(name+end, func(t *testing.T) { callerAfterLogout(t, opts, end) })
		}
	}
}

func callerAfterLogout(t *testing.T, opts []func(*egauth.Config[gateClaims]), end string) {
	w := newFacadeWorld(t, opts...)
	bob := w.seedUser("bob@example.com", false)
	_, admin, c := w.admin("root@example.com")
	ctx := context.Background()
	_, err := w.a.APIKeys().List(ctx, admin)
	require.NoError(t, err)
	rec := w.request(w.h, http.MethodPost, end, c)
	require.Less(t, rec.Code, 400, rec.Body.String())
	err = w.a.Accounts().Disable(ctx, admin, bob.User)
	require.ErrorIs(t, err, egauth.ErrSessionEnded, "a facade served the Caller of a session this instance just ended")
	u, err := w.st.Identity.GetUser(ctx, bob)
	require.NoError(t, err)
	require.True(t, u.DisabledAt.IsZero(), "a Caller of an ended session disabled bob")
}
