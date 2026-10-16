package egauth_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/keys"
)

func TestFacadesRefuseAResourceTokenCaller(t *testing.T) {
	w := newRSWorld(t, func(c *egauth.Config[gateClaims]) {
		c.Modules.APIKeys = &egauth.APIKeyModule{Kinds: []string{"pat"}}
	})
	alice := w.seedUser("alice@example.com", false)
	bob := w.seedUser("bob@example.com", false)
	w.claims.set(alice, egauth.AppClaims[gateClaims]{Roles: []string{"admin", "user"}, Scopes: []string{"items:read", "items:write"}})
	tok := w.mint("alice@example.com", rsAudience)

	var by principal.Caller
	var keyErr, disableErr error
	h, err := w.server().Routes().
		Protect("POST /reports", func(rw http.ResponseWriter, r *http.Request, p egauth.Principal[gateClaims]) {
			by = p.Caller()
			_, keyErr = w.a.APIKeys().Create(r.Context(), by, egauth.APIKeyRequest{
				Kind: "pat", Name: "persist", Roles: []string{"admin"}, Scopes: []string{"items:write"}, Lifetime: keys.NeverExpire(),
			})
			disableErr = w.a.Accounts().Disable(r.Context(), by, bob.User)
			rw.WriteHeader(http.StatusOK)
		}).Build()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, w.call(h, http.MethodPost, "/reports", tok).Code)

	require.ErrorIs(t, keyErr, egauth.ErrResourceTokenCaller, "a resource token must not mint an API key through the facade")
	require.ErrorIs(t, disableErr, egauth.ErrResourceTokenCaller, "a resource token must not administer accounts through the facade")
	require.Equal(t, principal.CallerResourceToken, by.Kind(), "a resource token is not a first-party session")
	for _, c := range facadeCalls(w.a, principal.TenantID{}, bob) {
		require.ErrorIs(t, c.call(context.Background(), by), egauth.ErrResourceTokenCaller, c.name)
	}
	u, err := w.st.Identity.GetUser(context.Background(), bob)
	require.NoError(t, err)
	require.True(t, u.DisabledAt.IsZero(), "bob was disabled by a resource-token holder")
	infos, err := w.st.Tokens.ListAPIKeys(context.Background(), alice)
	require.NoError(t, err)
	require.Empty(t, infos, "a resource-token holder minted an API key")
}

func TestFacadesRefuseASessionCallerOnceItsSessionEnded(t *testing.T) {
	backends := map[string][]func(*egauth.Config[gateClaims]){"jwt": nil, "stateful": {stateful}}
	for name, opts := range backends {
		for _, end := range []string{"/auth/logout", "/auth/logout-everywhere"} {
			t.Run(name+end, func(t *testing.T) {
				w := newFacadeWorld(t, opts...)
				bob := w.seedUser("bob@example.com", false)
				_, admin, c := w.admin("root@example.com")
				ctx := context.Background()
				_, err := w.a.APIKeys().List(ctx, admin)
				require.NoError(t, err, "the live session may use the facades")

				rec := w.request(w.h, http.MethodPost, end, c)
				require.Less(t, rec.Code, 400, rec.Body.String())
				require.Equal(t, http.StatusUnauthorized, w.status(c), "the session is gone")

				for _, call := range w.everyFacadeCall(bob) {
					require.ErrorIs(t, call.call(ctx, admin), egauth.ErrSessionEnded, call.name)
				}
				u, err := w.st.Identity.GetUser(ctx, bob)
				require.NoError(t, err)
				require.True(t, u.DisabledAt.IsZero(), "a Caller of an ended session disabled bob")
			})
		}
	}
}

func TestFacadesRefuseASessionCallerBoundToNoStoredSession(t *testing.T) {
	w := newFacadeWorld(t)
	bob := w.seedUser("bob@example.com", false)
	p, err := egauthtest.NewPrincipal[gateClaims](egauthtest.PrincipalSpec{Subject: w.seedUser("root@example.com", false), Roles: []string{"admin"}})
	require.NoError(t, err)
	for _, call := range w.everyFacadeCall(bob) {
		require.ErrorIs(t, call.call(context.Background(), p.Caller()), egauth.ErrSessionEnded, call.name)
	}
}
