package egauth_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/principal"
)

func TestSystemCallerIsRefusedInsideARequestByEveryFacadeMethod(t *testing.T) {
	w := newFacadeWorld(t)
	target := w.seedUser("bob@example.com", false)
	w.seedUser("alice@example.com", false)
	sys := w.system("nightly-sync")
	calls := w.everyFacadeCall(target)
	errs := make(map[string]error, len(calls))
	h := w.build(w.a.Routes().Protect("GET /run", func(rw http.ResponseWriter, r *http.Request, _ egauth.Principal[gateClaims]) {
		for _, c := range calls {
			errs[c.name] = c.call(r.Context(), sys)
		}
		rw.WriteHeader(http.StatusOK)
	}))
	c := w.login(h, "alice@example.com", false)
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/run", c).Code)
	require.Len(t, errs, len(calls))
	for name, err := range errs {
		require.ErrorIs(t, err, egauth.ErrSystemCallerInRequest, name)
	}
	uses := w.systemUses()
	require.Len(t, uses, len(calls), "every refused use is audited")
	for _, u := range uses {
		require.Contains(t, u.Err.Text(), egauth.ErrSystemCallerInRequest.Error())
	}
	u, err := w.st.Identity.GetUser(context.Background(), target)
	require.NoError(t, err)
	require.True(t, u.DisabledAt.IsZero() && u.DeletedAt.IsZero(), "nothing ran")
}

func TestSystemCallerUsedIsEmittedOnEveryUseWithTheReason(t *testing.T) {
	w := newFacadeWorld(t)
	target := w.seedUser("bob@example.com", false)
	sys := w.system("nightly-sync")
	ctx := context.Background()
	require.NoError(t, w.a.Accounts().Disable(ctx, sys, target.User))
	require.NoError(t, w.a.Accounts().Enable(ctx, sys, target.User))
	uses := w.systemUses()
	require.Len(t, uses, 2)
	for i, method := range []string{"Accounts.Disable", "Accounts.Enable"} {
		require.Equal(t, "nightly-sync", uses[i].Reason)
		require.Equal(t, method, uses[i].Attrs[string(event.KeyEndpoint)])
		require.Equal(t, event.SeverityWarn, uses[i].Type.Severity())
	}
}

func TestSystemRefusesAReasonThatIsBlankLongOrNotPrintableASCII(t *testing.T) {
	w := newFacadeWorld(t)
	for _, reason := range []string{"", "   ", strings.Repeat("a", 129), "job\nforged log line", "jöb"} {
		_, err := w.a.System(principal.TenantID{}, reason)
		require.ErrorIs(t, err, egauth.ErrInvalidRequest, "%q", reason)
	}
	_, err := w.a.System(principal.TenantID{}, strings.Repeat("a", 128))
	require.NoError(t, err)
}

func TestSystemRefusesATenantTheTenancyCannotServe(t *testing.T) {
	acme, err := principal.ParseTenantID("acme")
	require.NoError(t, err)
	mixed, err := principal.ParseTenantID("Acme")
	require.NoError(t, err)
	dotted, err := principal.ParseTenantID("acme.corp")
	require.NoError(t, err)

	single := newFacadeWorld(t)
	_, err = single.a.System(acme, "job")
	require.ErrorIs(t, err, egauth.ErrTenantNotServed)
	_, err = single.a.System(principal.TenantID{}, "job")
	require.NoError(t, err)

	perRequest := newFacadeWorld(t, perRequestTenancy)
	_, err = perRequest.a.System(principal.TenantID{}, "job")
	require.ErrorIs(t, err, egauth.ErrTenantNotServed)
	_, err = perRequest.a.System(mixed, "job")
	require.NoError(t, err)

	sub := newGateWorld(t, func(c *egauth.Config[gateClaims]) {
		c.Tenancy = egauth.TenantBySubdomain()
		c.PublicOrigin = "http://{tenant}.localhost:8080"
	})
	for _, bad := range []principal.TenantID{{}, mixed, dotted} {
		_, err = sub.a.System(bad, "job")
		require.ErrorIs(t, err, egauth.ErrTenantNotServed, bad.String())
	}
	_, err = sub.a.System(acme, "job")
	require.NoError(t, err)
}

func TestSystemCallerActsOnlyOnItsOwnTenant(t *testing.T) {
	w := newFacadeWorld(t, perRequestTenancy)
	w.tenant = "globex"
	victim := w.seedUser("bob@globex.example", false)
	w.tenant = "acme"
	sys := w.system("acme-job")
	ctx := context.Background()

	require.ErrorIs(t, w.a.Tenants().Erase(ctx, sys, victim.Tenant), egauth.ErrTenantMismatch)
	err := w.a.Accounts().Disable(ctx, sys, victim.User)
	require.Error(t, err, "the user id resolves in acme, where it does not exist")
	u, err := w.st.Identity.GetUser(ctx, victim)
	require.NoError(t, err)
	require.True(t, u.DisabledAt.IsZero())
}

func TestSystemCallerHasNoAPIKeysAndTheZeroCallerIsRefused(t *testing.T) {
	w := newFacadeWorld(t)
	target := w.seedUser("bob@example.com", false)
	ctx := context.Background()
	_, err := w.a.APIKeys().Create(ctx, w.system("job"), egauth.APIKeyRequest{Kind: "service", Lifetime: defaultExpiry()})
	require.ErrorIs(t, err, egauth.ErrForbidden)
	_, err = w.a.APIKeys().List(ctx, w.system("job"))
	require.ErrorIs(t, err, egauth.ErrForbidden)
	for _, c := range w.everyFacadeCall(target) {
		require.ErrorIs(t, c.call(ctx, principal.Caller{}), egauth.ErrForbidden, c.name)
	}
}
