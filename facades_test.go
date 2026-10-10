package egauth_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/memstore"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/keys"
)

type facadeWorld struct {
	*gateWorld
	h    http.Handler
	seen *seen
}

func newFacadeWorld(t *testing.T, opts ...func(*egauth.Config[gateClaims])) *facadeWorld {
	t.Helper()
	return wrapFacadeWorld(newGateWorld(t, opts...))
}

func newFacadeWorldWithIdP(t *testing.T, idp func(*egauthtest.Clock) *egauthtest.IdP, opts ...func(*egauth.Config[gateClaims], *egauthtest.IdP)) *facadeWorld {
	t.Helper()
	clk := egauthtest.NewClock(time.Time{})
	p := idp(clk)
	k := testKEK(t)
	built := &gateWorld{t: t, clk: clk, st: memstore.NewWithClock(k, clk.Library()), claims: &ownerClaims{}, sink: &wiringSink{}}
	base := egauth.Config[gateClaims]{
		PublicOrigin: gateOrigin,
		Proxy:        egauth.DirectClients(),
		Storage:      built.st,
		KEK:          k,
		Sessions:     egauth.JWT(egauth.StaticKeys(edSigner(t, "facade-1"))),
		Transport:    egauth.CookiesAndBearer,
		Admin:        egauth.RoleAdmin("admin"),
		Claims:       built.claims,
		Events:       built.sink,
		Email:        &egauthtest.Mailbox{},
		Pages: egauth.Pages{
			Login: "/login", AfterLogin: "/home", MFA: "/mfa", Error: "/error", ConfirmRegistration: "/register/confirm", PasswordReset: "/reset", SecurityRevert: "/revert",
		},
		Modules:  egauth.Modules{Password: &egauth.PasswordModule{}, MFA: &egauth.MFAModule{}},
		Insecure: egauth.InsecureOptOuts{NoRateLimit: egauth.Acknowledge("facade tests")},
	}
	for _, o := range opts {
		o(&base, p)
	}
	built.cfg = base
	a, err := egauthtest.New(base, clk, p)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })
	built.a = a
	return wrapFacadeWorld(built)
}

func wrapFacadeWorld(w *gateWorld) *facadeWorld {
	s := &seen{}
	return &facadeWorld{gateWorld: w, seen: s, h: w.build(w.a.Routes().Protect("GET /whoami", s.handler))}
}

func (w *facadeWorld) caller(email string) (principal.Caller, credentials) {
	w.t.Helper()
	c := w.login(w.h, email, false)
	require.Equal(w.t, http.StatusOK, c.code, c.body)
	rec := w.request(w.h, http.MethodGet, "/whoami", c)
	require.Equal(w.t, http.StatusOK, rec.Code, rec.Body.String())
	return w.seen.last(w.t).Caller(), c
}

func (w *facadeWorld) user(email string) (principal.Subject, principal.Caller, credentials) {
	w.t.Helper()
	sub := w.seedUser(email, false)
	by, c := w.caller(email)
	return sub, by, c
}

func (w *facadeWorld) admin(email string) (principal.Subject, principal.Caller, credentials) {
	w.t.Helper()
	sub := w.seedUser(email, false)
	w.claims.set(sub, egauth.AppClaims[gateClaims]{Roles: []string{"admin", "user"}, Scopes: []string{"items:read", "items:write"}, Groups: []string{"ops"}})
	by, c := w.caller(email)
	return sub, by, c
}

func (w *facadeWorld) system(reason string) principal.Caller {
	w.t.Helper()
	by, err := w.a.System(w.tenantID(), reason)
	require.NoError(w.t, err)
	return by
}

func (w *facadeWorld) apiKeyCaller(owner principal.Subject) principal.Caller {
	w.t.Helper()
	p, err := egauthtest.NewPrincipal[gateClaims](egauthtest.PrincipalSpec{Subject: owner, Machine: &egauth.APIKeyInfo{Kind: "service"}})
	require.NoError(w.t, err)
	return p.Caller()
}

func (w *facadeWorld) status(c credentials) int {
	w.t.Helper()
	w.clk.Advance(revoke.PollBound)
	return w.request(w.h, http.MethodGet, "/whoami", c).Code
}

func (w *facadeWorld) systemUses() []event.Event {
	return w.sink.of(event.SystemCallerUsed)
}

func defaultExpiry() keys.Expiry { return keys.DefaultExpiry() }

type facadeCall struct {
	name string
	call func(ctx context.Context, by principal.Caller) error
}

func (w *facadeWorld) everyFacadeCall(target principal.Subject) []facadeCall {
	tn := w.tenantID()
	return []facadeCall{
		{"Accounts.Create", func(ctx context.Context, by principal.Caller) error {
			_, err := w.a.Accounts().Create(ctx, by, egauth.CreateAccountRequest{Email: "new@example.com"})
			return err
		}},
		{"Accounts.Disable", func(ctx context.Context, by principal.Caller) error {
			return w.a.Accounts().Disable(ctx, by, target.User)
		}},
		{"Accounts.Enable", func(ctx context.Context, by principal.Caller) error {
			return w.a.Accounts().Enable(ctx, by, target.User)
		}},
		{"Accounts.Delete", func(ctx context.Context, by principal.Caller) error {
			return w.a.Accounts().Delete(ctx, by, target.User)
		}},
		{"Accounts.SetTemporaryPassword", func(ctx context.Context, by principal.Caller) error {
			_, err := w.a.Accounts().SetTemporaryPassword(ctx, by, target.User)
			return err
		}},
		{"Accounts.UnlockMFA", func(ctx context.Context, by principal.Caller) error {
			return w.a.Accounts().UnlockMFA(ctx, by, target.User)
		}},
		{"Accounts.RevokeSessions", func(ctx context.Context, by principal.Caller) error {
			return w.a.Accounts().RevokeSessions(ctx, by, target.User)
		}},
		{"APIKeys.Create", func(ctx context.Context, by principal.Caller) error {
			_, err := w.a.APIKeys().Create(ctx, by, egauth.APIKeyRequest{Kind: "service", Lifetime: defaultExpiry()})
			return err
		}},
		{"APIKeys.Revoke", func(ctx context.Context, by principal.Caller) error {
			return w.a.APIKeys().Revoke(ctx, by, target.User)
		}},
		{"APIKeys.List", func(ctx context.Context, by principal.Caller) error {
			_, err := w.a.APIKeys().List(ctx, by)
			return err
		}},
		{"Tenants.Erase", func(ctx context.Context, by principal.Caller) error { return w.a.Tenants().Erase(ctx, by, tn) }},
		{"Tenants.RenewKeys", func(ctx context.Context, by principal.Caller) error {
			return w.a.Tenants().RenewKeys(ctx, by, egauth.RenewKeysRequest{Tenant: tn, Lifetime: defaultExpiry(), Overlap: defaultExpiry()})
		}},
		{"Tenants.ImportKey", func(ctx context.Context, by principal.Caller) error {
			return w.a.Tenants().ImportKey(ctx, by, egauth.ImportKeyRequest{Tenant: tn, KeyID: "k", Alg: "EdDSA", Material: make([]byte, 32)})
		}},
		{"Tenants.RevokeKeys", func(ctx context.Context, by principal.Caller) error { return w.a.Tenants().RevokeKeys(ctx, by, tn) }},
		{"Tenants.SetOAuthProvider", func(ctx context.Context, by principal.Caller) error {
			return w.a.Tenants().SetOAuthProvider(ctx, by, egauth.SetProviderRequest{Tenant: tn, Provider: provider("corp")})
		}},
		{"Tenants.RemoveOAuthProvider", func(ctx context.Context, by principal.Caller) error {
			return w.a.Tenants().RemoveOAuthProvider(ctx, by, egauth.RemoveProviderRequest{Tenant: tn, Name: "corp"})
		}},
	}
}
