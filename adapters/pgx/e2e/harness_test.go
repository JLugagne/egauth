package e2e_test

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/adapters/pgx/pgxstore"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/principal"
)

const (
	publicOrigin = "https://example.com"
	e2eTenant    = "tenant-a"
	e2ePassword  = "correct horse battery staple"
)

type fixedTenant struct{ id principal.TenantID }

func (f fixedTenant) ResolveTenant(*http.Request) (principal.TenantID, error) { return f.id, nil }

type e2eClaims struct{}

func (e2eClaims) ClaimsFor(context.Context, principal.Subject) (egauth.AppClaims[struct{}], error) {
	return egauth.AppClaims[struct{}]{Roles: []string{"service"}, Scopes: []string{"report:read"}}, nil
}

type nopEmail struct{}

func (nopEmail) RegistrationLink(context.Context, egauth.LinkMessage) error         { return nil }
func (nopEmail) AccountExistsNotice(context.Context, egauth.NoticeMessage) error    { return nil }
func (nopEmail) PasswordResetLink(context.Context, egauth.LinkMessage) error        { return nil }
func (nopEmail) MagicLink(context.Context, egauth.LinkMessage) error                { return nil }
func (nopEmail) LoginCode(context.Context, egauth.CodeMessage) error                { return nil }
func (nopEmail) EmailVerificationLink(context.Context, egauth.LinkMessage) error    { return nil }
func (nopEmail) EmailChangeLink(context.Context, egauth.LinkMessage) error          { return nil }
func (nopEmail) RecoveryEmailLink(context.Context, egauth.LinkMessage) error        { return nil }
func (nopEmail) SecurityNotice(context.Context, egauth.SecurityNoticeMessage) error { return nil }

func randomKey(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func newKEK(t *testing.T) kek.KEK {
	t.Helper()
	k, err := kek.NewLocal(randomKey(t))
	require.NoError(t, err)
	return k
}

func buildAuth(ctx context.Context, t *testing.T, db pgxstore.DB, k kek.KEK) (*egauth.Auth[struct{}], error) {
	t.Helper()
	return buildAuthWith(ctx, t, db, k, egauth.JWT(egauth.TenantKeys()))
}

func buildAuthWith(ctx context.Context, t *testing.T, db pgxstore.DB, k kek.KEK, sessions egauth.SessionBackend) (*egauth.Auth[struct{}], error) {
	t.Helper()
	st, err := pgxstore.New(ctx, db)
	require.NoError(t, err)
	tenant, err := principal.ParseTenantID(e2eTenant)
	require.NoError(t, err)
	return egauth.New(egauth.Config[struct{}]{
		PublicOrigin: publicOrigin,
		Proxy:        egauth.DirectClients(),
		Tenancy:      egauth.TenantFromRequest(fixedTenant{id: tenant}),
		Storage:      st,
		KEK:          k,
		Sessions:     sessions,
		Transport:    egauth.CookiesAndBearer,
		Admin:        egauth.RoleAdmin("admin"),
		Claims:       e2eClaims{},
		Email:        nopEmail{},
		Pages: egauth.Pages{
			Login: "/login", AfterLogin: "/", MFA: "/mfa", Reauth: "/reauth", Error: "/login",
			ConfirmRegistration: "/register/confirm", PasswordReset: "/reset", SecurityRevert: "/revert",
		},
		Modules: egauth.Modules{
			Password: &egauth.PasswordModule{},
			Passkey:  &egauth.PasskeyModule{DisplayName: "e2e"},
			MFA:      &egauth.MFAModule{},
			APIKeys:  &egauth.APIKeyModule{Kinds: []string{"service"}},
		},
	})
}

func serve(t *testing.T, auth *egauth.Auth[struct{}]) http.Handler {
	t.Helper()
	h, err := auth.Routes().
		Protect("GET /me", func(w http.ResponseWriter, _ *http.Request, p egauth.Principal[struct{}]) {
			_, _ = w.Write([]byte(p.Subject().User.String()))
		}).
		ProtectAPI("GET /api/report", func(w http.ResponseWriter, _ *http.Request, p egauth.Principal[struct{}]) {
			_, _ = w.Write([]byte("report"))
		}, egauth.Kinds("service"), egauth.RequireAnyScope("report:read")).
		Build()
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close() })
	return h
}

type call struct {
	method, path string
	header       http.Header
	body         string
}

func send(h http.Handler, c call) *httptest.ResponseRecorder {
	req := httptest.NewRequest(c.method, publicOrigin+c.path, strings.NewReader(c.body))
	req.Host = "example.com"
	req.Header.Set("Accept", "application/json")
	if c.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.method != http.MethodGet {
		req.Header.Set("Origin", publicOrigin)
	}
	for k, vs := range c.header {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func bearer(token string) http.Header {
	return http.Header{"Authorization": {"Bearer " + token}}
}
