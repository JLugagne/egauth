package egauth_test

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/memstore"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/ceremony"
)

type dialRecorder struct {
	mu   sync.Mutex
	errs []error
}

func (r *dialRecorder) OutboundStart(*http.Request) func(*http.Response, error) {
	return func(_ *http.Response, err error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.errs = append(r.errs, err)
	}
}

func (r *dialRecorder) failures() []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]error(nil), r.errs...)
}

func journeyConfig(t *testing.T, clk *egauthtest.Clock, idp *egauthtest.IdP) egauth.Config[struct{}] {
	t.Helper()
	cfg := egauthtest.Config[struct{}]()
	cfg.Storage = memstore.NewWithClock(cfg.KEK, clk.Library())
	cfg.Pages.AfterLogin, cfg.Pages.MFA, cfg.Pages.Error = "/home", "/mfa", "/error"
	cfg.Modules.OAuth = &egauth.OAuthModule{Providers: []federation.Provider{{
		Name: "idp", ClientID: idp.ClientID(), ClientSecret: federation.NewSecret(idp.ClientSecret()), Issuer: idp.Issuer(),
	}}}
	return cfg
}

func loopbackAllowance() *egauth.OutboundAllowance {
	return &egauth.OutboundAllowance{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Ack:      egauth.Acknowledge("the fake identity provider listens on loopback"),
	}
}

func TestJourneySeamRunsEveryComponentOnTheTestClock(t *testing.T) {
	clk := egauthtest.NewClock(time.Time{})
	cfg := egauthtest.Config[struct{}]()
	cfg.Storage = memstore.NewWithClock(cfg.KEK, clk.Library())
	a, err := egauthtest.New(cfg, clk, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })

	issuer := egauth.OwnedOf(a).Issuer
	before, err := issuer.Detached(context.Background(), principal.TenantID{})
	require.NoError(t, err)
	require.True(t, before.ExpiresAt().After(clk.Now()))
	require.True(t, before.ExpiresAt().Before(clk.Now().Add(24*time.Hour)), "a pending expires on the test clock, not the wall clock")

	clk.Advance(72 * time.Hour)
	after, err := issuer.Detached(context.Background(), principal.TenantID{})
	require.NoError(t, err)
	require.True(t, after.ExpiresAt().After(clk.Now()))
	require.True(t, after.ExpiresAt().Before(clk.Now().Add(24*time.Hour)))
}

func TestJourneySeamTrustsTheIdPCertificateButNotTheWorld(t *testing.T) {
	clk := egauthtest.NewClock(time.Time{})
	idp := egauthtest.NewIdP(t, clk)

	cfg := journeyConfig(t, clk, idp)
	cfg.Insecure.OutboundPrivateNetwork = loopbackAllowance()
	a, err := egauthtest.New(cfg, clk, idp)
	require.NoError(t, err, "discovery reaches the fake IdP through the outbound client")
	require.NoError(t, a.Close())

	cfg = journeyConfig(t, clk, idp)
	cfg.Insecure.OutboundPrivateNetwork = loopbackAllowance()
	_, err = egauth.New(cfg)
	requireField(t, err, "Modules.OAuth")
}

func TestJourneySeamKeepsTheSSRFGuardInForce(t *testing.T) {
	clk := egauthtest.NewClock(time.Time{})
	idp := egauthtest.NewIdP(t, clk)
	cfg := journeyConfig(t, clk, idp)
	rec := &dialRecorder{}
	cfg.Outbound = rec
	_, err := egauthtest.New(cfg, clk, idp)
	requireField(t, err, "Modules.OAuth")
	var blocked bool
	for _, e := range rec.failures() {
		blocked = blocked || (e != nil && strings.Contains(e.Error(), "blocked address (SSRF guard)"))
	}
	require.True(t, blocked, "the loopback issuer is refused by the dial guard: %v", rec.failures())
}

func TestNewDeliversLinksToAbsolutePagesOnThePublicOrigin(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Pages.PasswordReset = "https://app.example.com/reset"
	cfg.Pages.ConfirmRegistration = "https://app.example.com/register/confirm"
	cfg.Pages.SecurityRevert = "https://admin.app.example.com/revert"
	cfg.Pages.AfterLogin = "https://app.example.com/home"
	a := mustNew(t, cfg)
	for k, want := range map[ceremony.Kind]string{
		ceremony.PasswordReset:       "https://app.example.com/reset?token=h",
		ceremony.PendingRegistration: "https://app.example.com/register/confirm?token=h",
		ceremony.SecurityRevert:      "https://admin.app.example.com/revert?token=h",
	} {
		got, err := egauth.LinkOf(a, core.TenantID{}, k, "h")
		require.NoError(t, err, k)
		require.Equal(t, want, got)
	}
}

func TestNewRequiresTheNoticePathInEveryDeployment(t *testing.T) {
	idp := egauthtest.NewIdP(t, nil)
	for name, modules := range map[string]egauth.Modules{
		"passkey": {Passkey: &egauth.PasskeyModule{DisplayName: "Example"}},
		"oauth":   {OAuth: &egauth.OAuthModule{Providers: []federation.Provider{idp.Provider("idp")}}},
		"sms":     {LoginCode: &egauth.LoginCodeModule{SMS: true}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := minimalConfig(t)
			cfg.Email, cfg.Pages = nil, egauth.Pages{}
			cfg.Modules = modules
			if modules.LoginCode != nil {
				cfg.SMS = &smsStub{}
			}
			err := newErr(t, cfg)
			requireField(t, err, "Email")
			requireField(t, err, "Pages.SecurityRevert")

			cfg.Pages = egauth.Pages{AfterLogin: "/home", MFA: "/mfa", Error: "/error"}
			requireField(t, newErr(t, cfg), "Pages.SecurityRevert")
		})
	}
}

func TestNewRefusesATenantThatCannotFormAHostLabel(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Tenancy = egauth.TenantBySubdomain()
	cfg.PublicOrigin = "https://{tenant}.example.com"
	cfg.ExtraOrigins, cfg.Audiences = nil, nil
	cfg.Pages.PasswordReset = "https://{tenant}.example.com/reset"
	a := mustNew(t, cfg)
	mixed, err := principal.ParseTenantID("Acme")
	require.NoError(t, err)
	_, err = egauth.LinkOf(a, mixed, ceremony.PasswordReset, "h")
	require.Error(t, err, "a mixed-case tenant must not be mapped onto the host of another tenant")
}
