package journeytest_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/journeytest"
	"github.com/JLugagne/egauth/internal/journeytest/testdata"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/memstore"
	"github.com/JLugagne/egauth/signing"
)

var requiredFamilies = []string{
	"csrf/cross-origin-with-cookie", "csrf/null-origin-with-cookie", "csrf/no-origin-no-referer-with-cookie",
	"csrf/same-site-fetch-with-cookie", "csrf/cross-site-get-with-cookie", "csrf/login-cross-origin-no-cookie",
	"csrf/user-cross-origin-with-cookie", "csrf/user-cross-site-get-with-cookie",
	"csrf/user-cross-site-get-with-valid-cookie", "csrf/user-same-origin-get-with-valid-cookie",
	"ceremony-binding/oauth-callback-without-bind", "ceremony-binding/oauth-callback-with-bind-passes-the-bind-check", "ceremony-binding/magic-link-consumed-without-bind",
	"limits/body-cap-plus-one", "limits/body-cap-exact", "limits/client-burst-plus-one", "limits/identifier-burst-plus-one", "limits/session-burst-plus-one/cookie", "limits/session-burst-plus-one/bearer",
	"limits/forwarded-clients-behind-trusted-proxies-have-independent-buckets",
	"session-state/mfa-flow-handle-as-session", "session-state/must-change", "session-state/disabled-subject", "session-state/epoch-stale",
	"sensitive/stale-primary-at/cookie", "sensitive/stale-primary-at/bearer",
	"sensitive/password-only-reauth-on-mfa-session/cookie", "sensitive/password-only-reauth-on-mfa-session/bearer",
	"sensitive/enrolled-without-multifactor/cookie", "sensitive/enrolled-without-multifactor/bearer",
	"tenancy/valid-credential-on-unresolvable-tenant", "tenancy/magic-link-token-of-another-tenant", "tenancy/password-reset-token-of-another-tenant",
	"tenancy/registration-token-of-another-tenant", "tenancy/oauth-state-of-another-tenant",
	"tenancy/unresolvable-tenant", "tenancy/code-handle-of-another-tenant", "tenancy/mfa-flow-handle-of-another-tenant",
	"credential-kind/api-key-on-session-route", "credential-kind/session-on-api-route",
	"facades/system-caller-inside-a-protect-handler", "facades/non-admin-disables-another-user",
	"facades/api-key-caller-on-a-facade", "facades/key-with-roles-beyond-the-callers",
	"redirects/" + egauth.PathLogin, "redirects/" + egauth.PathMagicLinkRequest, "redirects/" + egauth.PathRegister,
	"deny-by-default/unknown-path",
}

func hasFamily(names []string, family string) bool {
	for _, n := range names {
		if strings.HasPrefix(n, family+"/") || n == family {
			return true
		}
	}
	return false
}

func TestProbesCoverTheDesignTable(t *testing.T) {
	for _, b := range []journeytest.Backend{journeytest.JWT, journeytest.Stateful} {
		t.Run(b.String(), func(t *testing.T) {
			w := journeytest.NewWorld(t, journeytest.Settings{Backend: b})
			e := newEnv(w)
			served := map[string]bool{}
			for _, tg := range e.targets {
				if tg.kind == kAuth {
					served[tg.registry] = true
				}
			}
			for _, p := range routes.All() {
				if (p == routes.JWKS || p == routes.ResourceToken) && b == journeytest.Stateful {
					require.False(t, served[p], "%s is served under the stateful backend", p)
					continue
				}
				require.True(t, served[p], "%s is not served by the fully enabled Auth, so no probe covers it", p)
			}
			var names []string
			for _, p := range worldProbes(w) {
				names = append(names, p.Name)
			}
			for _, f := range requiredFamilies {
				require.True(t, hasFamily(names, f), "no probe of family %s", f)
			}
		})
	}
}

func onlyFamilies(ps []journeytest.Probe, families ...string) []journeytest.Probe {
	var out []journeytest.Probe
	for _, p := range ps {
		for _, f := range families {
			if strings.HasPrefix(p.Name, f+"/") {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

func TestProbesCrossSiteLoginUnderEveryTransport(t *testing.T) {
	for _, tr := range []egauth.Transport{egauth.Cookies, egauth.Bearer, egauth.CookiesAndBearer} {
		t.Run(transportLabel(tr), func(t *testing.T) {
			w := journeytest.NewWorld(t, journeytest.Settings{Transport: tr})
			ps := onlyFamilies(worldProbes(w), "csrf/login-cross-origin-no-cookie", "csrf/login-null-origin-no-cookie", "csrf/login-no-origin-no-cookie")
			require.NotEmpty(t, ps, "the cross-site login probe must run under every Transport")
			journeytest.Collect(ps).Check(t)
		})
	}
}

func transportLabel(t egauth.Transport) string {
	switch t {
	case egauth.Cookies:
		return "cookies"
	case egauth.Bearer:
		return "bearer"
	}
	return "cookies-and-bearer"
}

func TestProbesHaveTeeth(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*egauth.Config[journeytest.Claims])
		families []string
	}{
		{"no-origin-check", func(c *egauth.Config[journeytest.Claims]) { c.Insecure.NoOriginCheck = egauth.Acknowledge("teeth") }, []string{"csrf/cross-origin-with-cookie", "csrf/login-cross-origin-no-cookie", "csrf/user-cross-origin-with-cookie", "csrf/user-cross-site-get-with-valid-cookie"}},
		{"no-rate-limit", func(c *egauth.Config[journeytest.Claims]) { c.Insecure.NoRateLimit = egauth.Acknowledge("teeth") }, []string{"limits/client-burst-plus-one", "limits/identifier-burst-plus-one", "limits/session-burst-plus-one/cookie", "limits/session-burst-plus-one/bearer"}},
		{"no-reauth-window", func(c *egauth.Config[journeytest.Claims]) { c.Insecure.NoReauthWindow = egauth.Acknowledge("teeth") }, []string{"sensitive/stale-primary-at/cookie", "sensitive/stale-primary-at/bearer"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := journeytest.NewWorld(t, journeytest.Settings{}.Configure(tc.mutate))
			rep := journeytest.Collect(onlyFamilies(worldProbes(w), tc.families...))
			require.NotEmpty(t, rep)
			var failing []string
			for _, f := range rep.Failed() {
				require.False(t, f.Control, "control %s failed: the variant broke the harness, not a security control", f.Name)
				failing = append(failing, f.Name)
			}
			for _, f := range tc.families {
				require.True(t, hasFamily(failing, f), "no probe of %s failed under %s", f, tc.name)
			}
		})
	}
}

func TestProdConfigPosture(t *testing.T) {
	clk := egauthtest.NewClock(egauthtest.ReferenceTime())
	sum := sha256.Sum256([]byte("prod config posture kek"))
	k, err := kek.NewLocal(sum[:])
	require.NoError(t, err)
	seed := sha256.Sum256([]byte("prod config posture signer"))
	signer, err := signing.EdDSA("prod-1", seed[:])
	require.NoError(t, err)
	cfg := testdata.ProdConfig(testdata.Deps[journeytest.Claims]{
		Origin:    "https://{tenant}.example.com",
		Tenancy:   egauth.TenantBySubdomain(),
		Sessions:  egauth.JWT(egauth.StaticKeys(signer)),
		Transport: egauth.CookiesAndBearer,
		Audiences: []string{journeytest.AudienceOne},
		Storage:   journeytest.SharedStorage(memstore.NewWithClock(k, clk.Library())),
		KEK:       k,
		Events:    event.Discard,
		Email:     &egauthtest.Mailbox{},
		Providers: []federation.Provider{egauthtest.NewIdP(t, clk).Provider("idp")},
		Verifiers: []egauth.ExternalFactor{refusingFactor{}},
		AdminRole: journeytest.AdminRole,
		APIKinds:  []string{journeytest.APIKeyKind},
	})
	a, err := egauthtest.New(cfg, clk, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })
	require.Empty(t, a.Posture().OptOuts, "the golden production configuration must set no Insecure opt-out")
	require.Equal(t, cfg.Insecure, egauth.InsecureOptOuts{})
}

type refusingFactor struct{}

func (refusingFactor) Name() string { return "directory" }

func (refusingFactor) Verify(context.Context, egauth.ExternalRequest) (egauth.ExternalIdentity, error) {
	return egauth.ExternalIdentity{}, errors.New("refused")
}

func TestEveryWorldStartsWithoutOptOuts(t *testing.T) {
	for _, b := range []journeytest.Backend{journeytest.JWT, journeytest.Stateful} {
		w := journeytest.NewWorld(t, journeytest.Settings{Backend: b})
		require.Empty(t, w.Auth.Posture().OptOuts, b.String())
	}
}

func TestProbesAreDerivedFromEndpointMeta(t *testing.T) {
	w := journeytest.NewWorld(t, journeytest.Settings{})
	names := map[string]bool{}
	for _, p := range worldProbes(w) {
		names[p.Name] = true
	}
	has := func(family, label string) bool { return names[family+"/"+label] }
	for _, tg := range newEnv(w).targets {
		if tg.kind != kAuth {
			continue
		}
		m, l := tg.meta, tg.label()
		require.Equal(t, m.Mutation, has("csrf/cross-origin-with-cookie", l), "cross-origin probe of %s follows Meta.Mutation", l)
		require.Equal(t, m.Mutation, has("limits/body-cap-plus-one", l), "body cap probe of %s follows Meta.Mutation", l)
		require.Equal(t, !m.Mutation && m.Authenticated, has("csrf/cross-site-get-with-cookie", l), "cross-site GET probe of %s follows Meta", l)
		require.Equal(t, m.Mutation && m.SetsCookies, has("csrf/login-cross-origin-no-cookie", l), "login CSRF probe of %s follows Meta.SetsCookies", l)
		require.Equal(t, m.ClientLimit != 0, has("limits/client-burst-plus-one", l), "client burst probe of %s follows Meta.ClientLimit", l)
		require.Equal(t, m.IdentifierKeyed, has("limits/identifier-burst-plus-one", l), "identifier burst probe of %s follows Meta.IdentifierKeyed", l)
		require.Equal(t, m.Sensitive, has("sensitive/stale-primary-at/cookie", l), "sensitive probe of %s follows Meta.Sensitive", l)
		require.Equal(t, m.Authenticated, has("session-state/disabled-subject/cookie", l), "session-state probes of %s follow Meta.Authenticated", l)
		require.Equal(t, m.Authenticated, has("credential-kind/api-key-on-session-route", l), "credential-kind probes of %s follow Meta.Authenticated", l)
	}
}

func TestProbesRunAgainstAServer(t *testing.T) {
	journeytest.RunAgainst(t, func(_ *slog.Logger, origin string) (http.Handler, func() error, error) {
		sum := sha256.Sum256([]byte("run against kek"))
		k, err := kek.NewLocal(sum[:])
		if err != nil {
			return nil, nil, err
		}
		seed := sha256.Sum256([]byte("run against signer"))
		signer, err := signing.EdDSA("ra-1", seed[:])
		if err != nil {
			return nil, nil, err
		}
		auth, err := egauth.New(egauth.Config[struct{}]{
			PublicOrigin: origin,
			Proxy:        egauth.DirectClients(),
			Storage:      memstore.New(k),
			KEK:          k,
			Sessions:     egauth.JWT(egauth.StaticKeys(signer)),
			Admin:        egauth.SelfServiceOnly(),
			Email:        &egauthtest.Mailbox{},
			Pages:        egauth.Pages{Login: "/login", ConfirmRegistration: "/register/confirm", PasswordReset: "/reset", SecurityRevert: "/revert", MFA: "/mfa"},
			Modules:      egauth.Modules{Password: &egauth.PasswordModule{}, MFA: &egauth.MFAModule{}},
		})
		if err != nil {
			return nil, nil, err
		}
		h, err := auth.Routes().Public("GET /healthz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).Build()
		if err != nil {
			return nil, nil, errors.Join(err, auth.Close())
		}
		return h, auth.Close, nil
	})
}

func TestEveryEndpointDecidesWhetherItTakesAReturnTo(t *testing.T) {
	takes := map[string]bool{}
	for _, p := range returnToCeremonies {
		takes[p] = true
	}
	notReturnTo := map[string]bool{}
	for _, p := range []string{
		routes.Session, routes.Logout, routes.LogoutEverywhere, routes.Reauth, routes.Refresh, routes.Exchange, routes.ResourceToken,
		routes.JWKS, routes.RegisterConfirm, routes.PasswordReset, routes.PasswordChange, routes.MagicLink,
		routes.CodeVerify, routes.PasskeyLoginFinish, routes.PasskeyRegisterFinish, routes.PasskeyCredentials,
		routes.PasskeyCredentialsRename, routes.PasskeyCredentialsDelete, routes.OAuthCallback, routes.MFAChallenge,
		routes.MFAPasskeyBegin, routes.MFAPasskeyFinish, routes.MFATOTPEnroll, routes.MFATOTPConfirm, routes.MFATOTPDisable,
		routes.MFARecoveryCodesRegenerate, routes.EmailVerify, routes.EmailChangeConfirm,
		routes.PhoneVerify, routes.RecoveryEmailConfirm, routes.AccountDelete,
	} {
		notReturnTo[p] = true
	}
	for _, p := range routes.All() {
		require.NotEqual(t, takes[p], notReturnTo[p], "%s must be listed in exactly one of returnToCeremonies and the endpoints that take no return_to: a ceremony that accepts return_to needs its bypass corpus", p)
	}
}

func TestEveryDeclaredRouteIsProbed(t *testing.T) {
	w := journeytest.NewWorld(t, journeytest.Settings{})
	probed := map[string]bool{}
	for _, tg := range newEnv(w).targets {
		probed[tg.method+" "+tg.path] = true
	}
	declared := w.DeclaredRoutes()
	for _, path := range []string{journeytest.FacadeSystemRoute, journeytest.FacadeKeyRoute} {
		require.True(t, probed["POST "+path], "facade route %s is declared but not probed", path)
	}
	for _, d := range declared {
		require.True(t, probed[d.Method+" "+d.Path], "declared route %s %s is not probed", d.Method, d.Path)
	}
	require.GreaterOrEqual(t, len(declared), 12)
}

func stubServer(t *testing.T, mount func(mux *http.ServeMux)) *journeytest.Client {
	t.Helper()
	mux := http.NewServeMux()
	mount(mux)
	return journeytest.NewBareClient(t, mux, journeytest.ExampleOrigin)
}

func TestOAuthBindProbeHasTeeth(t *testing.T) {
	const state = "genuine-state"
	begin := func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "egauth_bind", Value: "secret", Path: "/"})
		http.Redirect(w, r, "https://idp.example.test/authorize?state="+state, http.StatusFound)
	}
	reply := func(w http.ResponseWriter, code string) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
	}
	build := func(checkBind bool) *journeytest.Client {
		return stubServer(t, func(mux *http.ServeMux) {
			mux.HandleFunc("GET /auth/oauth/idp/begin", begin)
			mux.HandleFunc("GET /auth/oauth/idp/callback", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("state") != state {
					reply(w, "invalid_state")
					return
				}
				if _, err := r.Cookie("egauth_bind"); err != nil && checkBind {
					reply(w, "unbound_ceremony")
					return
				}
				reply(w, "invalid_code")
			})
		})
	}
	bindProbes := func(c *journeytest.Client) journeytest.Report {
		var ps []journeytest.Probe
		for _, p := range journeytest.AuthProbes(c, "/auth") {
			if strings.HasPrefix(p.Name, "ceremony-binding/oauth-callback-") {
				ps = append(ps, p)
			}
		}
		return journeytest.Collect(ps)
	}
	good := bindProbes(build(true))
	require.Len(t, good, 2)
	require.Empty(t, good.Failed(), "a callback that checks the bind passes: %v", good)
	bad := bindProbes(build(false))
	require.Len(t, bad.Failed(), 1, "a callback that ignores the bind must fail the without-bind probe, whatever it says about a forged state")
	require.Equal(t, "ceremony-binding/oauth-callback-without-bind", bad.Failed()[0].Name)
}

func TestBodyCapProbesPinTheCapExactly(t *testing.T) {
	login, _ := routes.MetaFor(routes.Login)
	build := func(slack int64) *journeytest.Client {
		return stubServer(t, func(mux *http.ServeMux) {
			mux.HandleFunc("POST /auth/login", func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, login.BodyCap+slack)); err != nil {
					w.WriteHeader(http.StatusRequestEntityTooLarge)
					return
				}
				w.WriteHeader(http.StatusBadRequest)
			})
		})
	}
	caps := func(c *journeytest.Client) journeytest.Report {
		return journeytest.Collect(onlyFamilies(journeytest.AuthProbes(c, "/auth"), "limits/body-cap-plus-one", "limits/body-cap-exact"))
	}
	require.Empty(t, caps(build(0)).Failed(), "a cap enforced exactly passes both probes")
	for _, slack := range []int64{1, 2} {
		failed := caps(build(slack)).Failed()
		require.Len(t, failed, 1, "a cap %d bytes too generous must fail the plus-one probe", slack)
		require.Equal(t, "limits/body-cap-plus-one/POST /auth/login", failed[0].Name)
	}
	short := caps(build(-1)).Failed()
	require.Len(t, short, 1, "a cap one byte too strict must fail the exact-cap control")
	require.Equal(t, "limits/body-cap-exact/POST /auth/login", short[0].Name)
}

func TestLoopbackIdPCompletesAnOAuthLogin(t *testing.T) {
	golden := journeytest.NewWorld(t, journeytest.Settings{})
	require.Equal(t, http.StatusBadGateway, golden.NewClient().CompleteOAuth(golden).Status, "the golden World cannot reach its loopback provider: the SSRF guard refuses it")

	w := journeytest.NewWorld(t, journeytest.Settings{LoopbackIdP: true})
	require.NotEmpty(t, w.Auth.Posture().OptOuts, "the knob is an opt-out, so the World is not the golden configuration")
	res := w.NewClient().CompleteOAuth(w)
	require.True(t, res.Established(), journeytest.Describe(res))
}

func TestBearerSessionsRenewThroughTheirRefreshToken(t *testing.T) {
	w := journeytest.NewWorld(t, journeytest.Settings{})
	email := w.FreshEmail("refresh")
	w.SeedUser(email, false)
	c := w.NewClient()
	c.Login(email, true)
	before := c.Bearer
	w.Clock.Advance(w.ReauthWindow() + time.Minute)
	res := c.RefreshBearer()
	require.Equal(t, http.StatusOK, res.Status, journeytest.Describe(res))
	require.NotEqual(t, before, c.Bearer, "a JWT refresh issues a new access token")
	require.Equal(t, http.StatusOK, c.Session().Status, "the renewed session reads its session")
}

func TestEveryReturnToCeremonyIsProbedWithTheWholeCorpus(t *testing.T) {
	w := journeytest.NewWorld(t, journeytest.Settings{})
	count := map[string]int{}
	for _, p := range newEnv(w).redirectProbes() {
		path := strings.TrimPrefix(p.Name, "redirects/")
		if i := strings.LastIndex(path, "/"); i > 0 {
			count[path[:i]]++
		}
	}
	e := newEnv(w)
	for _, registry := range returnToCeremonies {
		if !e.serves(registry) {
			continue
		}
		require.Equal(t, len(bypassCorpus), count[providerPaths.Replace(registry)], "%s takes a return_to: every corpus entry must be probed", registry)
	}
}

func TestBearerTransportProbesCeremonyBindingAndOAuthExchange(t *testing.T) {
	w := journeytest.NewWorld(t, journeytest.Settings{}.Configure(func(c *egauth.Config[journeytest.Claims]) { c.Transport = egauth.Bearer }))
	rep := journeytest.Collect(newEnv(w).ceremonyBindProbes())
	names := rep.ByName()
	for _, name := range []string{
		"ceremony-binding/magic-link-consumed-without-bind/bearer",
		"ceremony-binding/magic-link-consumed-with-bind/bearer",
		"ceremony-binding/oauth-exchange-without-bind/bearer",
		"ceremony-binding/oauth-exchange-with-bind/bearer",
	} {
		require.Contains(t, names, name)
	}
	rep.Check(t)
}

func TestSemanticOptOutsRunTheResourceBattery(t *testing.T) {
	rep := journeytest.Collect(resourceProbes(journeytest.NewResourceWorld(t, journeytest.Settings{})))
	require.NotEmpty(t, rep)
	for _, name := range rep.Names() {
		require.True(t, hasAnyPrefix(name, bearerOnlyProbes) && strings.HasPrefix(name, "resource-server/"), name)
	}
	f := variantFacts{key: "Transport=Cookies", transport: egauth.Cookies, tenancy: journeytest.Single}
	require.Empty(t, vanished(f, rep.Names(), nil, func(string) {}), "a Cookies-only variant has no Bearer resource tokens to probe")
	g := variantFacts{key: "Policy.Mystery=flipped", transport: egauth.CookiesAndBearer, tenancy: journeytest.Single}
	require.NotEmpty(t, vanished(g, rep.Names(), nil, func(string) {}), "any other variant must keep the resource battery")
}

func TestSessionLimitProbesFollowMetaSessionLimit(t *testing.T) {
	w := journeytest.NewWorld(t, journeytest.Settings{})
	names := map[string]bool{}
	for _, p := range newEnv(w).sessionLimitProbes() {
		names[p.Name] = true
	}
	for _, tg := range newEnv(w).targets {
		if tg.kind != kAuth {
			continue
		}
		want := tg.meta.SessionLimit != 0 && !tg.meta.EndsSession
		require.Equal(t, want, names["limits/session-burst-plus-one/cookie/"+tg.label()], "session burst probe of %s follows Meta.SessionLimit (logout-everywhere ends the session it is keyed on, so request two is unauthenticated: not probeable)", tg.label())
	}
}

func TestCrossTenantRefusalIsNotAnyErrorStatus(t *testing.T) {
	resp := func(status int, body string) *journeytest.Resp {
		return &journeytest.Resp{Status: status, Body: []byte(body)}
	}
	require.True(t, refusedAsUnknown(resp(http.StatusUnauthorized, `{"error":"unauthenticated"}`)))
	require.True(t, refusedAsUnknown(resp(http.StatusBadRequest, `{"error":"invalid_token"}`)))
	require.False(t, refusedAsUnknown(resp(http.StatusBadRequest, `{"error":"invalid_return_to"}`)))
	require.False(t, refusedAsUnknown(resp(http.StatusInternalServerError, `{"error":"internal"}`)))
	require.False(t, refusedAsUnknown(resp(http.StatusOK, `{"state":"authenticated"}`)))
}

func TestCrossTenantProbesCoverEveryConsumedRecordTheHarnessCanDrive(t *testing.T) {
	w := journeytest.NewWorld(t, journeytest.Settings{})
	names := map[string]bool{}
	for _, p := range newEnv(w).tenancyProbes() {
		names[p.Name] = true
	}
	for _, name := range []string{
		"tenancy/code-handle-of-another-tenant/email", "tenancy/code-handle-of-another-tenant/sms",
		"tenancy/mfa-flow-handle-of-another-tenant", "tenancy/magic-link-token-of-another-tenant",
		"tenancy/password-reset-token-of-another-tenant", "tenancy/registration-token-of-another-tenant",
		"tenancy/email-change-token-of-another-tenant", "tenancy/recovery-email-token-of-another-tenant",
		"tenancy/oauth-exchange-handle-of-another-tenant", "tenancy/oauth-state-of-another-tenant",
	} {
		require.True(t, names[name], "missing probe %s", name)
	}
}
