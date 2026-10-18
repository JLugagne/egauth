package egauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/delivery"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

type wiringSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (s *wiringSink) EmitEvent(_ context.Context, e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *wiringSink) of(t event.Type) []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []event.Event
	for _, e := range s.events {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

func mustNew(t *testing.T, cfg egauth.Config[struct{}]) *egauth.Auth[struct{}] {
	t.Helper()
	a, err := egauth.New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func stacks() string {
	buf := make([]byte, 1<<22)
	return string(buf[:runtime.Stack(buf, true)])
}

func minimalConfig(t testing.TB) egauth.Config[struct{}] {
	t.Helper()
	return egauth.Config[struct{}]{
		PublicOrigin: "https://app.example.com",
		Proxy:        egauth.DirectClients(),
		Storage:      storage(store.Shared),
		KEK:          testKEK(t),
		Sessions:     egauth.Stateful(),
		Admin:        egauth.SelfServiceOnly(),
		Email:        &egauthtest.Mailbox{},
		Pages:        egauth.Pages{SecurityRevert: "/revert"},
		Modules:      egauth.Modules{Passkey: &egauth.PasskeyModule{DisplayName: "Example"}},
	}
}

func hooked(cfg egauth.Config[struct{}]) egauth.Config[struct{}] {
	cfg.Hooks.AccountDeleted = func(context.Context, uuid.UUID, principal.Subject) error { return nil }
	cfg.Hooks.TenantErased = func(context.Context, uuid.UUID, principal.TenantID) error { return nil }
	return cfg
}

func TestNewOwnsEveryPolicyObject(t *testing.T) {
	a := mustNew(t, fullConfig(t))
	for name, ok := range egauth.OwnedOf(a).Fields {
		require.True(t, ok, "Auth does not own its %s", name)
	}
}

func TestNewOwnsOnlyWhatTheConfigurationEnables(t *testing.T) {
	a := mustNew(t, minimalConfig(t))
	f := egauth.OwnedOf(a).Fields
	for _, absent := range []string{"families", "keys", "codec", "mfa", "codes", "federation", "external"} {
		require.False(t, f[absent], absent)
	}
	for _, present := range []string{"passkeys", "identity", "accounts", "issuer", "flow", "backend", "dispatcher", "reaper", "preamble"} {
		require.True(t, f[present], present)
	}
}

func TestNewFillsTheEnvOnceForEveryService(t *testing.T) {
	a := mustNew(t, fullConfig(t))
	v := egauth.OwnedOf(a)
	require.NoError(t, v.Env.Validate())
	require.NotNil(t, v.Env.BeforeEndpoint)
	require.True(t, v.Env.Issuer == httpx.Issuer(v.Issuer), "the Env issuer is the issuer the services serve through")
	require.True(t, v.Env.Authenticator == httpx.Authenticator(v.Backend))
	require.True(t, v.Env.Limiter == v.Limiter)
}

func TestNewIdentityIsInternalAndWiredOnce(t *testing.T) {
	a := mustNew(t, hooked(fullConfig(t)))
	cfg := egauth.ConfigOf(a)
	v := egauth.OwnedOf(a)
	w := v.Dispatcher.Wired()
	require.True(t, w[identity.ComponentSessions] == any(v.Backend), "the sessions row revokes the backend the requests resume through")
	require.True(t, w[identity.ComponentAPIKeys] == any(cfg.Storage.Tokens))
	require.True(t, w[identity.ComponentMFA] == any(cfg.Storage.MFA))
	require.True(t, w[identity.ComponentPasskeys] == any(cfg.Storage.Passkeys))
	require.True(t, w[identity.ComponentFederation] == any(cfg.Storage.Federation))
	require.True(t, w[identity.ComponentKeys] == any(cfg.Storage.Keys))
	require.True(t, w[identity.ComponentIdentity] == any(cfg.Storage.Identity))
	require.True(t, w[identity.ComponentNotices] == any(v.Accounts), "the notices row is the Accounts the endpoints serve")
	require.Nil(t, w[identity.ComponentHooks])
	c, ok := w[identity.ComponentCeremonies].(lifecycle.CeremoniesWiring)
	require.True(t, ok)
	require.True(t, c.Store == any(cfg.Storage.Ceremonies))
	require.True(t, c.Accounts == any(cfg.Storage.Identity))
	require.True(t, c.Scoper == any(v.Accounts), "the ceremony row scopes identifiers like the Accounts that wrote them")
}

func TestG18SubscriberWiringEqualsTheLifecycleMatrix(t *testing.T) {
	a := mustNew(t, hooked(fullConfig(t)))
	got := egauth.OwnedOf(a).Dispatcher.Matrix()
	want := lifecycle.Golden()
	require.Len(t, got, len(want))
	for _, c := range identity.Components() {
		w, g := reflect.ValueOf(want[c]), reflect.ValueOf(got[c])
		for i := range w.NumField() {
			require.Equal(t, w.Field(i).Interface(), g.Field(i).Interface(), "%s / %s", c, w.Type().Field(i).Name)
		}
	}
}

func TestG18AbsentOptionalStoresAndHooksAreReportedHonestly(t *testing.T) {
	cfg := minimalConfig(t)
	cfg.Storage.Keys, cfg.Storage.Federation, cfg.Storage.Tokens = nil, nil, nil
	a := mustNew(t, cfg)
	got := egauth.OwnedOf(a).Dispatcher.Matrix()
	want := lifecycle.Golden()
	for _, c := range []identity.Component{identity.ComponentKeys, identity.ComponentFederation, identity.ComponentAPIKeys} {
		for _, cell := range cellsOf(got[c]) {
			require.Equal(t, lifecycle.CellAbsent, cell, c.String())
		}
	}
	require.Equal(t, lifecycle.CellNone, got[identity.ComponentHooks].Delete)
	require.Equal(t, lifecycle.CellNone, got[identity.ComponentHooks].TenantErased)
	for _, c := range []identity.Component{identity.ComponentSessions, identity.ComponentCeremonies, identity.ComponentMFA,
		identity.ComponentPasskeys, identity.ComponentNotices, identity.ComponentIdentity} {
		require.Equal(t, want[c], got[c], c.String())
	}
}

func cellsOf(c lifecycle.Cells) []lifecycle.Cell {
	v := reflect.ValueOf(c)
	out := make([]lifecycle.Cell, v.NumField())
	for i := range out {
		out[i] = v.Field(i).Interface().(lifecycle.Cell)
	}
	return out
}

func TestG18AStandInWiringIsDistinguishable(t *testing.T) {
	a := mustNew(t, fullConfig(t))
	other := mustNew(t, fullConfig(t))
	w, o := egauth.OwnedOf(a).Dispatcher.Wired(), egauth.OwnedOf(other).Dispatcher.Wired()
	require.False(t, w[identity.ComponentSessions] == o[identity.ComponentSessions])
	require.False(t, w[identity.ComponentNotices] == o[identity.ComponentNotices])
}

func TestNewBuildsTheAuthRouteTable(t *testing.T) {
	full := egauth.OwnedOf(mustNew(t, fullConfig(t))).Patterns
	seen := map[string]bool{}
	for _, p := range full {
		require.False(t, seen[p], "%s is mounted twice", p)
		seen[p] = true
	}
	for _, p := range []string{
		"GET /auth/session", "POST /auth/logout", "POST /auth/login", "POST /auth/register", "POST /auth/magic-link",
		"POST /auth/code/verify", "POST /auth/passkey/login/begin", "GET /auth/oauth/{provider}/begin",
		"POST /auth/external/{name}/login", "POST /auth/mfa/challenge", "POST /auth/mfa/totp/enroll", "POST /auth/reauth",
		"POST /auth/password/change", "POST /auth/security/revert", "POST /auth/email/verify", "POST /auth/phone/verify",
		"POST /auth/recovery-email", "POST /auth/account/delete", "POST /auth/exchange",
	} {
		require.True(t, seen[p], "the full deployment does not serve %s", p)
	}
	minimal := egauth.OwnedOf(mustNew(t, minimalConfig(t))).Patterns
	for _, p := range minimal {
		for _, off := range []string{"/login", "/register", "/magic-link", "/code/", "/oauth/", "/external/", "/mfa/totp", "/email/", "/phone/", "/recovery-email", "/account/delete"} {
			require.False(t, strings.Contains(p, " /auth"+off), "a disabled module is mounted: %s", p)
		}
	}
	require.Contains(t, minimal, "GET /auth/session")
	require.Contains(t, minimal, "POST /auth/passkey/login/begin")
	require.Contains(t, minimal, "POST /auth/mfa/passkey/begin")
	for _, p := range full {
		_, path, _ := strings.Cut(p, " ")
		require.Contains(t, routes.All(), strings.TrimPrefix(path, "/auth"))
	}
}

func TestNewMountsEveryEndpointBehindThePreamble(t *testing.T) {
	a := mustNew(t, fullConfig(t))
	h := egauth.Handler(a)
	req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	req.RemoteAddr = "192.0.2.10:4000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
}

func TestNewBeforeEndpointHookRunsAfterTheLibraryGates(t *testing.T) {
	var seen []egauth.EndpointRequest
	cfg := fullConfig(t)
	cfg.Hooks.BeforeEndpoint = func(_ context.Context, r egauth.EndpointRequest) error {
		seen = append(seen, r)
		return errors.New("refused")
	}
	h := egauth.Handler(mustNew(t, cfg))
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader(""))
	req.RemoteAddr = "192.0.2.10:4000"
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Len(t, seen, 1)
	require.Equal(t, egauth.EndpointID("/logout"), seen[0].Endpoint)
	require.Equal(t, "192.0.2.10", seen[0].Client.String())
}

func TestNewDoesNotTakeACallerContext(t *testing.T) {
	ty := reflect.TypeOf(egauth.New[struct{}])
	require.Equal(t, 1, ty.NumIn())
	require.Equal(t, reflect.TypeOf(egauth.Config[struct{}]{}), ty.In(0))
}

const deliveryMarker = "delivery.(*Pool).work"

var workerMarkers = []string{"revoke.(*follower", "reap.(*Reaper)", "owned).startHeartbeat", deliveryMarker}

func workerCounts() map[string]int {
	out := map[string]int{}
	for g := range strings.SplitSeq(stacks(), "\n\n") {
		for _, m := range workerMarkers {
			if strings.Contains(g, m) {
				out[m]++
			}
		}
	}
	return out
}

func TestNewStartsTheBackgroundWorkAndCloseStopsIt(t *testing.T) {
	before := workerCounts()
	a, err := egauth.New(fullConfig(t))
	require.NoError(t, err)
	running := workerCounts()
	for _, m := range workerMarkers {
		require.Greater(t, running[m], before[m], "%s is not running after New", m)
	}
	require.Equal(t, before[deliveryMarker]+2*delivery.Workers, running[deliveryMarker], "the code and identity services each run one delivery pool")
	require.NoError(t, a.Close())
	require.Eventually(t, func() bool {
		return reflect.DeepEqual(workerCounts(), before)
	}, 5*time.Second, 10*time.Millisecond, "Close left a worker running")
}

func TestNewFailureAfterTheBuildStopsWhatItStarted(t *testing.T) {
	before := workerCounts()
	cfg := fullConfig(t)
	cfg.RateLimit = allowEverything{memLimiter(store.Shared)}
	_, err := egauth.New(cfg)
	requireField(t, err, "RateLimit")
	require.Eventually(t, func() bool {
		return reflect.DeepEqual(workerCounts(), before)
	}, 5*time.Second, 10*time.Millisecond, "a failed New leaked a worker")
}

func TestNewEmitsInsecureConfigurationOncePerOptOut(t *testing.T) {
	sink := &wiringSink{}
	cfg := fullConfig(t)
	cfg.Events = sink
	cfg.Insecure.NoOriginCheck = egauth.Acknowledge("behind a gateway that checks origins")
	cfg.Insecure.NoReauthWindow = egauth.Acknowledge("kiosk")
	a := mustNew(t, cfg)
	got := sink.of(event.InsecureConfiguration)
	require.Len(t, got, 2)
	reasons := map[string]string{}
	for _, e := range got {
		reasons[e.Attrs[string(event.KeyPurpose)].(string)] = e.Reason
	}
	require.Equal(t, map[string]string{"NoOriginCheck": "behind a gateway that checks origins", "NoReauthWindow": "kiosk"}, reasons)
	require.Len(t, a.Posture().OptOuts, 2)
}

func TestNewEmitsNoInsecureConfigurationWhenItFails(t *testing.T) {
	sink := &wiringSink{}
	cfg := fullConfig(t)
	cfg.Events = sink
	cfg.Insecure.NoOriginCheck = egauth.Acknowledge("behind a gateway")
	cfg.PublicOrigin = "http://app.example.com"
	_, err := egauth.New(cfg)
	require.Error(t, err)
	require.Empty(t, sink.of(event.InsecureConfiguration))
}

func TestNewReadyOnAZeroAuthFails(t *testing.T) {
	var a egauth.Auth[struct{}]
	require.Error(t, a.Ready(context.Background()))
	require.NoError(t, a.Close())
	require.Equal(t, 1, a.Posture().Instances)
}

func TestNewClaimsSourceIsReadThroughTheRenewerOnly(t *testing.T) {
	cfg := fullConfig(t)
	a := mustNew(t, cfg)
	sub := principal.Subject{User: uuid.New()}
	c, err := egauth.OwnedOf(a).Renewer.FetchClaims(context.Background(), sub)
	require.NoError(t, err)
	var wire map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(c.Bytes(), &wire))
	require.JSONEq(t, `["user"]`, string(wire["roles"]))
	require.JSONEq(t, `[]`, string(wire["groups"]))
	require.JSONEq(t, `[]`, string(wire["scopes"]))
	require.JSONEq(t, `{}`, string(wire["custom"]))
}

type unknownClaims struct{}

func (unknownClaims) ClaimsFor(context.Context, principal.Subject) (egauth.AppClaims[struct{}], error) {
	return egauth.AppClaims[struct{}]{}, egauth.ErrUnknownSubject
}

func TestNewMapsAnUnknownSubjectToARefusal(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Claims = unknownClaims{}
	a := mustNew(t, cfg)
	_, err := egauth.OwnedOf(a).Renewer.FetchClaims(context.Background(), principal.Subject{User: uuid.New()})
	require.ErrorIs(t, err, core.ErrClaimsSubjectUnknown)
}

func TestNewClaimsFingerprintNamesTheClaimsType(t *testing.T) {
	require.Equal(t, egauth.ClaimsFingerprint[struct{}](), egauth.ClaimsFingerprint[struct{}]())
	require.NotEqual(t, egauth.ClaimsFingerprint[struct{}](), egauth.ClaimsFingerprint[map[string]string]())
	require.NotEqual(t, egauth.ClaimsFingerprint[unknownClaims](), egauth.ClaimsFingerprint[struct{ A int }]())
}

func TestNewBuildsLinksFromThePublicOriginAndThePages(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Pages.Error = "https://admin.app.example.com/error"
	a := mustNew(t, cfg)
	for k, want := range map[ceremony.Kind]string{
		ceremony.PendingRegistration: "https://app.example.com/register/confirm?token=h%2F1",
		ceremony.PasswordReset:       "https://app.example.com/reset?token=h%2F1",
		ceremony.MagicLink:           "https://app.example.com/magic?token=h%2F1",
		ceremony.EmailVerification:   "https://app.example.com/verify?token=h%2F1",
		ceremony.EmailChange:         "https://app.example.com/email/confirm?token=h%2F1",
		ceremony.RecoveryEmail:       "https://app.example.com/email/confirm?token=h%2F1",
		ceremony.SecurityRevert:      "https://app.example.com/revert?token=h%2F1",
	} {
		got, err := egauth.LinkOf(a, principal.TenantID{}, k, "h/1")
		require.NoError(t, err, k.String())
		require.Equal(t, want, got, k.String())
	}
	_, err := egauth.LinkOf(a, principal.TenantID{}, ceremony.MFAFlow, "h")
	require.Error(t, err)
}

func TestNewBuildsTenantLinksUnderSubdomainTenancy(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Tenancy = egauth.TenantBySubdomain()
	cfg.PublicOrigin = "https://{tenant}.example.com"
	cfg.ExtraOrigins, cfg.Audiences = nil, nil
	cfg.Pages.AfterLogin = "https://{tenant}.example.com/home"
	a := mustNew(t, cfg)
	tenant, err := principal.ParseTenantID("acme")
	require.NoError(t, err)
	got, err := egauth.LinkOf(a, tenant, ceremony.PasswordReset, "h")
	require.NoError(t, err)
	require.Equal(t, "https://acme.example.com/reset?token=h", got)
	_, err = egauth.LinkOf(a, principal.TenantID{}, ceremony.PasswordReset, "h")
	require.Error(t, err, "a tenant-less link has no host")
	bad, err := principal.ParseTenantID("Acme_Inc")
	require.NoError(t, err)
	_, err = egauth.LinkOf(a, bad, ceremony.PasswordReset, "h")
	require.Error(t, err, "a tenant that cannot form a host label gets no link")
}

func TestNewRefusesPagesItsLinksAndRedirectsCannotServe(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Pages.AfterLogin = "https://admin.app.example.com/home"
	requireField(t, newErr(t, cfg), "Pages.AfterLogin")
	cfg = fullConfig(t)
	cfg.Pages.ConfirmEmailChange, cfg.Pages.VerifyEmail = "", ""
	cfg.Modules.Verification = &egauth.VerificationModule{RecoveryEmail: true}
	requireField(t, newErr(t, cfg), "Pages.ConfirmEmailChange")
	cfg = fullConfig(t)
	cfg.Tenancy = egauth.TenantBySubdomain()
	cfg.PublicOrigin = "https://{tenant}.example.com"
	cfg.ExtraOrigins = []string{"https://{tenant}.admin.example.com"}
	cfg.Audiences = nil
	requireField(t, newErr(t, cfg), "ExtraOrigins[0]")
}

func TestNewSecurityNoticesFindTheirDetachedPending(t *testing.T) {
	a := mustNew(t, fullConfig(t))
	p, err := egauth.OwnedOf(a).Issuer.Detached(context.Background(), principal.TenantID{})
	require.NoError(t, err)
	_, bound := p.Subject()
	require.False(t, bound)
	require.True(t, p.ExpiresAt().After(time.Now()))
}

func TestNewRunsTheApplicationHooksFromTheLifecycleOutbox(t *testing.T) {
	var mu sync.Mutex
	var ids []uuid.UUID
	cfg := fullConfig(t)
	cfg.Hooks.TenantErased = func(_ context.Context, id uuid.UUID, _ principal.TenantID) error {
		mu.Lock()
		defer mu.Unlock()
		ids = append(ids, id)
		return nil
	}
	a := mustNew(t, cfg)
	tenant, err := principal.ParseTenantID("acme")
	require.NoError(t, err)
	d := egauth.OwnedOf(a).Dispatcher
	require.NoError(t, d.EraseTenant(context.Background(), tenant))
	require.NoError(t, d.EraseTenant(context.Background(), tenant))
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, ids, 2)
	require.Equal(t, ids[0], ids[1], "a retried erasure carries the same DeliveryID")
}
