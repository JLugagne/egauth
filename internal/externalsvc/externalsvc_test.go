package externalsvc_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/clientaddr"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/externalsvc"
	"github.com/JLugagne/egauth/internal/federationsvc"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/store"
	storefed "github.com/JLugagne/egauth/store/federation"
	fedmem "github.com/JLugagne/egauth/store/federation/memory"
	"github.com/JLugagne/egauth/store/identity"
	identitymem "github.com/JLugagne/egauth/store/identity/memory"
	"github.com/JLugagne/egauth/store/limiter"
)

const (
	origin   = "https://auth.example.com"
	basePath = "/auth"
)

var start = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

type sink struct {
	mu     sync.Mutex
	events []event.Event
}

func (s *sink) EmitEvent(_ context.Context, e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

type allowAll struct{}

func (allowAll) Allow(context.Context, limiter.Key) (limiter.Decision, error) {
	return limiter.Decision{Allowed: true}, nil
}

type noSession struct{}

func (noSession) Resume(context.Context, http.ResponseWriter, *http.Request, core.TenantID) (session.Resumed, error) {
	return session.Resumed{}, errors.New("no session")
}

type noEnrollment struct{}

func (noEnrollment) MFARequired(context.Context, core.Subject) (bool, error) { return false, nil }

type accounts struct{ identity.Store }

func (a accounts) AccountState(ctx context.Context, s core.Subject) (core.AccountState, error) {
	u, err := a.GetUser(ctx, s)
	if errors.Is(err, store.ErrNotFound) {
		return core.AccountState{}, nil
	}
	if err != nil {
		return core.AccountState{}, errors.Join(httpx.ErrUnavailable, err)
	}
	return core.NewAccountState(true, !u.DisabledAt.IsZero(), !u.DeletedAt.IsZero(), u.MustChange, !u.EmailVerifiedAt.IsZero(), u.SecurityEpoch), nil
}

type completion struct {
	pending  core.Pending
	verified core.Verified
}

type fakeIssuer struct {
	clock    *clock.Test
	accounts accounts
	origins  redirect.Origins
	mu       sync.Mutex
	mfa      map[core.Subject]bool
	done     []completion
}

func (f *fakeIssuer) Begin(_ context.Context, r *httpx.Request) (core.Pending, error) {
	remember := core.RememberDeclined
	if r.Flag(routes.FieldRemember) {
		remember = core.RememberRequested
	}
	target, err := redirect.Parse(r.Field(routes.FieldReturnTo), f.origins)
	if err != nil {
		return core.Pending{}, httpx.ErrInvalidRequest
	}
	return core.NewPending(r.Tenant(), remember, target, r.Transport(), core.RememberUserChoice, f.clock.Now())
}

func (f *fakeIssuer) Complete(ctx context.Context, _ http.ResponseWriter, _ *httpx.Request, p core.Pending, v core.Verified) (httpx.Response, error) {
	f.mu.Lock()
	f.done = append(f.done, completion{pending: p, verified: v})
	enrolled := f.mfa[v.Subject()]
	f.mu.Unlock()
	st, err := f.accounts.AccountState(ctx, v.Subject())
	if err != nil {
		return httpx.Response{}, err
	}
	p, err = p.Add(v, st)
	if err != nil {
		return httpx.Response{}, errors.Join(httpx.ErrUnauthenticated, err)
	}
	decision := core.NewMFADecision(nil)
	if enrolled {
		decision = core.NewMFADecision([]core.Factor{core.FactorTOTP})
	}
	adm, err := core.Admit(p, st, decision, f.clock.Now())
	if err != nil {
		return httpx.Response{}, errors.Join(httpx.ErrUnauthenticated, err)
	}
	if _, _, needs := adm.NeedsFactor(); needs {
		return httpx.Response{Body: map[string]string{"state": "mfa_required"}}, nil
	}
	return httpx.Response{Body: map[string]string{"state": "authenticated"}}, nil
}

func (f *fakeIssuer) Reauthenticate(context.Context, http.ResponseWriter, *httpx.Request, core.Verified) (httpx.Response, error) {
	return httpx.Response{}, httpx.ErrInternal
}

func (f *fakeIssuer) Reissue(context.Context, http.ResponseWriter, *httpx.Request, httpx.Change) error {
	return httpx.ErrInternal
}

type ldap struct {
	users map[string]externalsvc.Identity
	seen  []externalsvc.Request
	mu    sync.Mutex
}

func (l *ldap) Name() string { return "ldap" }

func (l *ldap) Verify(_ context.Context, req externalsvc.Request) (externalsvc.Identity, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = append(l.seen, req)
	id, ok := l.users[req.Identifier+"/"+req.Secret]
	if !ok {
		return externalsvc.Identity{}, errors.New("bad credentials")
	}
	return id, nil
}

type world struct {
	t       *testing.T
	ids     identity.Store
	fed     storefed.Store
	issuer  *fakeIssuer
	ldap    *ldap
	handler http.Handler
}

func newWorld(t *testing.T, reg federationsvc.Registration) *world {
	t.Helper()
	clk := clock.NewTest(start)
	ids := identitymem.NewWithClock(clk.Clock())
	fed := fedmem.NewWithClock(clk.Clock(), ids)
	audit := httpx.SinkAudit(&sink{})
	acc := accounts{Store: ids}
	dir, err := federationsvc.NewDirectory(federationsvc.DirectoryConfig{Users: ids, Links: fed, Accounts: acc, Registration: reg, Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	l := &ldap{users: map[string]externalsvc.Identity{
		"alice/pw":   {ExternalID: "uid=alice", Email: "alice@example.org", EmailVerified: true},
		"bob/pw":     {ExternalID: "uid=bob", Email: "bob@example.org"},
		"carol/pw":   {ExternalID: "uid=carol", Email: "carol@example.org", EmailVerified: true},
		"noid/pw":    {Email: "noid@example.org", EmailVerified: true},
		"noemail/pw": {ExternalID: "uid=noemail", EmailVerified: true},
	}}
	svc, err := externalsvc.New(externalsvc.Config{Verifiers: []externalsvc.Verifier{l}, Directory: dir, Clock: clk.Clock(), Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	ro, err := redirect.NewOrigins(origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, ids: ids, fed: fed, ldap: l, issuer: &fakeIssuer{clock: clk, accounts: acc, origins: ro, mfa: map[core.Subject]bool{}}}
	eps, err := svc.Endpoints(w.issuer)
	if err != nil {
		t.Fatal(err)
	}
	table, err := routes.NewTable(eps...)
	if err != nil {
		t.Fatal(err)
	}
	res, err := clientaddr.New(clientaddr.Direct(), nil)
	if err != nil {
		t.Fatal(err)
	}
	o, err := csrf.NewOrigins(origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := httpx.NewPreamble(httpx.Env{
		Tenants: httpx.SingleTenant(), Limiter: allowAll{}, Authenticator: noSession{}, Issuer: w.issuer,
		Identifiers: identitysvc.Normalizer{}, Enrollment: noEnrollment{}, Clock: clk.Clock(), Audit: audit,
	}, httpx.Settings{Clients: res, Origins: o, Transports: httpx.CookiesAndBearer, ReauthWindow: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := table.Mount(mux, basePath, p); err != nil {
		t.Fatal(err)
	}
	w.handler = mux
	return w
}

func (w *world) login(name, identifier, secret string, extra map[string]string) *httptest.ResponseRecorder {
	w.t.Helper()
	fields := map[string]string{routes.FieldIdentifier: identifier, routes.FieldPassword: secret}
	maps.Copy(fields, extra)
	b, err := json.Marshal(fields)
	if err != nil {
		w.t.Fatal(err)
	}
	hr := httptest.NewRequest(http.MethodPost, origin+basePath+"/external/"+name+"/login", strings.NewReader(string(b)))
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Origin", origin)
	hr.Header.Set("Sec-Fetch-Site", "same-origin")
	hr.RemoteAddr = "198.51.100.7:4000"
	rec := httptest.NewRecorder()
	w.handler.ServeHTTP(rec, hr)
	return rec
}

func (w *world) user(email string) core.Subject {
	w.t.Helper()
	id, err := identitysvc.NormalizeAs(identity.IdentifierEmail, email)
	if err != nil {
		w.t.Fatal(err)
	}
	a, err := w.ids.Apply(context.Background(), identity.CreateVerified{Email: id})
	if err != nil {
		w.t.Fatal(err)
	}
	return a.Subject
}

func body(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return m
}

func TestNewExternalAccountEndsInCompleteWithTheExtFactor(t *testing.T) {
	w := newWorld(t, federationsvc.RegistrationOpen)
	rec := w.login("ldap", "alice", "pw", map[string]string{routes.FieldRemember: "true", routes.FieldReturnTo: "/home"})
	if rec.Code != http.StatusOK || body(t, rec)["state"] != "authenticated" {
		t.Fatalf("external login answered %d %s", rec.Code, rec.Body.String())
	}
	done := w.issuer.done
	if len(done) != 1 {
		t.Fatalf("Complete called %d times", len(done))
	}
	v := done[0].verified
	if fs := v.Factors(); len(fs) != 1 || fs[0] != core.FactorExternal || v.Provider() != "external:ldap" {
		t.Fatalf("Complete got %v from %q, want ext from external:ldap", fs, v.Provider())
	}
	if p := done[0].pending; !p.RememberMe() || p.ReturnTo() != "/home" {
		t.Fatalf("the sealed Pending lost remember or return_to: %v %q", p.RememberMe(), p.ReturnTo())
	}
	l, err := w.fed.FindLinked(context.Background(), core.TenantID{}, storefed.LinkKey{Provider: "external:ldap", ProviderSubject: "uid=alice"})
	if err != nil || l.Subject != v.Subject() {
		t.Fatalf("external id not mapped through the federation store: %+v %v", l, err)
	}
	again := w.login("ldap", "alice", "pw", nil)
	if again.Code != http.StatusOK || w.issuer.done[1].verified.Subject() != v.Subject() {
		t.Fatalf("second external login did not reach the same account: %s", again.Body.String())
	}
}

func TestExternalLoginNeverLinksAnExistingAccount(t *testing.T) {
	w := newWorld(t, federationsvc.RegistrationOpen)
	owner := w.user("carol@example.org")
	rec := w.login("ldap", "carol", "pw", nil)
	if rec.Code != http.StatusConflict || body(t, rec)["error"] != "account_exists" {
		t.Fatalf("existing email answered %d %s, want 409 account_exists (D6)", rec.Code, rec.Body.String())
	}
	if links, _ := w.fed.LinkedFor(context.Background(), owner); len(links) != 0 || len(w.issuer.done) != 0 {
		t.Fatalf("the external identity reached the existing account: %v", links)
	}
}

func TestExternalSignUpNeedsAVerifiedEmail(t *testing.T) {
	w := newWorld(t, federationsvc.RegistrationOpen)
	for _, who := range []string{"bob", "noemail"} {
		rec := w.login("ldap", who, "pw", nil)
		if rec.Code != http.StatusForbidden || body(t, rec)["error"] != "email_unverified" {
			t.Fatalf("%s answered %d %s, want 403 email_unverified", who, rec.Code, rec.Body.String())
		}
	}
}

func TestExternalInviteOnlyCreatesNothing(t *testing.T) {
	w := newWorld(t, federationsvc.RegistrationInviteOnly)
	rec := w.login("ldap", "alice", "pw", nil)
	if rec.Code != http.StatusForbidden || body(t, rec)["error"] != "registration_closed" {
		t.Fatalf("invite-only answered %d %s", rec.Code, rec.Body.String())
	}
}

func TestExternalRefusalsAreUniform(t *testing.T) {
	w := newWorld(t, federationsvc.RegistrationOpen)
	a := w.login("ldap", "alice", "wrong", nil)
	b := w.login("ldap", "nobody", "pw", nil)
	c := w.login("ldap", "noid", "pw", nil)
	for _, rec := range []*httptest.ResponseRecorder{a, b, c} {
		if rec.Code != http.StatusUnauthorized || rec.Body.String() != a.Body.String() || body(t, rec)["error"] != "invalid_credentials" {
			t.Fatalf("refusal answered %d %s", rec.Code, rec.Body.String())
		}
	}
	if len(w.issuer.done) != 0 {
		t.Fatal("a refused external login reached Complete")
	}
}

func TestExternalEnrolledUserGetsTheMFAStep(t *testing.T) {
	w := newWorld(t, federationsvc.RegistrationOpen)
	if rec := w.login("ldap", "alice", "pw", nil); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	w.issuer.mfa[w.issuer.done[0].verified.Subject()] = true
	if rec := w.login("ldap", "alice", "pw", nil); body(t, rec)["state"] != "mfa_required" {
		t.Fatalf("an enrolled user skipped MFA through the external factor: %s", rec.Body.String())
	}
}

func TestUnknownExternalNameIs404(t *testing.T) {
	w := newWorld(t, federationsvc.RegistrationOpen)
	if rec := w.login("saml", "alice", "pw", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown external factor answered %d", rec.Code)
	}
}

type named string

func (n named) Name() string { return string(n) }

func (n named) Verify(context.Context, externalsvc.Request) (externalsvc.Identity, error) {
	return externalsvc.Identity{}, errors.New("no")
}

func TestNewRefusesBadVerifiers(t *testing.T) {
	cases := map[string][]externalsvc.Verifier{
		"none":      nil,
		"bad name":  {named("LDAP!")},
		"duplicate": {named("ldap"), named("ldap")},
		"nil":       {nil},
	}
	for name, vs := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := externalsvc.New(externalsvc.Config{Verifiers: vs, Directory: &federationsvc.Directory{}, Audit: httpx.SinkAudit(&sink{})})
			if !errors.Is(err, externalsvc.ErrInvalidConfig) {
				t.Fatalf("New accepted %s: %v", name, err)
			}
		})
	}
}

func TestRequestRedactsTheSecret(t *testing.T) {
	r := externalsvc.Request{Identifier: "alice", Secret: "hunter2"}
	var b strings.Builder
	slog.New(slog.NewTextHandler(&b, nil)).Info("x", "req", r)
	for _, out := range []string{fmt.Sprint(r), fmt.Sprintf("%+v", r), fmt.Sprintf("%#v", r), b.String()} {
		if strings.Contains(out, "hunter2") {
			t.Fatalf("secret leaked: %s", out)
		}
	}
}
