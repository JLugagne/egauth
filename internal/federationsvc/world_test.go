package federationsvc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/clientaddr"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/federationsvc"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	ceremonymem "github.com/JLugagne/egauth/store/ceremony/memory"
	storefed "github.com/JLugagne/egauth/store/federation"
	fedmem "github.com/JLugagne/egauth/store/federation/memory"
	"github.com/JLugagne/egauth/store/identity"
	identitymem "github.com/JLugagne/egauth/store/identity/memory"
	"github.com/JLugagne/egauth/store/limiter"
)

const (
	origin   = "https://auth.example.com"
	basePath = "/auth"
	sessHdr  = "X-Test-Session"
)

var start = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func testDataKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)*13 + 5
	}
	return k
}

type recordingSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (s *recordingSink) EmitEvent(_ context.Context, e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *recordingSink) has(t event.Type) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if e.Type == t {
			return true
		}
	}
	return false
}

type allowAll struct{}

func (allowAll) Allow(context.Context, limiter.Key) (limiter.Decision, error) {
	return limiter.Decision{Allowed: true}, nil
}

type noEnrollment struct{}

func (noEnrollment) MFARequired(context.Context, core.Subject) (bool, error) { return false, nil }

type accounts struct {
	identity.Store
	mu         sync.Mutex
	unverified map[core.Subject]bool
}

func (a *accounts) unverify(s core.Subject) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.unverified[s] = true
}

func (a *accounts) AccountState(ctx context.Context, s core.Subject) (core.AccountState, error) {
	u, err := a.GetUser(ctx, s)
	if errors.Is(err, store.ErrNotFound) {
		return core.AccountState{}, nil
	}
	if err != nil {
		return core.AccountState{}, errors.Join(httpx.ErrUnavailable, err)
	}
	a.mu.Lock()
	verified := !u.EmailVerifiedAt.IsZero() && !a.unverified[s]
	a.mu.Unlock()
	return core.NewAccountState(true, !u.DisabledAt.IsZero(), !u.DeletedAt.IsZero(), u.MustChange, verified, u.SecurityEpoch), nil
}

type sessions struct {
	mu   sync.Mutex
	byID map[string]core.SessionAttrs
	ids  identity.Store
}

func (s *sessions) Resume(ctx context.Context, _ http.ResponseWriter, r *http.Request) (session.Resumed, error) {
	s.mu.Lock()
	a, ok := s.byID[r.Header.Get(sessHdr)]
	s.mu.Unlock()
	if !ok {
		return session.Resumed{}, errors.New("no session")
	}
	e, err := s.ids.CurrentEpoch(ctx, a.Subject())
	if err != nil || e != a.Epoch() {
		return session.Resumed{}, errors.New("stale epoch")
	}
	h, err := session.NewHandle(a, uuid.New())
	if err != nil {
		return session.Resumed{}, err
	}
	return session.NewResumed(a, core.SealedClaims{}, h)
}

type completion struct {
	pending  core.Pending
	verified core.Verified
}

type fakeIssuer struct {
	clock    *clock.Test
	accounts *accounts
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
	var target redirect.Target
	if raw := r.Field(routes.FieldReturnTo); raw != "" {
		t, err := redirect.Parse(raw, f.origins)
		if err != nil {
			return core.Pending{}, httpx.ErrInvalidRequest
		}
		target = t
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
	return httpx.Response{Body: map[string]string{"state": "authenticated", "subject": v.Subject().User.String()}}, nil
}

func (f *fakeIssuer) Reauthenticate(context.Context, http.ResponseWriter, *httpx.Request, core.Verified) (httpx.Response, error) {
	return httpx.Response{}, httpx.ErrInternal
}

func (f *fakeIssuer) Reissue(context.Context, http.ResponseWriter, *httpx.Request, httpx.Change) error {
	return httpx.ErrInternal
}

func (f *fakeIssuer) completions() []completion {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]completion(nil), f.done...)
}

type origins struct{}

func (origins) PublicOrigin(core.TenantID) (string, error) { return origin, nil }

type headerTenants struct{}

func (headerTenants) ResolveTenant(r *http.Request) (core.TenantID, error) {
	return core.ParseTenantID(r.Header.Get("X-Tenant"))
}

type world struct {
	t          *testing.T
	clock      *clock.Test
	idp        *fakeIdP
	ids        identity.Store
	accounts   *accounts
	fed        storefed.Store
	ceremonies ceremony.Store
	sink       *recordingSink
	issuer     *fakeIssuer
	sessions   *sessions
	svc        *federationsvc.Service
	handler    http.Handler
	tenants    httpx.TenantResolver
	tenant     string
}

type config struct {
	oidc         bool
	issuerPath   string
	ev           federation.EmailVerification
	registration federationsvc.Registration
	tenants      httpx.TenantResolver
	tenant       string
	discover     bool
	perTenant    bool
}

func defaults() config {
	return config{oidc: true, ev: federation.Always, registration: federationsvc.RegistrationOpen}
}

func newWorld(t *testing.T, mods ...func(*config)) *world {
	t.Helper()
	c := defaults()
	for _, m := range mods {
		m(&c)
	}
	clk := clock.NewTest(start)
	ids := identitymem.NewWithClock(clk.Clock())
	w := &world{
		t:          t,
		clock:      clk,
		idp:        newIdP(t, clk, c.oidc, c.issuerPath),
		ids:        ids,
		accounts:   &accounts{Store: ids, unverified: map[core.Subject]bool{}},
		fed:        fedmem.NewWithClock(clk.Clock(), ids),
		ceremonies: ceremonymem.NewWithClock(clk.Clock()),
		sink:       &recordingSink{},
		tenants:    httpx.SingleTenant(),
		tenant:     c.tenant,
	}
	if c.tenants != nil {
		w.tenants = c.tenants
	}
	w.sessions = &sessions{byID: map[string]core.SessionAttrs{}, ids: ids}
	spec := w.idp.provider("idp", c.ev)
	if c.discover {
		spec.AuthURL, spec.TokenURL, spec.UserInfoURL, spec.JWKSURL = "", "", "", ""
	}
	cp, err := cookie.NewPolicy(cookie.Options{PublicOrigin: origin})
	if err != nil {
		t.Fatal(err)
	}
	static := []federation.Provider{spec}
	var k kek.KEK
	if c.perTenant {
		static, k = nil, w.storeProvider(spec)
	}
	svc, err := federationsvc.NewWithHTTPClient(context.Background(), federationsvc.Config{
		Providers:    static,
		PerTenant:    c.perTenant,
		KEK:          k,
		Federation:   w.fed,
		Users:        ids,
		Accounts:     w.accounts,
		Ceremonies:   w.ceremonies,
		Origins:      origins{},
		BasePath:     basePath,
		Cookies:      cp,
		DataKey:      testDataKey(),
		Registration: c.registration,
		Clock:        clk.Clock(),
		Audit:        httpx.SinkAudit(w.sink),
	}, w.idp.client())
	if err != nil {
		t.Fatal(err)
	}
	w.svc = svc
	ro, err := redirect.NewOrigins(origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.issuer = &fakeIssuer{clock: clk, accounts: w.accounts, origins: ro, mfa: map[core.Subject]bool{}}
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
		Tenants:       w.tenants,
		Limiter:       allowAll{},
		Authenticator: w.sessions,
		Issuer:        w.issuer,
		Identifiers:   identitysvc.Normalizer{},
		Enrollment:    noEnrollment{},
		Clock:         clk.Clock(),
		Audit:         httpx.SinkAudit(w.sink),
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

type call struct {
	method  string
	target  string
	fields  map[string]string
	bearer  bool
	session string
	cookies []*http.Cookie
	tenant  string
}

func (w *world) do(c call) *httptest.ResponseRecorder {
	w.t.Helper()
	var hr *http.Request
	if c.method == http.MethodPost {
		b, err := json.Marshal(c.fields)
		if err != nil {
			w.t.Fatal(err)
		}
		hr = httptest.NewRequest(http.MethodPost, c.target, strings.NewReader(string(b)))
		hr.Header.Set("Content-Type", "application/json")
		hr.Header.Set("Origin", origin)
		hr.Header.Set("Sec-Fetch-Site", "same-origin")
	} else {
		u, err := url.Parse(c.target)
		if err != nil {
			w.t.Fatal(err)
		}
		q := u.Query()
		for k, v := range c.fields {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		hr = httptest.NewRequest(http.MethodGet, u.String(), nil)
		hr.Header.Set("Sec-Fetch-Site", "cross-site")
		hr.Header.Set("Sec-Fetch-Mode", "navigate")
	}
	if c.bearer {
		hr.Header.Set(routes.HeaderTransport, "bearer")
	}
	if c.session != "" {
		hr.Header.Set(sessHdr, c.session)
	}
	tenant := c.tenant
	if tenant == "" {
		tenant = w.tenant
	}
	if tenant != "" {
		hr.Header.Set("X-Tenant", tenant)
	}
	for _, ck := range c.cookies {
		hr.AddCookie(ck)
	}
	hr.RemoteAddr = "198.51.100.7:4000"
	rec := httptest.NewRecorder()
	w.handler.ServeHTTP(rec, hr)
	return rec
}

func (w *world) begin(fields map[string]string) *httptest.ResponseRecorder {
	w.t.Helper()
	return w.do(call{method: http.MethodGet, target: origin + basePath + "/oauth/idp/begin", fields: fields})
}

func (w *world) authorize(authURL string) string {
	w.t.Helper()
	resp, err := w.idp.client().Get(authURL)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		w.t.Fatalf("authorize answered %d", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

func (w *world) callback(target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	w.t.Helper()
	return w.do(call{method: http.MethodGet, target: target, cookies: cookies})
}

func (w *world) login(fields map[string]string) (*httptest.ResponseRecorder, *http.Cookie) {
	w.t.Helper()
	rec := w.begin(fields)
	if rec.Code != http.StatusSeeOther {
		w.t.Fatalf("begin answered %d %s", rec.Code, rec.Body.String())
	}
	bind := bindCookie(rec)
	if bind == nil {
		w.t.Fatal("begin set no bind cookie")
	}
	return w.callback(w.authorize(rec.Header().Get("Location")), bind), bind
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

func (w *world) session(s core.Subject, tr core.Transport) string {
	w.t.Helper()
	e, err := w.ids.CurrentEpoch(context.Background(), s)
	if err != nil {
		w.t.Fatal(err)
	}
	a := principaltest.Attrs(principaltest.Spec{
		Lineage: uuid.New(), Subject: s, Factors: []core.Factor{core.FactorPassword}, PrimaryAt: w.clock.Now(),
		Epoch: e, Transport: tr, CreatedAt: w.clock.Now(),
	})
	id := uuid.NewString()
	w.sessions.mu.Lock()
	w.sessions.byID[id] = a
	w.sessions.mu.Unlock()
	return id
}

func (w *world) linked(sub string) (storefed.LinkedIdentity, error) {
	return w.fed.FindLinked(context.Background(), core.TenantID{}, storefed.LinkKey{Provider: "idp", ProviderSubject: sub})
}

func bindCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if strings.HasSuffix(c.Name, "egauth_bind") && c.MaxAge > 0 {
			return c
		}
	}
	return nil
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return m
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	s, _ := decode(t, rec)["error"].(string)
	return s
}
