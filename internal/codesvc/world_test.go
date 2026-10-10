package codesvc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/clientaddr"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/codesvc"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	ceremonymem "github.com/JLugagne/egauth/store/ceremony/memory"
	"github.com/JLugagne/egauth/store/identity"
	identitymem "github.com/JLugagne/egauth/store/identity/memory"
	"github.com/JLugagne/egauth/store/limiter"
)

const (
	origin   = "https://auth.example.com"
	basePath = "/auth"
)

var start = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func testDataKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)*13 + 5
	}
	return k
}

type sent struct {
	kind string
	to   string
	link string
	code string
}

type fakeDelivery struct {
	mu   sync.Mutex
	msgs []sent
	err  error
}

func (d *fakeDelivery) add(s sent) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.msgs = append(d.msgs, s)
	return d.err
}

func (d *fakeDelivery) all() []sent {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]sent(nil), d.msgs...)
}

type fakeMailer struct{ *fakeDelivery }

func (m fakeMailer) MagicLink(_ context.Context, l identitysvc.LinkMessage) error {
	return m.add(sent{kind: "magic_link", to: l.To, link: l.Link})
}

func (m fakeMailer) LoginCode(_ context.Context, c codesvc.CodeMessage) error {
	return m.add(sent{kind: "email_code", to: c.To, code: c.Code})
}

type fakeTexter struct{ *fakeDelivery }

func (m fakeTexter) LoginCode(_ context.Context, c codesvc.CodeMessage) error {
	return m.add(sent{kind: "sms_code", to: c.To, code: c.Code})
}

type fakeLinks struct{}

func (fakeLinks) Link(_ context.Context, t core.TenantID, k ceremony.Kind, handle string) (string, error) {
	return origin + "/" + k.String() + "?tenant=" + t.String() + "&token=" + url.QueryEscape(handle), nil
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

type accountView struct {
	identity.Store
	mu         sync.Mutex
	unverified map[core.Subject]bool
}

func (v *accountView) hide(u identity.User) identity.User {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.unverified[u.Subject] {
		u.EmailVerifiedAt = time.Time{}
	}
	return u
}

func (v *accountView) GetUser(ctx context.Context, s core.Subject) (identity.User, error) {
	u, err := v.Store.GetUser(ctx, s)
	return v.hide(u), err
}

func (v *accountView) FindUser(ctx context.Context, t core.TenantID, id identity.Identifier) (identity.User, error) {
	u, err := v.Store.FindUser(ctx, t, id)
	return v.hide(u), err
}

func (v *accountView) AccountState(ctx context.Context, s core.Subject) (core.AccountState, error) {
	u, err := v.GetUser(ctx, s)
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
	accounts *accountView
	origins  redirect.Origins
	mfa      map[core.Subject]bool
	mu       sync.Mutex
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
	var decision core.MFADecision
	if enrolled {
		decision = core.NewMFADecision([]core.Factor{core.FactorTOTP})
	} else {
		decision = core.NewMFADecision(nil)
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

func (f *fakeIssuer) completions() []completion {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]completion(nil), f.done...)
}

type world struct {
	t          *testing.T
	clock      *clock.Test
	raw        identity.Store
	accounts   *accountView
	ceremonies ceremony.Store
	counted    *countingStore
	mail       *fakeDelivery
	sms        *fakeDelivery
	sink       *recordingSink
	issuer     *fakeIssuer
	svc        *codesvc.Service
	cookies    cookie.Policy
	handler    http.Handler
}

type option func(*codesvc.Config)

func newWorld(t *testing.T, opts ...option) *world {
	t.Helper()
	clk := clock.NewTest(start)
	raw := identitymem.NewWithClock(clk.Clock())
	counted := &countingStore{Store: ceremonymem.NewWithClock(clk.Clock())}
	w := &world{
		t:          t,
		clock:      clk,
		raw:        raw,
		accounts:   &accountView{Store: raw, unverified: map[core.Subject]bool{}},
		ceremonies: counted,
		counted:    counted,
		mail:       &fakeDelivery{},
		sms:        &fakeDelivery{},
		sink:       &recordingSink{},
	}
	return w.build(opts...)
}

func (w *world) build(opts ...option) *world {
	t := w.t
	t.Helper()
	cp, err := cookie.NewPolicy(cookie.Options{PublicOrigin: origin})
	if err != nil {
		t.Fatal(err)
	}
	w.cookies = cp
	cfg := codesvc.Config{
		Identity:   w.accounts,
		Accounts:   w.accounts,
		Ceremonies: w.ceremonies,
		Mailer:     fakeMailer{w.mail},
		Texter:     fakeTexter{w.sms},
		Links:      fakeLinks{},
		Cookies:    cp,
		DataKey:    testDataKey(),
		MagicLink:  true,
		EmailCodes: true,
		SMSCodes:   true,
		Clock:      w.clock.Clock(),
		Audit:      httpx.SinkAudit(w.sink),
	}
	for _, o := range opts {
		o(&cfg)
	}
	svc, err := codesvc.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w.svc = svc
	t.Cleanup(func() { _ = svc.Close() })
	origins, err := redirect.NewOrigins(origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.issuer = &fakeIssuer{clock: w.clock, accounts: w.accounts, origins: origins, mfa: map[core.Subject]bool{}}
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
		Tenants:       httpx.SingleTenant(),
		Limiter:       allowAll{},
		Authenticator: noSession{},
		Issuer:        w.issuer,
		Identifiers:   identitysvc.Normalizer{},
		Enrollment:    noEnrollment{},
		Clock:         w.clock.Clock(),
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

func (w *world) flush() {
	w.t.Helper()
	if err := w.svc.Close(); err != nil {
		w.t.Fatal(err)
	}
}

type req struct {
	path    string
	fields  map[string]string
	bearer  bool
	cookies []*http.Cookie
}

func (w *world) do(r req) *httptest.ResponseRecorder {
	w.t.Helper()
	fields := r.fields
	if fields == nil {
		fields = map[string]string{}
	}
	b, err := json.Marshal(fields)
	if err != nil {
		w.t.Fatal(err)
	}
	hr := httptest.NewRequest(http.MethodPost, origin+basePath+r.path, strings.NewReader(string(b)))
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Origin", origin)
	hr.Header.Set("Sec-Fetch-Site", "same-origin")
	if r.bearer {
		hr.Header.Set(routes.HeaderTransport, "bearer")
	}
	for _, c := range r.cookies {
		hr.AddCookie(c)
	}
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
	a, err := w.raw.Apply(context.Background(), identity.CreateVerified{Email: id})
	if err != nil {
		w.t.Fatal(err)
	}
	return a.Subject
}

func (w *world) withPhone(s core.Subject, phone string) {
	w.t.Helper()
	id, err := identitysvc.NormalizeAs(identity.IdentifierPhone, phone)
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.raw.Apply(context.Background(), identity.SetPhone{Subject: s, Phone: id}); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) waitSent(d *fakeDelivery, n int) []sent {
	w.t.Helper()
	for range 2000 {
		if got := d.all(); len(got) >= n {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	w.t.Fatalf("waited for %d messages, got %v", n, d.all())
	return nil
}

func bindCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if strings.HasSuffix(c.Name, "egauth_bind") && c.MaxAge > 0 {
			return c
		}
	}
	return nil
}

func tokenOf(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("token")
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return m
}

type countingStore struct {
	ceremony.Store
	charged atomic.Int64
}

func (c *countingStore) RecordFailure(ctx context.Context, t core.TenantID, k ceremony.Kind, h []byte) (int, error) {
	n, err := c.Store.RecordFailure(ctx, t, k, h)
	if err == nil {
		c.charged.Add(1)
	}
	return n, err
}
