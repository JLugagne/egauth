package identitysvc_test

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
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/clientaddr"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	ceremonymem "github.com/JLugagne/egauth/store/ceremony/memory"
	"github.com/JLugagne/egauth/store/identity"
	identitymem "github.com/JLugagne/egauth/store/identity/memory"
	"github.com/JLugagne/egauth/store/limiter"
	"github.com/JLugagne/egauth/store/mfa"
	mfamem "github.com/JLugagne/egauth/store/mfa/memory"
	"github.com/JLugagne/egauth/store/passkey"
	passkeymem "github.com/JLugagne/egauth/store/passkey/memory"
)

const (
	origin   = "https://auth.example.com"
	basePath = "/auth"
	goodPass = "correct horse battery"
)

var start = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

type fakeHasher struct {
	hashes   atomic.Int64
	compares atomic.Int64
}

func (h *fakeHasher) Hash(_ context.Context, password string) (string, error) {
	h.hashes.Add(1)
	if len(password) > passwords.MaxPasswordLength {
		return "", passwords.ErrPasswordTooLong
	}
	return "$fake$" + password, nil
}

func (h *fakeHasher) Compare(_ context.Context, hash, password string) error {
	h.compares.Add(1)
	if len(password) > passwords.MaxPasswordLength || hash != "$fake$"+password {
		return passwords.ErrInvalidPassword
	}
	return nil
}

type acceptAll struct{}

func (acceptAll) Verify(context.Context, string) error { return nil }

type sent struct {
	kind string
	to   string
	link string
}

type fakeMailer struct {
	mu   sync.Mutex
	msgs []sent
	err  error
}

func (m *fakeMailer) add(s sent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, s)
	return m.err
}

func (m *fakeMailer) RegistrationLink(_ context.Context, l identitysvc.LinkMessage) error {
	return m.add(sent{kind: "registration", to: l.To, link: l.Link})
}

func (m *fakeMailer) AccountExistsNotice(_ context.Context, n identitysvc.NoticeMessage) error {
	return m.add(sent{kind: "account_exists", to: n.To})
}

func (m *fakeMailer) PasswordResetLink(_ context.Context, l identitysvc.LinkMessage) error {
	return m.add(sent{kind: "reset", to: l.To, link: l.Link})
}

func (m *fakeMailer) all() []sent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]sent(nil), m.msgs...)
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

func (s *recordingSink) types() []event.Type {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []event.Type
	for _, e := range s.events {
		out = append(out, e.Type)
	}
	return out
}

func (s *recordingSink) has(t event.Type) bool {
	for _, got := range s.types() {
		if got == t {
			return true
		}
	}
	return false
}

type admission struct {
	subject core.Subject
	factors []core.Factor
}

type fakeIssuer struct {
	svc   *identitysvc.Service
	clock *clock.Test
	mu    sync.Mutex
	done  []admission
}

func (f *fakeIssuer) Begin(_ context.Context, r *httpx.Request) (core.Pending, error) {
	remember := core.RememberDeclined
	if r.Flag(routes.FieldRemember) {
		remember = core.RememberRequested
	}
	return core.NewPending(r.Tenant(), remember, redirect.Target{}, r.Transport(), core.RememberUserChoice, f.clock.Now())
}

func (f *fakeIssuer) Complete(ctx context.Context, _ http.ResponseWriter, _ *httpx.Request, p core.Pending, v core.Verified) (httpx.Response, error) {
	st, err := f.svc.AccountState(ctx, v.Subject())
	if err != nil {
		return httpx.Response{}, err
	}
	p, err = p.Add(v, st)
	if err != nil {
		return httpx.Response{}, errors.Join(httpx.ErrUnauthenticated, err)
	}
	adm, err := core.Admit(p, st, core.NewMFADecision(nil), f.clock.Now())
	if err != nil {
		return httpx.Response{}, errors.Join(httpx.ErrUnauthenticated, err)
	}
	a, ok := adm.Session()
	if !ok {
		return httpx.Response{}, httpx.ErrUnauthenticated
	}
	f.mu.Lock()
	f.done = append(f.done, admission{subject: a.Subject(), factors: a.Factors()})
	f.mu.Unlock()
	return httpx.Response{Body: map[string]string{"state": "authenticated"}}, nil
}

func (f *fakeIssuer) Reauthenticate(context.Context, http.ResponseWriter, *httpx.Request, core.Verified) (httpx.Response, error) {
	return httpx.Response{}, httpx.ErrInternal
}

func (f *fakeIssuer) Reissue(context.Context, http.ResponseWriter, *httpx.Request, httpx.Change) error {
	return httpx.ErrInternal
}

func (f *fakeIssuer) admissions() []admission {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]admission(nil), f.done...)
}

type recordingLimiter struct {
	mu   sync.Mutex
	keys []limiter.Key
}

func (l *recordingLimiter) Allow(_ context.Context, k limiter.Key) (limiter.Decision, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = append(l.keys, k)
	return limiter.Decision{Allowed: true}, nil
}

func (l *recordingLimiter) identifierKeys() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, k := range l.keys {
		if k.Class.PerTenant() {
			out = append(out, k.Value)
		}
	}
	return out
}

type noSession struct{}

func (noSession) Resume(context.Context, http.ResponseWriter, *http.Request) (session.Resumed, error) {
	return session.Resumed{}, errors.New("no session")
}

type noEnrollment struct{}

func (noEnrollment) MFARequired(context.Context, core.Subject) (bool, error) { return false, nil }

type world struct {
	t          *testing.T
	clock      *clock.Test
	identity   identity.Store
	ceremonies *ceremonymem.Store
	mfa        mfa.Store
	passkeys   passkey.Store
	hasher     *fakeHasher
	mailer     *fakeMailer
	sink       *recordingSink
	limiter    *recordingLimiter
	issuer     *fakeIssuer
	svc        *identitysvc.Service
	cookies    cookie.Policy
	handler    http.Handler
	closed     bool
}

type option func(*identitysvc.Config)

func newWorld(t *testing.T, opts ...option) *world {
	t.Helper()
	return newWorldWrapping(t, nil, opts...)
}

func newWorldWrapping(t *testing.T, wrap func(identity.Store) identity.Store, opts ...option) *world {
	t.Helper()
	clk := clock.NewTest(start)
	w := &world{
		t:          t,
		clock:      clk,
		identity:   identitymem.NewWithClock(clk.Clock()),
		ceremonies: ceremonymem.NewWithClock(clk.Clock()),
		mfa:        mfamem.NewWithClock(clk.Clock()),
		passkeys:   passkeymem.New(),
		hasher:     &fakeHasher{},
		mailer:     &fakeMailer{},
		sink:       &recordingSink{},
		limiter:    &recordingLimiter{},
	}
	if wrap != nil {
		w.identity = wrap(w.identity)
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
	cfg := identitysvc.Config{
		Identity:         w.identity,
		Ceremonies:       w.ceremonies,
		MFA:              w.mfa,
		Passkeys:         w.passkeys,
		Hasher:           w.hasher,
		Policy:           acceptAll{},
		Mailer:           w.mailer,
		Links:            fakeLinks{},
		Cookies:          cp,
		DataKey:          testDataKey(9),
		OpenRegistration: true,
		Clock:            w.clock.Clock(),
		Audit:            httpx.SinkAudit(w.sink),
	}
	for _, o := range opts {
		o(&cfg)
	}
	svc, err := identitysvc.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w.svc = svc
	t.Cleanup(func() { _ = svc.Close() })
	w.issuer = &fakeIssuer{svc: svc, clock: w.clock}
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
		Limiter:       w.limiter,
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
	form    bool
	cookies []*http.Cookie
}

func (w *world) do(r req) *httptest.ResponseRecorder {
	w.t.Helper()
	var body, ct string
	if r.form {
		vs := url.Values{}
		for k, v := range r.fields {
			vs.Set(k, v)
		}
		body, ct = vs.Encode(), "application/x-www-form-urlencoded"
	} else {
		b, err := json.Marshal(r.fields)
		if err != nil {
			w.t.Fatal(err)
		}
		body, ct = string(b), "application/json"
	}
	hr := httptest.NewRequest(http.MethodPost, origin+basePath+r.path, strings.NewReader(body))
	hr.Header.Set("Content-Type", ct)
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

func (w *world) waitMail(n int) []sent {
	w.t.Helper()
	for range 2000 {
		if got := w.mailer.all(); len(got) >= n {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	w.t.Fatalf("waited for %d messages, got %v", n, w.mailer.all())
	return nil
}

func (w *world) createVerified(email, password string) core.Subject {
	w.t.Helper()
	id, err := identitysvc.NormalizeAs(identity.IdentifierEmail, email)
	if err != nil {
		w.t.Fatal(err)
	}
	var phc identity.PasswordHash
	if password != "" {
		h, err := w.hasher.Hash(context.Background(), passwords.Canonical(password))
		if err != nil {
			w.t.Fatal(err)
		}
		phc = identity.NewPasswordHash(h)
	}
	a, err := w.identity.Apply(context.Background(), identity.CreateVerified{Email: id, PHC: phc})
	if err != nil {
		w.t.Fatal(err)
	}
	return a.Subject
}

func (w *world) epoch(s core.Subject) uint64 {
	w.t.Helper()
	e, err := w.identity.CurrentEpoch(context.Background(), s)
	if err != nil {
		w.t.Fatal(err)
	}
	return e
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

func noAudit() httpx.Audit {
	return auditFunc(func(context.Context, event.Type, audit.Scope, audit.Detail, error, ...audit.Attr) error { return nil })
}

type auditFunc func(context.Context, event.Type, audit.Scope, audit.Detail, error, ...audit.Attr) error

func (f auditFunc) Emit(ctx context.Context, t event.Type, s audit.Scope, d audit.Detail, cause error, attrs ...audit.Attr) error {
	return f(ctx, t, s, d, cause, attrs...)
}

type unverifiedStore struct {
	identity.Store
	mu         sync.Mutex
	unverified map[core.Subject]bool
	noPassword map[core.Subject]bool
	marked     []identity.MarkEmailVerified
	getErr     error
	passErr    error
	afterApply func(identity.Mutation)
}

func newUnverifiedStore(inner identity.Store) *unverifiedStore {
	return &unverifiedStore{Store: inner, unverified: map[core.Subject]bool{}, noPassword: map[core.Subject]bool{}}
}

func (s *unverifiedStore) setUnverified(sub core.Subject) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unverified[sub] = true
}

func (s *unverifiedStore) marks() []identity.MarkEmailVerified {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]identity.MarkEmailVerified(nil), s.marked...)
}

func (s *unverifiedStore) view(u identity.User) identity.User {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unverified[u.Subject] {
		u.EmailVerifiedAt = time.Time{}
	}
	return u
}

func (s *unverifiedStore) GetUser(ctx context.Context, sub core.Subject) (identity.User, error) {
	if s.getErr != nil {
		return identity.User{}, s.getErr
	}
	u, err := s.Store.GetUser(ctx, sub)
	return s.view(u), err
}

func (s *unverifiedStore) FindUser(ctx context.Context, t core.TenantID, id identity.Identifier) (identity.User, error) {
	u, err := s.Store.FindUser(ctx, t, id)
	return s.view(u), err
}

func (s *unverifiedStore) onApply(f func(identity.Mutation)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.afterApply = f
}

func (s *unverifiedStore) GetPassword(ctx context.Context, sub core.Subject) (identity.PasswordCredential, error) {
	if s.passErr != nil {
		return identity.PasswordCredential{}, s.passErr
	}
	s.mu.Lock()
	gone := s.noPassword[sub]
	s.mu.Unlock()
	if gone {
		return identity.PasswordCredential{}, store.ErrNotFound
	}
	return s.Store.GetPassword(ctx, sub)
}

func (s *unverifiedStore) Apply(ctx context.Context, m identity.Mutation) (identity.Applied, error) {
	a, err := s.apply(ctx, m)
	s.mu.Lock()
	hook := s.afterApply
	s.mu.Unlock()
	if err == nil && hook != nil {
		hook(m)
	}
	return a, err
}

func (s *unverifiedStore) apply(ctx context.Context, m identity.Mutation) (identity.Applied, error) {
	mark, ok := m.(identity.MarkEmailVerified)
	if !ok {
		return s.Store.Apply(ctx, m)
	}
	s.mu.Lock()
	if !s.unverified[mark.Subject] {
		s.mu.Unlock()
		return identity.Applied{}, store.ErrConflict
	}
	delete(s.unverified, mark.Subject)
	s.marked = append(s.marked, mark)
	s.noPassword[mark.Subject] = mark.PHC.IsZero()
	s.mu.Unlock()
	if mark.PHC.IsZero() {
		return s.Store.Apply(ctx, identity.BumpEpoch{Subject: mark.Subject, Change: identity.FactorTOTPRemoved})
	}
	return s.Store.Apply(ctx, identity.SetPassword{Subject: mark.Subject, PHC: mark.PHC, Reason: identity.RotationPasswordReset})
}

type countingCeremonies struct {
	ceremony.Store
	puts   atomic.Int64
	putErr error
}

func (c *countingCeremonies) Put(ctx context.Context, r ceremony.Record) (int, error) {
	c.puts.Add(1)
	if c.putErr != nil {
		return 0, c.putErr
	}
	return c.Store.Put(ctx, r)
}
