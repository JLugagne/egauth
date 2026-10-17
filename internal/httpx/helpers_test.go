package httpx_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/clientaddr"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/limiter"
)

const (
	originTemplate = "https://{tenant}.example.com"
	origin         = "https://acme.example.com"
)

var acme = mustTenant("acme")

func mustTenant(s string) core.TenantID {
	t, err := core.ParseTenantID(s)
	if err != nil {
		panic(err)
	}
	return t
}

func csrfOrigins(public string) (csrf.Origins, error) {
	return csrf.NewOrigins(public, nil)
}

var start = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

type recorder struct {
	mu    sync.Mutex
	steps []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, s)
}

func (r *recorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.steps...)
}

type fakeTenants struct {
	rec *recorder
	t   core.TenantID
	err error
}

func (f *fakeTenants) ResolveTenant(*http.Request) (core.TenantID, error) {
	f.rec.add("tenant")
	return f.t, f.err
}

type fakeLimiter struct {
	rec   *recorder
	keys  []limiter.Key
	deny  map[limiter.Class]bool
	err   error
	retry time.Duration
}

func (f *fakeLimiter) Allow(_ context.Context, k limiter.Key) (limiter.Decision, error) {
	f.rec.add("limit:" + k.Class.String())
	f.keys = append(f.keys, k)
	if f.err != nil {
		return limiter.Decision{}, f.err
	}
	if f.deny[k.Class] {
		return limiter.Decision{RetryAfter: f.retry}, nil
	}
	return limiter.Decision{Allowed: true}, nil
}

type fakeAuth struct {
	rec        *recorder
	attrs      core.SessionAttrs
	err        error
	setCookie  string
	setHeaders map[string]string
}

func (f *fakeAuth) Resume(_ context.Context, w http.ResponseWriter, _ *http.Request, _ core.TenantID) (session.Resumed, error) {
	f.rec.add("resume")
	if f.setCookie != "" {
		w.Header().Add("Set-Cookie", f.setCookie)
	}
	for k, v := range f.setHeaders {
		w.Header().Set(k, v)
	}
	if f.err != nil {
		return session.Resumed{}, f.err
	}
	h, err := session.NewHandle(f.attrs, uuid.New())
	if err != nil {
		return session.Resumed{}, err
	}
	return session.NewResumed(f.attrs, core.SealedClaims{}, h)
}

type fakeNormalizer struct{}

func (fakeNormalizer) Normalize(raw string) (identity.Identifier, error) {
	if !strings.Contains(raw, "@") {
		return identity.Identifier{}, errors.New("not an email")
	}
	return identity.NewIdentifier(identity.IdentifierEmail, strings.ToLower(strings.TrimSpace(raw)))
}

type fakeEnrollment struct {
	rec      *recorder
	required bool
	err      error
}

func (f *fakeEnrollment) MFARequired(context.Context, core.Subject) (bool, error) {
	f.rec.add("enrollment")
	return f.required, f.err
}

type fakeHook struct {
	rec  *recorder
	err  error
	last httpx.EndpointCall
}

func (f *fakeHook) BeforeEndpoint(_ context.Context, c httpx.EndpointCall) error {
	f.rec.add("hook")
	f.last = c
	return f.err
}

type world struct {
	rec    *recorder
	tenant *fakeTenants
	lim    *fakeLimiter
	auth   *fakeAuth
	enr    *fakeEnrollment
	hook   *fakeHook
	clock  *clock.Test
	set    httpx.Settings
}

func subject(t core.TenantID) core.Subject {
	return core.Subject{Tenant: t, User: uuid.MustParse("6f1c3d1e-7a51-4c55-9a43-6bde0e1f5a10")}
}

func attrs(f core.ForTestAttrs) core.SessionAttrs {
	if f.Lineage == uuid.Nil {
		f.Lineage = uuid.MustParse("0b3a8e8a-27e6-4d8e-8f0e-6d0b7a0b6e11")
	}
	if f.Transport == 0 {
		f.Transport = core.TransportCookies
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = start
	}
	return core.ForTestSessionAttrs(f)
}

func freshPasswordSession() core.SessionAttrs {
	return attrs(core.ForTestAttrs{Subject: subject(acme), Factors: []core.Factor{core.FactorPassword}, PrimaryAt: start})
}

func newWorld(t *testing.T) *world {
	t.Helper()
	rec := &recorder{}
	res, err := clientaddr.New(clientaddr.Direct(), nil)
	if err != nil {
		t.Fatal(err)
	}
	o, err := csrf.NewOrigins(originTemplate, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &world{
		rec:    rec,
		tenant: &fakeTenants{rec: rec, t: acme},
		lim:    &fakeLimiter{rec: rec, deny: map[limiter.Class]bool{}},
		auth:   &fakeAuth{rec: rec, attrs: freshPasswordSession()},
		enr:    &fakeEnrollment{rec: rec},
		hook:   &fakeHook{rec: rec},
		clock:  clock.NewTest(start.Add(time.Minute)),
		set: httpx.Settings{
			Clients:      res,
			Origins:      o,
			Transports:   httpx.CookiesAndBearer,
			ReauthWindow: 10 * time.Minute,
		},
	}
}

func (w *world) env() httpx.Env {
	return httpx.Env{
		Tenants:        w.tenant,
		Limiter:        w.lim,
		Authenticator:  w.auth,
		Identifiers:    fakeNormalizer{},
		Enrollment:     w.enr,
		BeforeEndpoint: w.hook,
		Clock:          w.clock.Clock(),
		Audit:          httpx.SinkAudit(nil),
	}
}

func (w *world) handler(t *testing.T, meta httpx.Meta, f httpx.EndpointFunc) http.Handler {
	t.Helper()
	p, err := httpx.NewPreamble(w.env(), w.set)
	if err != nil {
		t.Fatal(err)
	}
	if f == nil {
		f = func(rw http.ResponseWriter, r *httpx.Request) {
			w.rec.add("endpoint")
			r.Respond(rw, httpx.Response{Body: map[string]string{"ok": "1"}})
		}
	}
	h, err := p.Wrap("/login", meta, f)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

type trackingBody struct {
	r    io.Reader
	read bool
}

func (b *trackingBody) Read(p []byte) (int, error) {
	b.read = true
	return b.r.Read(p)
}

func (b *trackingBody) Close() error { return nil }

func post(body, contentType string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, origin+"/auth/login", strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	r.Header.Set("Origin", origin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.RemoteAddr = "198.51.100.7:4000"
	return r
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	body := w.Body.String()
	_, after, ok := strings.Cut(body, `"error":"`)
	if !ok {
		return ""
	}
	code, _, _ := strings.Cut(after, `"`)
	return code
}

func loginMeta() httpx.Meta {
	return httpx.Meta{
		Mutation: true, IdentifierKeyed: true, SetsCookies: true, BodyCap: httpx.FormBodyCap,
		ClientLimit: limiter.LoginClient, IdentifierLimit: limiter.LoginIdentifier,
	}
}

func sensitiveMeta() httpx.Meta {
	return httpx.Meta{
		Authenticated: true, Mutation: true, Sensitive: true, BodyCap: httpx.FormBodyCap,
		ClientLimit: limiter.LoginClient,
	}
}
