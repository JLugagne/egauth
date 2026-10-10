package flow_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/flow"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/issuance"
	"github.com/JLugagne/egauth/internal/mfasvc"
	"github.com/JLugagne/egauth/internal/passkeysvc"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/internal/session/endpoints"
	"github.com/JLugagne/egauth/internal/session/stateful"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	ceremonymem "github.com/JLugagne/egauth/store/ceremony/memory"
	"github.com/JLugagne/egauth/store/identity"
	identitymem "github.com/JLugagne/egauth/store/identity/memory"
	"github.com/JLugagne/egauth/store/limiter"
	"github.com/JLugagne/egauth/store/mfa"
	mfamem "github.com/JLugagne/egauth/store/mfa/memory"
	passkeymem "github.com/JLugagne/egauth/store/passkey/memory"
	sessionsmem "github.com/JLugagne/egauth/store/sessions/memory"
	"github.com/JLugagne/egauth/webauthntest"
)

const (
	origin   = "https://auth.example.com"
	basePath = "/auth"
)

var (
	start    = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	lifetime = session.Lifetimes{IdleTimeout: 30 * time.Minute, MaxLifetime: 24 * time.Hour, RecheckEvery: 5 * time.Minute}
	window   = 10 * time.Minute
)

var (
	_ issuance.Completer = (*flow.Service)(nil)
	_ flow.Issuer        = (*issuance.Issuer)(nil)
	_ flow.SecondFactors = (*mfasvc.Service)(nil)
	_ flow.StepUp        = (*passkeysvc.Service)(nil)
	_ flow.Flows         = ceremony.Store(nil)
)

type recordingSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (s *recordingSink) EmitEvent(_ context.Context, e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *recordingSink) count(t event.Type) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.events {
		if e.Type == t {
			n++
		}
	}
	return n
}

func (s *recordingSink) last(t event.Type) (event.Event, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].Type == t {
			return s.events[i], true
		}
	}
	return event.Event{}, false
}

func (s *recordingSink) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = nil
}

type allowAll struct{}

func (allowAll) Allow(context.Context, limiter.Key) (limiter.Decision, error) {
	return limiter.Decision{Allowed: true}, nil
}

type accounts struct{ identity identity.Store }

func (a accounts) AccountState(ctx context.Context, s core.Subject) (core.AccountState, error) {
	u, err := a.identity.GetUser(ctx, s)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return core.AccountState{}, nil
	case err != nil:
		return core.AccountState{}, errors.Join(httpx.ErrUnavailable, err)
	}
	return core.NewAccountState(true, !u.DisabledAt.IsZero(), !u.DeletedAt.IsZero(), u.MustChange, !u.EmailVerifiedAt.IsZero(), u.SecurityEpoch), nil
}

type authority struct {
	accounts
	*issuance.Enrollment
}

type claimsSource struct{ down atomic.Bool }

func (c *claimsSource) ClaimsFor(context.Context, core.Subject) ([]byte, error) {
	if c.down.Load() {
		return nil, errors.New("claims source down")
	}
	return []byte(`{"roles":["member"]}`), nil
}

type flakyMFA struct {
	mfa.Store
	down atomic.Bool
}

func (f *flakyMFA) HasConfirmedTOTP(ctx context.Context, s core.Subject) (bool, error) {
	if f.down.Load() {
		return false, errors.New("mfa store down")
	}
	return f.Store.HasConfirmedTOTP(ctx, s)
}

var errBadPassword = httpx.NewProblem(http.StatusUnauthorized, "invalid_credentials")

type passwords struct {
	mu     sync.Mutex
	byID   map[string]core.Subject
	secret map[core.Subject]string
	checks atomic.Int64
}

func (p *passwords) CheckPassword(_ context.Context, s core.Subject, password string) error {
	p.checks.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	if want, ok := p.secret[s]; !ok || want != password {
		return errBadPassword
	}
	return nil
}

func (p *passwords) lookup(identifier, password string) (core.Subject, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.byID[identifier]
	if !ok || p.secret[s] != password {
		return core.Subject{}, false
	}
	return s, true
}

type mutator struct{ identity identity.Store }

func (m mutator) Apply(ctx context.Context, mu identity.Mutation) (identity.Applied, error) {
	return m.identity.Apply(ctx, mu)
}

type origins struct{ o redirect.Origins }

func (o origins) Origins(core.TenantID) (redirect.Origins, error) { return o.o, nil }

type options struct {
	noMFAModule     bool
	noPasskeyModule bool
	noPasswords     bool
	pages           issuance.Pages
}

type world struct {
	t          *testing.T
	clock      *clock.Test
	identity   identity.Store
	mfa        *flakyMFA
	passkeys   *passkeymem.Store
	ceremonies *ceremonymem.Store
	sessions   *sessionsmem.Store
	sink       *recordingSink
	claims     *claimsSource
	passwords  *passwords
	cookies    cookie.Policy
	backend    *stateful.Backend
	issuer     *issuance.Issuer
	flow       *flow.Service
	handler    http.Handler
}

func newWorld(t *testing.T) *world { return newWorldWith(t, options{}) }

func newWorldWith(t *testing.T, o options) *world {
	t.Helper()
	clk := clock.NewTest(start)
	w := &world{
		t:          t,
		clock:      clk,
		identity:   identitymem.NewWithClock(clk.Clock()),
		mfa:        &flakyMFA{Store: mfamem.NewWithClock(clk.Clock())},
		passkeys:   passkeymem.New(),
		ceremonies: ceremonymem.NewWithClock(clk.Clock()),
		sessions:   sessionsmem.NewWithClock(clk.Clock()),
		sink:       &recordingSink{},
		claims:     &claimsSource{},
		passwords:  &passwords{byID: map[string]core.Subject{}, secret: map[core.Subject]string{}},
	}
	audit := httpx.SinkAudit(w.sink)
	cp, err := cookie.NewPolicy(cookie.Options{PublicOrigin: origin})
	must(t, err)
	w.cookies = cp
	enrollment, err := issuance.NewEnrollment(w.mfa, w.passkeys)
	must(t, err)
	acc := accounts{identity: w.identity}
	renewer, err := session.NewRenewer(session.RenewConfig{
		Authority: authority{accounts: acc, Enrollment: enrollment}, Claims: w.claims, Lifetimes: lifetime,
		Clock: clk.Clock(), Events: w.sink,
	})
	must(t, err)
	epochs, err := revoke.NewEpochs(w.identity, revoke.Config{Clock: clk.Clock(), Events: w.sink})
	must(t, err)
	w.backend, err = stateful.New(stateful.Config{
		Sessions: w.sessions, Epochs: epochs, Renewer: renewer, Cookies: cp, Clock: clk.Clock(), Events: w.sink,
	})
	must(t, err)
	trusted, err := csrf.NewOrigins(origin, nil)
	must(t, err)
	k, err := kek.NewLocal(sha(t, "egauth/flow_test/kek"))
	must(t, err)
	mfaSvc, err := mfasvc.New(mfasvc.Config{
		MFA: w.mfa, Passkeys: w.passkeys, Identity: w.identity, Mutations: mutator{w.identity}, KEK: k,
		TOTPIssuer: "Example", Clock: clk.Clock(), Audit: audit,
	})
	must(t, err)
	pkSvc, err := passkeysvc.New(passkeysvc.Config{
		Passkeys: w.passkeys, MFA: w.mfa, Identity: w.identity, Accounts: acc, Mutations: mutator{w.identity},
		Ceremonies: w.ceremonies, Origins: trusted, Cookies: cp, DisplayName: "Example",
		DataKey: sha(t, "egauth/flow_test/data"), Clock: clk.Clock(), Audit: audit,
	})
	must(t, err)
	fc := flow.Config{Flows: w.ceremonies, Cookies: cp, Clock: clk.Clock(), Audit: audit}
	if !o.noMFAModule {
		fc.SecondFactors = mfaSvc
	}
	if !o.noPasskeyModule {
		fc.StepUp = pkSvc
	}
	if !o.noPasswords {
		fc.Passwords = w.passwords
	}
	w.flow, err = flow.New(fc)
	must(t, err)
	ro, err := redirect.NewOrigins(origin, nil)
	must(t, err)
	w.issuer, err = issuance.New(issuance.Config{
		Accounts: acc, Enrollment: enrollment, Backend: w.backend, Claims: renewer, Flows: w.ceremonies,
		Completer: w.flow, Cookies: cp, Origins: origins{ro}, RememberMe: core.RememberUserChoice,
		Pages: o.pages, Clock: clk.Clock(), Audit: audit,
	})
	must(t, err)
	eps, err := w.flow.Endpoints(w.issuer)
	must(t, err)
	more, err := mfaSvc.Endpoints(w.issuer)
	must(t, err)
	eps = append(eps, more...)
	more, err = pkSvc.Endpoints(w.issuer)
	must(t, err)
	eps = append(eps, more...)
	more, err = endpoints.Endpoints(endpoints.Config{Backend: w.backend, Audit: audit})
	must(t, err)
	eps = append(eps, more...)
	login, err := routes.NewEndpoint(routes.Login, w.login)
	must(t, err)
	change, err := routes.NewEndpoint(routes.PasswordChange, w.passwordChange)
	must(t, err)
	eps = append(eps, login, change)
	table, err := routes.NewTable(eps...)
	must(t, err)
	res, err := clientaddr.New(clientaddr.Direct(), nil)
	must(t, err)
	p, err := httpx.NewPreamble(httpx.Env{
		Tenants: httpx.SingleTenant(), Limiter: allowAll{}, Authenticator: w.backend, Issuer: w.issuer,
		Identifiers: identitysvc.Normalizer{}, Enrollment: enrollment, Clock: clk.Clock(), Audit: audit,
	}, httpx.Settings{Clients: res, Origins: trusted, Transports: httpx.CookiesAndBearer, ReauthWindow: window})
	must(t, err)
	mux := http.NewServeMux()
	must(t, table.Mount(mux, basePath, p))
	w.handler = mux
	return w
}

func (w *world) login(rw http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	p, err := w.issuer.Begin(ctx, r)
	if err != nil {
		r.Fail(rw, err)
		return
	}
	sub, ok := w.passwords.lookup(r.Field(routes.FieldIdentifier), r.Field(routes.FieldPassword))
	if !ok {
		r.Fail(rw, errBadPassword)
		return
	}
	v, err := factors.Password(sub, w.clock.Now())
	if err != nil {
		r.Fail(rw, errors.Join(httpx.ErrInternal, err))
		return
	}
	resp, err := w.issuer.Complete(ctx, rw, r, p, v)
	if err != nil {
		r.Fail(rw, err)
		return
	}
	r.RespondPending(rw, p, resp)
}

func (w *world) passwordChange(rw http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	res, ok := r.Session()
	if !ok {
		r.Fail(rw, httpx.ErrUnauthenticated)
		return
	}
	c := httpx.PasswordChangedChange()
	switch r.Field(routes.FieldConfirm) {
	case "bump":
		if _, err := w.identity.Apply(ctx, identity.BumpEpoch{Subject: res.Attrs().Subject(), Keep: res.Attrs().Lineage(), Change: identity.FactorPasskeyAdded}); err != nil {
			r.Fail(rw, errors.Join(httpx.ErrServiceUnavailable, err))
			return
		}
	case "zero":
		c = httpx.Change{}
	}
	if err := w.issuer.Reissue(ctx, rw, r, c); err != nil {
		r.Fail(rw, err)
		return
	}
	r.Respond(rw, httpx.Response{Body: map[string]string{"state": "password_changed"}})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func sha(t *testing.T, s string) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func (w *world) user(email, password string) core.Subject {
	w.t.Helper()
	id, err := identitysvc.NormalizeAs(identity.IdentifierEmail, email)
	must(w.t, err)
	a, err := w.identity.Apply(context.Background(), identity.CreateVerified{Email: id})
	must(w.t, err)
	w.passwords.mu.Lock()
	w.passwords.byID[email] = a.Subject
	w.passwords.secret[a.Subject] = password
	w.passwords.mu.Unlock()
	return a.Subject
}

type client struct {
	w       *world
	bearer  bool
	cookies map[string]*http.Cookie
	token   string
}

func (w *world) browser() *client { return &client{w: w, cookies: map[string]*http.Cookie{}} }

func (w *world) native() *client {
	return &client{w: w, bearer: true, cookies: map[string]*http.Cookie{}}
}

func (c *client) request(method, path string, body []byte, contentType string) *httptest.ResponseRecorder {
	c.w.t.Helper()
	var hr *http.Request
	if method == http.MethodGet {
		hr = httptest.NewRequest(method, origin+basePath+path, nil)
	} else {
		hr = httptest.NewRequest(method, origin+basePath+path, strings.NewReader(string(body)))
		hr.Header.Set("Content-Type", contentType)
	}
	hr.Header.Set("Origin", origin)
	hr.Header.Set("Sec-Fetch-Site", "same-origin")
	if c.bearer {
		hr.Header.Set(routes.HeaderTransport, "bearer")
		if c.token != "" {
			hr.Header.Set("Authorization", "Bearer "+c.token)
		}
	}
	for _, ck := range c.cookies {
		hr.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	hr.RemoteAddr = "198.51.100.7:4000"
	rec := httptest.NewRecorder()
	c.w.handler.ServeHTTP(rec, hr)
	for _, ck := range rec.Result().Cookies() {
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(c.cookies, ck.Name)
			continue
		}
		c.cookies[ck.Name] = ck
	}
	if tok := rec.Header().Get(stateful.HeaderSessionToken); tok != "" {
		c.token = tok
	}
	return rec
}

func (c *client) post(path string, fields map[string]any) *httptest.ResponseRecorder {
	c.w.t.Helper()
	if fields == nil {
		fields = map[string]any{}
	}
	b, err := json.Marshal(fields)
	must(c.w.t, err)
	return c.request(http.MethodPost, path, b, "application/json")
}

func (c *client) form(path string, fields url.Values) *httptest.ResponseRecorder {
	c.w.t.Helper()
	return c.request(http.MethodPost, path, []byte(fields.Encode()), "application/x-www-form-urlencoded")
}

func (c *client) get(path string) *httptest.ResponseRecorder {
	c.w.t.Helper()
	return c.request(http.MethodGet, path, nil, "")
}

func (c *client) cookie(n cookie.Name) (*http.Cookie, bool) {
	ck, ok := c.cookies[c.w.cookies.CookieName(n)]
	return ck, ok
}

func (c *client) login(email, password string, extra map[string]any) *httptest.ResponseRecorder {
	c.w.t.Helper()
	fields := map[string]any{routes.FieldIdentifier: email, routes.FieldPassword: password}
	for k, v := range extra {
		fields[k] = v
	}
	return c.post(routes.Login, fields)
}

type journeyBody struct {
	State    string   `json:"state"`
	Factors  []string `json:"factors"`
	Flow     string   `json:"flow"`
	ReturnTo string   `json:"return_to"`
	Error    string   `json:"error"`
}

type sessionView struct {
	Subject    string   `json:"subject"`
	Factors    []string `json:"factors"`
	AMR        []string `json:"amr"`
	RememberMe bool     `json:"remember_me"`
	ReturnTo   string   `json:"return_to"`
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return v
}

func expect(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d: %s", rec.Code, status, rec.Body.String())
	}
}

func expectError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	expect(t, rec, status)
	if got := decode[journeyBody](t, rec).Error; got != code {
		t.Fatalf("error %q, want %q", got, code)
	}
}

func (c *client) session() sessionView {
	c.w.t.Helper()
	rec := c.get(routes.Session)
	expect(c.w.t, rec, http.StatusOK)
	return decode[sessionView](c.w.t, rec)
}

func (c *client) attrs() core.SessionAttrs {
	c.w.t.Helper()
	hr := httptest.NewRequest(http.MethodGet, origin+"/", nil)
	if c.bearer {
		hr.Header.Set("Authorization", "Bearer "+c.token)
	}
	for _, ck := range c.cookies {
		hr.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	res, err := c.w.backend.Resume(context.Background(), httptest.NewRecorder(), hr, core.TenantID{})
	must(c.w.t, err)
	return res.Attrs()
}

func totpAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	must(t, err)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

func wrongCode(right string) string {
	if right == "000000" {
		return "000001"
	}
	return "000000"
}

type totpEnrollment struct {
	secret string
	codes  []string
}

func (w *world) enrollTOTP(email, password string) totpEnrollment {
	w.t.Helper()
	c := w.native()
	expect(w.t, c.login(email, password, nil), http.StatusOK)
	rec := c.post(routes.MFATOTPEnroll, nil)
	expect(w.t, rec, http.StatusOK)
	enrolled := decode[struct {
		Secret string `json:"secret"`
	}](w.t, rec)
	rec = c.post(routes.MFATOTPConfirm, map[string]any{routes.FieldCode: totpAt(w.t, enrolled.Secret, w.clock.Now())})
	expect(w.t, rec, http.StatusOK)
	codes := decode[struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}](w.t, rec)
	w.clock.Advance(30 * time.Second)
	w.sink.reset()
	return totpEnrollment{secret: enrolled.Secret, codes: codes.RecoveryCodes}
}

type passkeyChallenge struct {
	State   string          `json:"state"`
	Options json.RawMessage `json:"options"`
	Handle  string          `json:"handle"`
}

func (w *world) enrollPasskey(email, password string) *webauthntest.Authenticator {
	w.t.Helper()
	c := w.native()
	expect(w.t, c.login(email, password, nil), http.StatusOK)
	rec := c.post(routes.PasskeyRegisterBegin, nil)
	expect(w.t, rec, http.StatusOK)
	ch := decode[passkeyChallenge](w.t, rec)
	a := webauthntest.New(origin)
	body := map[string]any{}
	must(w.t, json.Unmarshal(a.Register(w.t, ch.Options), &body))
	body[routes.FieldHandle] = ch.Handle
	expect(w.t, c.post(routes.PasskeyRegisterFinish, body), http.StatusOK)
	w.sink.reset()
	return a
}

func (c *client) finishStepUp(a *webauthntest.Authenticator, flowField string) *httptest.ResponseRecorder {
	c.w.t.Helper()
	fields := map[string]any{}
	if flowField != "" {
		fields[routes.FieldFlow] = flowField
	}
	rec := c.post(routes.MFAPasskeyBegin, fields)
	expect(c.w.t, rec, http.StatusOK)
	ch := decode[passkeyChallenge](c.w.t, rec)
	body := map[string]any{}
	must(c.w.t, json.Unmarshal(a.Login(c.w.t, ch.Options), &body))
	body[routes.FieldHandle] = ch.Handle
	for k, v := range fields {
		body[k] = v
	}
	return c.post(routes.MFAPasskeyFinish, body)
}
