package passkeysvc_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/clientaddr"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/passkeysvc"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session"
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
	"github.com/JLugagne/egauth/webauthntest"
)

const (
	origin   = "https://auth.example.com"
	basePath = "/auth"
)

var start = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func testDataKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)*29 + 3
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

type allowAll struct{}

func (allowAll) Allow(context.Context, limiter.Key) (limiter.Decision, error) {
	return limiter.Decision{Allowed: true}, nil
}

type accounts struct {
	identity   identity.Store
	unverified *sync.Map
	reads      *atomic.Int64
}

func (a accounts) AccountState(ctx context.Context, s core.Subject) (core.AccountState, error) {
	if a.reads != nil {
		a.reads.Add(1)
	}
	u, err := a.identity.GetUser(ctx, s)
	if errors.Is(err, store.ErrNotFound) {
		return core.AccountState{}, nil
	}
	if err != nil {
		return core.AccountState{}, errors.Join(httpx.ErrUnavailable, err)
	}
	verified := !u.EmailVerifiedAt.IsZero()
	if _, carried := a.unverified.Load(s); carried {
		verified = false
	}
	return core.NewAccountState(true, !u.DisabledAt.IsZero(), !u.DeletedAt.IsZero(), u.MustChange, verified, u.SecurityEpoch), nil
}

type hookedPasskeys struct {
	passkey.Store
	afterGet       atomic.Pointer[func()]
	afterSignCount atomic.Pointer[func()]
	lists          atomic.Int64
}

func (h *hookedPasskeys) List(ctx context.Context, s core.Subject) ([]passkey.Credential, error) {
	h.lists.Add(1)
	return h.Store.List(ctx, s)
}

func (h *hookedPasskeys) Get(ctx context.Context, t core.TenantID, id passkey.CredentialID) (passkey.Credential, error) {
	c, err := h.Store.Get(ctx, t, id)
	if f := h.afterGet.Swap(nil); f != nil {
		(*f)()
	}
	return c, err
}

func (h *hookedPasskeys) UpdateSignCount(ctx context.Context, s core.Subject, id passkey.CredentialID, next uint32) (bool, error) {
	ok, err := h.Store.UpdateSignCount(ctx, s, id, next)
	if f := h.afterSignCount.Swap(nil); f != nil {
		(*f)()
	}
	return ok, err
}

type liveSession struct {
	id    uuid.UUID
	attrs core.SessionAttrs
}

type sessionTable struct {
	mu       sync.Mutex
	byToken  map[string]*liveSession
	identity identity.Store
}

func (s *sessionTable) Resume(ctx context.Context, _ http.ResponseWriter, r *http.Request) (session.Resumed, error) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return session.Resumed{}, errors.New("no session")
	}
	s.mu.Lock()
	ls, found := s.byToken[tok]
	var cp liveSession
	if found {
		cp = *ls
	}
	s.mu.Unlock()
	if !found {
		return session.Resumed{}, errors.New("unknown session")
	}
	e, err := s.identity.CurrentEpoch(ctx, cp.attrs.Subject())
	if err != nil || e != cp.attrs.Epoch() {
		return session.Resumed{}, errors.New("stale epoch")
	}
	h, err := session.NewHandle(cp.attrs, cp.id)
	if err != nil {
		return session.Resumed{}, err
	}
	return session.NewResumed(cp.attrs, core.SealedClaims{}, h)
}

func (s *sessionTable) add(a core.SessionAttrs) string {
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	tok := base64.RawURLEncoding.EncodeToString(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byToken[tok] = &liveSession{id: uuid.New(), attrs: a}
	return tok
}

func (s *sessionTable) replace(lineage uuid.UUID, a core.SessionAttrs) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ls := range s.byToken {
		if ls.attrs.Lineage() == lineage {
			ls.attrs = a
			return nil
		}
	}
	return store.ErrNotFound
}

func (s *sessionTable) attrsOf(tok string) core.SessionAttrs {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byToken[tok].attrs
}

type enrollment struct {
	mfa      mfa.Store
	passkeys passkey.Store
}

func (e enrollment) MFARequired(ctx context.Context, s core.Subject) (bool, error) {
	totp, err := e.mfa.HasConfirmedTOTP(ctx, s)
	if err != nil {
		return false, err
	}
	pk, err := e.passkeys.HasActive(ctx, s)
	return totp || pk, err
}

type completion struct {
	pending  core.Pending
	verified core.Verified
	added    core.Pending
	err      error
}

type fakeIssuer struct {
	clock    *clock.Test
	accounts accounts
	enrolled enrollment
	sessions *sessionTable
	origins  redirect.Origins
	mu       sync.Mutex
	done     []completion
	reissues []core.Factor
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

func (f *fakeIssuer) admit(ctx context.Context, p core.Pending, v core.Verified) (core.Pending, core.Admission, error) {
	st, err := f.accounts.AccountState(ctx, v.Subject())
	if err != nil {
		return core.Pending{}, core.Admission{}, err
	}
	added, err := p.Add(v, st)
	if err != nil {
		return core.Pending{}, core.Admission{}, errors.Join(httpx.ErrUnauthenticated, err)
	}
	required, err := f.enrolled.MFARequired(ctx, v.Subject())
	if err != nil {
		return core.Pending{}, core.Admission{}, err
	}
	decision := core.NewMFADecision(nil)
	if required {
		decision = core.NewMFADecision([]core.Factor{core.FactorPasskeyStepUp})
	}
	adm, err := core.Admit(added, st, decision, f.clock.Now())
	if err != nil {
		return core.Pending{}, core.Admission{}, errors.Join(httpx.ErrUnauthenticated, err)
	}
	return added, adm, nil
}

func (f *fakeIssuer) Complete(ctx context.Context, _ http.ResponseWriter, _ *httpx.Request, p core.Pending, v core.Verified) (httpx.Response, error) {
	added, adm, err := f.admit(ctx, p, v)
	f.mu.Lock()
	f.done = append(f.done, completion{pending: p, verified: v, added: added, err: err})
	f.mu.Unlock()
	if err != nil {
		return httpx.Response{}, err
	}
	if _, _, needs := adm.NeedsFactor(); needs {
		return httpx.Response{Body: map[string]string{"state": "mfa_required"}}, nil
	}
	return httpx.Response{Body: map[string]string{"state": "authenticated"}}, nil
}

func (f *fakeIssuer) Reauthenticate(context.Context, http.ResponseWriter, *httpx.Request, core.Verified) (httpx.Response, error) {
	return httpx.Response{}, httpx.ErrInternal
}

func (f *fakeIssuer) Reissue(ctx context.Context, _ http.ResponseWriter, r *httpx.Request, c httpx.Change) error {
	res, ok := r.Session()
	fac, enrolled := c.EnrolledFactor()
	if !ok || !enrolled {
		return httpx.ErrInternal
	}
	st, err := f.accounts.AccountState(ctx, res.Attrs().Subject())
	if err != nil {
		return err
	}
	a, err := core.FactorEnrolled(res.Attrs(), fac, st)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.reissues = append(f.reissues, fac)
	f.mu.Unlock()
	return f.sessions.replace(a.Lineage(), a)
}

func (f *fakeIssuer) completions() []completion {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]completion(nil), f.done...)
}

type mutator struct {
	identity identity.Store
	mu       sync.Mutex
	applied  []identity.BumpEpoch
}

func (m *mutator) Apply(ctx context.Context, mu identity.Mutation) (identity.Applied, error) {
	if b, ok := mu.(identity.BumpEpoch); ok {
		m.mu.Lock()
		m.applied = append(m.applied, b)
		m.mu.Unlock()
	}
	return m.identity.Apply(ctx, mu)
}

func (m *mutator) bumps() []identity.BumpEpoch {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]identity.BumpEpoch(nil), m.applied...)
}

type countingCeremonies struct {
	ceremony.Store
	puts atomic.Int64
}

func (c *countingCeremonies) Put(ctx context.Context, r ceremony.Record) (int, error) {
	c.puts.Add(1)
	return c.Store.Put(ctx, r)
}

type world struct {
	t          *testing.T
	clock      *clock.Test
	identity   identity.Store
	passkeys   passkey.Store
	hooks      *hookedPasskeys
	unverified *sync.Map
	stateReads *atomic.Int64
	mfa        mfa.Store
	ceremonies *countingCeremonies
	sink       *recordingSink
	mutator    *mutator
	sessions   *sessionTable
	issuer     *fakeIssuer
	svc        *passkeysvc.Service
	cookies    cookie.Policy
	handler    http.Handler
}

func newWorld(t *testing.T) *world {
	t.Helper()
	clk := clock.NewTest(start)
	hooks := &hookedPasskeys{Store: passkeymem.New()}
	w := &world{
		t:          t,
		clock:      clk,
		identity:   identitymem.NewWithClock(clk.Clock()),
		passkeys:   hooks,
		hooks:      hooks,
		unverified: &sync.Map{},
		stateReads: &atomic.Int64{},
		mfa:        mfamem.NewWithClock(clk.Clock()),
		ceremonies: &countingCeremonies{Store: ceremonymem.NewWithClock(clk.Clock())},
		sink:       &recordingSink{},
	}
	w.mutator = &mutator{identity: w.identity}
	w.sessions = &sessionTable{byToken: map[string]*liveSession{}, identity: w.identity}
	cp, err := cookie.NewPolicy(cookie.Options{PublicOrigin: origin})
	if err != nil {
		t.Fatal(err)
	}
	w.cookies = cp
	trusted, err := csrf.NewOrigins(origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := passkeysvc.New(w.config(trusted))
	if err != nil {
		t.Fatal(err)
	}
	w.svc = svc
	origins, err := redirect.NewOrigins(origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	acc := accounts{identity: w.identity, unverified: w.unverified}
	w.issuer = &fakeIssuer{clock: clk, accounts: acc, enrolled: enrollment{mfa: w.mfa, passkeys: w.passkeys}, sessions: w.sessions, origins: origins}
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
	p, err := httpx.NewPreamble(httpx.Env{
		Tenants:       httpx.SingleTenant(),
		Limiter:       allowAll{},
		Authenticator: w.sessions,
		Issuer:        w.issuer,
		Identifiers:   identitysvc.Normalizer{},
		Enrollment:    enrollment{mfa: w.mfa, passkeys: w.passkeys},
		Clock:         clk.Clock(),
		Audit:         httpx.SinkAudit(w.sink),
	}, httpx.Settings{Clients: res, Origins: trusted, Transports: httpx.CookiesAndBearer, ReauthWindow: 10 * time.Minute})
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

func (w *world) config(trusted csrf.Origins) passkeysvc.Config {
	return passkeysvc.Config{
		Passkeys:    w.passkeys,
		MFA:         w.mfa,
		Identity:    w.identity,
		Accounts:    accounts{identity: w.identity, unverified: w.unverified, reads: w.stateReads},
		Mutations:   w.mutator,
		Ceremonies:  w.ceremonies,
		Origins:     trusted,
		Cookies:     w.cookies,
		DisplayName: "Example",
		DataKey:     testDataKey(),
		Clock:       w.clock.Clock(),
		Audit:       httpx.SinkAudit(w.sink),
	}
}

func (w *world) user(email string) core.Subject {
	w.t.Helper()
	id, err := identitysvc.NormalizeAs(identity.IdentifierEmail, email)
	if err != nil {
		w.t.Fatal(err)
	}
	a, err := w.identity.Apply(context.Background(), identity.CreateVerified{Email: id})
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

func (w *world) session(s core.Subject) string {
	w.t.Helper()
	return w.sessions.add(principaltest.Attrs(principaltest.Spec{
		Lineage:   uuid.New(),
		Subject:   s,
		Factors:   []core.Factor{core.FactorPassword, core.FactorTOTP},
		PrimaryAt: w.clock.Now(),
		SecondAt:  w.clock.Now(),
		Epoch:     w.epoch(s),
		Transport: core.TransportBearer,
		CreatedAt: w.clock.Now(),
	}))
}

type req struct {
	path    string
	fields  map[string]any
	body    []byte
	token   string
	bearer  bool
	cookies []*http.Cookie
	method  string
}

func (w *world) do(r req) *httptest.ResponseRecorder {
	w.t.Helper()
	fields := map[string]any{}
	if len(r.body) > 0 {
		if err := json.Unmarshal(r.body, &fields); err != nil {
			w.t.Fatal(err)
		}
	}
	for k, v := range r.fields {
		fields[k] = v
	}
	b, err := json.Marshal(fields)
	if err != nil {
		w.t.Fatal(err)
	}
	method := r.method
	if method == "" {
		method = http.MethodPost
	}
	var hr *http.Request
	if method == http.MethodGet {
		hr = httptest.NewRequest(method, origin+basePath+r.path, nil)
	} else {
		hr = httptest.NewRequest(method, origin+basePath+r.path, strings.NewReader(string(b)))
		hr.Header.Set("Content-Type", "application/json")
	}
	hr.Header.Set("Origin", origin)
	hr.Header.Set("Sec-Fetch-Site", "same-origin")
	if r.bearer || r.token != "" {
		hr.Header.Set(routes.HeaderTransport, "bearer")
	}
	if r.token != "" {
		hr.Header.Set("Authorization", "Bearer "+r.token)
	}
	for _, c := range r.cookies {
		hr.AddCookie(c)
	}
	hr.RemoteAddr = "198.51.100.7:4000"
	rec := httptest.NewRecorder()
	w.handler.ServeHTTP(rec, hr)
	return rec
}

type challenge struct {
	State   string          `json:"state"`
	Options json.RawMessage `json:"options"`
	Handle  string          `json:"handle"`
	Bind    string          `json:"bind"`
}

type registered struct {
	State        string                    `json:"state"`
	Credential   passkeysvc.CredentialView `json:"credential"`
	SessionEnded bool                      `json:"session_ended"`
}

func decodeInto(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]any
	decodeInto(t, rec, &m)
	s, _ := m["error"].(string)
	return s
}

func expect(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d: %s", rec.Code, status, rec.Body.String())
	}
}

func (w *world) beginRegistration(tok string) challenge {
	w.t.Helper()
	rec := w.do(req{path: routes.PasskeyRegisterBegin, token: tok})
	expect(w.t, rec, http.StatusOK)
	var c challenge
	decodeInto(w.t, rec, &c)
	return c
}

func (w *world) finishRegistration(tok string, c challenge, body []byte, extra map[string]any) *httptest.ResponseRecorder {
	w.t.Helper()
	fields := map[string]any{routes.FieldHandle: c.Handle}
	for k, v := range extra {
		fields[k] = v
	}
	return w.do(req{path: routes.PasskeyRegisterFinish, token: tok, body: body, fields: fields})
}

func (w *world) register(tok string, a *webauthntest.Authenticator) registered {
	w.t.Helper()
	c := w.beginRegistration(tok)
	rec := w.finishRegistration(tok, c, a.Register(w.t, c.Options), nil)
	expect(w.t, rec, http.StatusOK)
	var out registered
	decodeInto(w.t, rec, &out)
	return out
}

func (w *world) enrolled(email string) (core.Subject, *webauthntest.Authenticator) {
	w.t.Helper()
	sub := w.user(email)
	a := webauthntest.New(origin)
	w.register(w.session(sub), a)
	return sub, a
}

func (w *world) beginLogin(fields map[string]any) (challenge, []*http.Cookie) {
	w.t.Helper()
	rec := w.do(req{path: routes.PasskeyLoginBegin, fields: fields})
	expect(w.t, rec, http.StatusOK)
	var c challenge
	decodeInto(w.t, rec, &c)
	return c, rec.Result().Cookies()
}

func (w *world) finishLogin(c challenge, cookies []*http.Cookie, body []byte) *httptest.ResponseRecorder {
	w.t.Helper()
	return w.do(req{path: routes.PasskeyLoginFinish, body: body, cookies: cookies, fields: map[string]any{routes.FieldHandle: c.Handle}})
}

func (w *world) storeCredential(c passkey.Credential) {
	w.t.Helper()
	if err := w.passkeys.Save(context.Background(), c); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) credentials(s core.Subject) []passkey.Credential {
	w.t.Helper()
	cs, err := w.passkeys.List(context.Background(), s)
	if err != nil {
		w.t.Fatal(err)
	}
	return cs
}

func publicKeyOf(t *testing.T, opts json.RawMessage) map[string]any {
	t.Helper()
	var wrapper struct {
		PublicKey map[string]any `json:"publicKey"`
	}
	if err := json.Unmarshal(opts, &wrapper); err != nil {
		t.Fatal(err)
	}
	return wrapper.PublicKey
}
