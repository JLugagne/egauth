package mfasvc_test

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/clientaddr"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/mfasvc"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/store"
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
)

var start = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

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

type allowAll struct{}

func (allowAll) Allow(context.Context, limiter.Key) (limiter.Decision, error) {
	return limiter.Decision{Allowed: true}, nil
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

type reissue struct {
	change core.Factor
	err    error
}

type fakeIssuer struct {
	identity identity.Store
	sessions *sessionTable
	mu       sync.Mutex
	reissues []reissue
}

func (f *fakeIssuer) Begin(context.Context, *httpx.Request) (core.Pending, error) {
	return core.Pending{}, httpx.ErrInternal
}

func (f *fakeIssuer) Complete(context.Context, http.ResponseWriter, *httpx.Request, core.Pending, core.Verified) (httpx.Response, error) {
	return httpx.Response{}, httpx.ErrInternal
}

func (f *fakeIssuer) Reauthenticate(context.Context, http.ResponseWriter, *httpx.Request, core.Verified) (httpx.Response, error) {
	return httpx.Response{}, httpx.ErrInternal
}

func (f *fakeIssuer) Reissue(ctx context.Context, _ http.ResponseWriter, r *httpx.Request, c httpx.Change) error {
	res, ok := r.Session()
	fac, enrolled := c.EnrolledFactor()
	err := func() error {
		if !ok || !enrolled {
			return httpx.ErrInternal
		}
		epoch, err := f.identity.CurrentEpoch(ctx, res.Attrs().Subject())
		if err != nil {
			return err
		}
		a, err := core.FactorEnrolled(res.Attrs(), fac, core.NewAccountState(true, false, false, false, true, epoch))
		if err != nil {
			return err
		}
		return f.sessions.replace(a.Lineage(), a)
	}()
	f.mu.Lock()
	f.reissues = append(f.reissues, reissue{change: fac, err: err})
	f.mu.Unlock()
	return err
}

func (f *fakeIssuer) all() []reissue {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]reissue(nil), f.reissues...)
}

type mutator struct {
	identity identity.Store
	mu       sync.Mutex
	applied  []identity.Mutation
	before   func(identity.Mutation)
}

func (m *mutator) Apply(ctx context.Context, mu identity.Mutation) (identity.Applied, error) {
	m.mu.Lock()
	hook := m.before
	m.applied = append(m.applied, mu)
	m.mu.Unlock()
	if hook != nil {
		hook(mu)
	}
	return m.identity.Apply(ctx, mu)
}

func (m *mutator) changes() []identity.FactorChange {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []identity.FactorChange
	for _, mu := range m.applied {
		if b, ok := mu.(identity.BumpEpoch); ok {
			out = append(out, b.Change)
		}
	}
	return out
}

type world struct {
	t        *testing.T
	clock    *clock.Test
	identity identity.Store
	mfa      mfa.Store
	passkeys passkey.Store
	kek      kek.KEK
	sink     *recordingSink
	mutator  *mutator
	sessions *sessionTable
	issuer   *fakeIssuer
	svc      *mfasvc.Service
	handler  http.Handler
}

func newKEK(t *testing.T) kek.KEK {
	t.Helper()
	sum := sha256.Sum256([]byte("egauth/mfasvc_test/kek"))
	k, err := kek.NewLocal(sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newWorld(t *testing.T) *world {
	t.Helper()
	clk := clock.NewTest(start)
	w := &world{
		t:        t,
		clock:    clk,
		identity: identitymem.NewWithClock(clk.Clock()),
		mfa:      mfamem.NewWithClock(clk.Clock()),
		passkeys: passkeymem.New(),
		kek:      newKEK(t),
		sink:     &recordingSink{},
	}
	return w.build()
}

func (w *world) build() *world {
	t := w.t
	t.Helper()
	w.mutator = &mutator{identity: w.identity}
	w.sessions = &sessionTable{byToken: map[string]*liveSession{}, identity: w.identity}
	w.issuer = &fakeIssuer{identity: w.identity, sessions: w.sessions}
	svc, err := mfasvc.New(mfasvc.Config{
		MFA:        w.mfa,
		Passkeys:   w.passkeys,
		Identity:   w.identity,
		Mutations:  w.mutator,
		KEK:        w.kek,
		TOTPIssuer: "Example",
		Clock:      w.clock.Clock(),
		Audit:      httpx.SinkAudit(w.sink),
	})
	if err != nil {
		t.Fatal(err)
	}
	w.svc = svc
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
		Authenticator: w.sessions,
		Issuer:        w.issuer,
		Identifiers:   identitysvc.Normalizer{},
		Enrollment:    enrollment{mfa: w.mfa, passkeys: w.passkeys},
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

func (w *world) session(s core.Subject, fs ...core.Factor) string {
	w.t.Helper()
	if len(fs) == 0 {
		fs = []core.Factor{core.FactorPassword}
	}
	spec := principaltest.Spec{
		Lineage:   uuid.New(),
		Subject:   s,
		Factors:   fs,
		PrimaryAt: w.clock.Now(),
		Epoch:     w.epoch(s),
		Transport: core.TransportBearer,
		CreatedAt: w.clock.Now(),
	}
	for _, f := range fs {
		if f.Role() == core.RoleSecond || f == core.FactorUserVerification {
			spec.SecondAt = w.clock.Now()
		}
	}
	return w.sessions.add(principaltest.Attrs(spec))
}

func (w *world) post(tok, path string, fields map[string]string) *httptest.ResponseRecorder {
	w.t.Helper()
	if fields == nil {
		fields = map[string]string{}
	}
	b, err := json.Marshal(fields)
	if err != nil {
		w.t.Fatal(err)
	}
	hr := httptest.NewRequest(http.MethodPost, origin+basePath+path, strings.NewReader(string(b)))
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Origin", origin)
	hr.Header.Set("Sec-Fetch-Site", "same-origin")
	hr.Header.Set(routes.HeaderTransport, "bearer")
	if tok != "" {
		hr.Header.Set("Authorization", "Bearer "+tok)
	}
	hr.RemoteAddr = "198.51.100.7:4000"
	rec := httptest.NewRecorder()
	w.handler.ServeHTTP(rec, hr)
	return rec
}

type enrollBody struct {
	State  string `json:"state"`
	Secret string `json:"secret"`
	URI    string `json:"otpauth_uri"`
}

type codesBody struct {
	State         string   `json:"state"`
	RecoveryCodes []string `json:"recovery_codes"`
	SessionEnded  bool     `json:"session_ended"`
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

func totpAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
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

func (w *world) enroll(tok string) enrollBody {
	w.t.Helper()
	rec := w.post(tok, routes.MFATOTPEnroll, nil)
	if rec.Code != http.StatusOK {
		w.t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
	}
	var b enrollBody
	decodeInto(w.t, rec, &b)
	return b
}

func (w *world) enrolled(s core.Subject) (string, []string) {
	w.t.Helper()
	tok := w.session(s)
	b := w.enroll(tok)
	rec := w.post(tok, routes.MFATOTPConfirm, map[string]string{routes.FieldCode: totpAt(w.t, b.Secret, w.clock.Now())})
	if rec.Code != http.StatusOK {
		w.t.Fatalf("confirm: %d %s", rec.Code, rec.Body.String())
	}
	var c codesBody
	decodeInto(w.t, rec, &c)
	w.clock.Advance(30 * time.Second)
	return b.Secret, c.RecoveryCodes
}

func (w *world) addPasskey(s core.Subject) {
	w.t.Helper()
	err := w.passkeys.Save(context.Background(), passkey.Credential{
		Subject: s, ID: passkey.CredentialID(uuid.New().String()), PublicKey: []byte{1, 2, 3},
		CreatedAt: w.clock.Now(), Discoverable: passkey.Confirmed,
	})
	if err != nil {
		w.t.Fatal(err)
	}
}
