package identitysvc_test

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
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/clientaddr"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/store"
	ceremonymem "github.com/JLugagne/egauth/store/ceremony/memory"
	"github.com/JLugagne/egauth/store/identity"
	identitymem "github.com/JLugagne/egauth/store/identity/memory"
	mfamem "github.com/JLugagne/egauth/store/mfa/memory"
	passkeymem "github.com/JLugagne/egauth/store/passkey/memory"
)

type acctMailer struct {
	*fakeMailer
	mu      sync.Mutex
	notices []identitysvc.SecurityNoticeMessage
}

func (m *acctMailer) EmailVerificationLink(_ context.Context, l identitysvc.LinkMessage) error {
	return m.add(sent{kind: "email_verification", to: l.To, link: l.Link})
}

func (m *acctMailer) EmailChangeLink(_ context.Context, l identitysvc.LinkMessage) error {
	return m.add(sent{kind: "email_change", to: l.To, link: l.Link})
}

func (m *acctMailer) RecoveryEmailLink(_ context.Context, l identitysvc.LinkMessage) error {
	return m.add(sent{kind: "recovery_email", to: l.To, link: l.Link})
}

func (m *acctMailer) SecurityNotice(_ context.Context, n identitysvc.SecurityNoticeMessage) error {
	m.mu.Lock()
	m.notices = append(m.notices, n)
	m.mu.Unlock()
	return m.add(sent{kind: "security_notice", to: n.To, link: n.RevertLink})
}

func (m *acctMailer) securityNotices() []identitysvc.SecurityNoticeMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]identitysvc.SecurityNoticeMessage(nil), m.notices...)
}

type fakeTexter struct {
	mu   sync.Mutex
	msgs []identitysvc.CodeMessage
}

func (f *fakeTexter) PhoneVerificationCode(_ context.Context, m identitysvc.CodeMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, m)
	return nil
}

func (f *fakeTexter) all() []identitysvc.CodeMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]identitysvc.CodeMessage(nil), f.msgs...)
}

type detachedPendings struct{ clock *clock.Test }

func (d detachedPendings) Detached(_ context.Context, t core.TenantID) (core.Pending, error) {
	return core.NewPending(t, core.RememberDeclined, redirect.Target{}, core.TransportCookies, core.RememberUserChoice, d.clock.Now())
}

type liveSession struct {
	id      uuid.UUID
	attrs   core.SessionAttrs
	revoked bool
}

type sessionTable struct {
	mu       sync.Mutex
	byToken  map[string]*liveSession
	identity identity.Store
	lenient  bool
}

func (s *sessionTable) Resume(ctx context.Context, _ http.ResponseWriter, r *http.Request, _ core.TenantID) (session.Resumed, error) {
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
	lenient := s.lenient
	s.mu.Unlock()
	if !found || cp.revoked {
		return session.Resumed{}, errors.New("revoked")
	}
	if !lenient {
		e, err := s.identity.CurrentEpoch(ctx, cp.attrs.Subject())
		if err != nil || e != cp.attrs.Epoch() {
			return session.Resumed{}, errors.New("stale epoch")
		}
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

func (s *sessionTable) revokeAllBut(sub core.Subject, keep uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ls := range s.byToken {
		if ls.attrs.Subject() == sub && (keep == uuid.Nil || ls.attrs.Lineage() != keep) {
			ls.revoked = true
		}
	}
}

func (s *sessionTable) replace(lineage uuid.UUID, a core.SessionAttrs) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ls := range s.byToken {
		if ls.attrs.Lineage() == lineage {
			if ls.revoked {
				return store.ErrConflict
			}
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

type acctIssuer struct {
	*fakeIssuer
	sessions *sessionTable
}

func (i *acctIssuer) Reissue(ctx context.Context, _ http.ResponseWriter, r *httpx.Request, c httpx.Change) error {
	res, ok := r.Session()
	if !ok || !c.PasswordChanged() {
		return httpx.ErrInternal
	}
	st, err := i.svc.AccountState(ctx, res.Attrs().Subject())
	if err != nil {
		return err
	}
	a, err := core.PasswordChanged(res.Attrs(), st, i.clock.Now())
	if err != nil {
		return err
	}
	return i.sessions.replace(a.Lineage(), a)
}

type outboxRouter struct {
	mu       sync.Mutex
	accounts *identitysvc.Accounts
	sessions *sessionTable
	errs     []error
}

func (o *outboxRouter) DispatchOutbox(ctx context.Context, items []identity.OutboxItem) {
	o.mu.Lock()
	acc := o.accounts
	o.mu.Unlock()
	for _, it := range items {
		switch it.Component {
		case identity.ComponentSessions:
			if it.Event != identity.EventEnable {
				o.sessions.revokeAllBut(it.Subject, it.Keep)
			}
		case identity.ComponentNotices:
			if acc == nil {
				continue
			}
			if err := acc.SecurityNotice(ctx, it); err != nil {
				o.mu.Lock()
				o.errs = append(o.errs, err)
				o.mu.Unlock()
			}
		}
	}
}

func (o *outboxRouter) failures() []error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]error(nil), o.errs...)
}

type acctWorld struct {
	*world
	amailer  *acctMailer
	texter   *fakeTexter
	sessions *sessionTable
	router   *outboxRouter
	accounts *identitysvc.Accounts
	sealer   *ceremonycodec.Sealer
	noReset  bool
}

func newAcctWorld(t *testing.T, wrap func(identity.Store) identity.Store) *acctWorld {
	t.Helper()
	clk := clock.NewTest(start)
	base := &world{
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
		base.identity = wrap(base.identity)
	}
	w := &acctWorld{
		world:    base,
		amailer:  &acctMailer{fakeMailer: base.mailer},
		texter:   &fakeTexter{},
		sessions: &sessionTable{byToken: map[string]*liveSession{}, identity: base.identity},
	}
	w.router = &outboxRouter{sessions: w.sessions}
	key := make([]byte, ceremonycodec.DataKeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sealer, err := ceremonycodec.NewSealer(key, clk.Clock())
	if err != nil {
		t.Fatal(err)
	}
	w.sealer = sealer
	w.build()
	return w
}

func (w *acctWorld) build() {
	t := w.t
	t.Helper()
	cp, err := cookie.NewPolicy(cookie.Options{PublicOrigin: origin})
	if err != nil {
		t.Fatal(err)
	}
	w.cookies = cp
	svc, err := identitysvc.New(identitysvc.Config{
		Identity:         w.identity,
		Ceremonies:       w.ceremonies,
		MFA:              w.mfa,
		Passkeys:         w.passkeys,
		Hasher:           w.hasher,
		Policy:           acceptAll{},
		Mailer:           w.amailer,
		Links:            fakeLinks{},
		Cookies:          cp,
		DataKey:          testDataKey(9),
		OpenRegistration: true,
		NoPasswordReset:  w.noReset,
		Dispatcher:       w.router,
		Clock:            w.clock.Clock(),
		Audit:            httpx.SinkAudit(w.sink),
	})
	if err != nil {
		t.Fatal(err)
	}
	w.svc = svc
	t.Cleanup(func() { _ = svc.Close() })
	acc, err := identitysvc.NewAccounts(svc, identitysvc.AccountsConfig{
		Mailer:        w.amailer,
		Texter:        w.texter,
		Sealer:        w.sealer,
		Pendings:      detachedPendings{clock: w.clock},
		Email:         true,
		Phone:         true,
		RecoveryEmail: true,
		SelfDelete:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.accounts = acc
	w.router.mu.Lock()
	w.router.accounts = acc
	w.router.mu.Unlock()
	issuer := &acctIssuer{fakeIssuer: &fakeIssuer{svc: svc, clock: w.clock}, sessions: w.sessions}
	w.issuer = issuer.fakeIssuer
	eps, err := svc.Endpoints(issuer)
	if err != nil {
		t.Fatal(err)
	}
	more, err := acc.Endpoints(issuer)
	if err != nil {
		t.Fatal(err)
	}
	table, err := routes.NewTable(append(eps, more...)...)
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
		Authenticator: w.sessions,
		Issuer:        issuer,
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
}

func (w *acctWorld) login(sub core.Subject) string {
	w.t.Helper()
	ctx := context.Background()
	st, err := w.svc.AccountState(ctx, sub)
	if err != nil {
		w.t.Fatal(err)
	}
	now := w.clock.Now()
	p, err := core.NewPending(sub.Tenant, core.RememberDeclined, redirect.Target{}, core.TransportBearer, core.RememberUserChoice, now)
	if err != nil {
		w.t.Fatal(err)
	}
	v, err := factors.Password(sub, now)
	if err != nil {
		w.t.Fatal(err)
	}
	if p, err = p.Add(v, st); err != nil {
		w.t.Fatal(err)
	}
	adm, err := core.Admit(p, st, core.NewMFADecision(nil), now)
	if err != nil {
		w.t.Fatal(err)
	}
	a, ok := adm.Session()
	if !ok {
		w.t.Fatal("no session admitted")
	}
	return w.sessions.add(a)
}

func (w *acctWorld) call(path, token string, fields map[string]string) *httptest.ResponseRecorder {
	w.t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		w.t.Fatal(err)
	}
	hr := httptest.NewRequest(http.MethodPost, origin+basePath+path, strings.NewReader(string(b)))
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Origin", origin)
	hr.Header.Set("Sec-Fetch-Site", "same-origin")
	if token != "" {
		hr.Header.Set("Authorization", "Bearer "+token)
	}
	hr.RemoteAddr = "198.51.100.7:4000"
	rec := httptest.NewRecorder()
	w.handler.ServeHTTP(rec, hr)
	return rec
}

func (w *acctWorld) alive(token string) bool {
	w.t.Helper()
	return w.call(routes.PhoneVerify, token, map[string]string{}).Code != http.StatusUnauthorized
}

func (w *acctWorld) mailsOf(kind string) []sent {
	var out []sent
	for _, m := range w.mailer.all() {
		if m.kind == kind {
			out = append(out, m)
		}
	}
	return out
}

func (w *acctWorld) waitKind(kind string, n int) []sent {
	w.t.Helper()
	for range 2000 {
		if got := w.mailsOf(kind); len(got) >= n {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	w.t.Fatalf("waited for %d %s messages, got %v", n, kind, w.mailer.all())
	return nil
}

func (w *acctWorld) waitTexts(n int) []identitysvc.CodeMessage {
	w.t.Helper()
	for range 2000 {
		if got := w.texter.all(); len(got) >= n {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	w.t.Fatalf("waited for %d texts, got %d", n, len(w.texter.all()))
	return nil
}

func (w *acctWorld) user(sub core.Subject) identity.User {
	w.t.Helper()
	u, err := w.identity.GetUser(context.Background(), sub)
	if err != nil {
		w.t.Fatal(err)
	}
	return u
}

func (w *acctWorld) loginStatus(identifier, password string) int {
	w.t.Helper()
	return w.do(req{path: routes.Login, fields: map[string]string{routes.FieldIdentifier: identifier, routes.FieldPassword: password}}).Code
}

func expectStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status %d, want %d: %s", rec.Code, want, rec.Body.String())
	}
}
