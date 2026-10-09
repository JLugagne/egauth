package stateful_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/internal/session/backendtest"
	"github.com/JLugagne/egauth/internal/session/stateful"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
	identitymemory "github.com/JLugagne/egauth/store/identity/memory"
	"github.com/JLugagne/egauth/store/sessions"
	sessionsmemory "github.com/JLugagne/egauth/store/sessions/memory"
)

const publicOrigin = "https://{tenant}.example.test"

type authority struct {
	id  identity.Store
	enr *backendtest.Enrollment
}

func (a authority) AccountState(ctx context.Context, s core.Subject) (core.AccountState, error) {
	u, err := a.id.GetUser(ctx, s)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return core.AccountState{}, nil
	case err != nil:
		return core.AccountState{}, errors.Join(httpx.ErrUnavailable, err)
	}
	return core.NewAccountState(true, !u.DisabledAt.IsZero(), !u.DeletedAt.IsZero(), u.MustChange, !u.EmailVerifiedAt.IsZero(), u.SecurityEpoch), nil
}

func (a authority) MFADecision(_ context.Context, s core.Subject) (core.MFADecision, error) {
	return core.NewMFADecision(a.enr.Factors(s)), nil
}

type flakySessions struct {
	sessions.Store
	o *backendtest.Outage
}

func (f flakySessions) Get(ctx context.Context, t principal.TenantID, tokenHash []byte) (sessions.Record, error) {
	if err := f.o.Err(); err != nil {
		return sessions.Record{}, err
	}
	return f.Store.Get(ctx, t, tokenHash)
}

func (f flakySessions) Touch(ctx context.Context, t principal.TenantID, tokenHash []byte, idleUntil time.Time) (time.Time, error) {
	if err := f.o.Err(); err != nil {
		return time.Time{}, err
	}
	return f.Store.Touch(ctx, t, tokenHash, idleUntil)
}

func (f flakySessions) Rotate(ctx context.Context, req sessions.RotateRequest) error {
	if err := f.o.Err(); err != nil {
		return err
	}
	return f.Store.Rotate(ctx, req)
}

type world struct {
	fx       *backendtest.Fixture
	backend  *stateful.Backend
	sessions *sessionsmemory.Store
	identity *identitymemory.Store
	epochs   *revoke.Epochs
	cookies  cookie.Policy
}

func build(t *testing.T, fx *backendtest.Fixture) *stateful.Backend {
	t.Helper()
	return buildWorld(t, fx).backend
}

func buildWorld(t *testing.T, fx *backendtest.Fixture) *world {
	t.Helper()
	clk := fx.Clock.Clock()
	w := &world{fx: fx, sessions: sessionsmemory.NewWithClock(clk), identity: identitymemory.NewWithClock(clk)}
	var err error
	if w.epochs, err = revoke.NewEpochs(fx.Outage.Epochs(w.identity), revoke.Config{Clock: clk, Events: fx.Events}); err != nil {
		t.Fatal(err)
	}
	renewer, err := session.NewRenewer(session.RenewConfig{
		Authority: authority{id: w.identity, enr: fx.Enrollment}, Claims: fx.Claims,
		Lifetimes: fx.Lifetimes, Clock: clk, Events: fx.Events,
	})
	if err != nil {
		t.Fatal(err)
	}
	if w.cookies, err = cookie.NewPolicy(cookie.Options{PublicOrigin: publicOrigin}); err != nil {
		t.Fatal(err)
	}
	if w.backend, err = stateful.New(stateful.Config{
		Sessions: flakySessions{Store: w.sessions, o: fx.Outage}, Epochs: w.epochs, Renewer: renewer,
		Cookies: w.cookies, Clock: clk, Events: fx.Events,
	}); err != nil {
		t.Fatal(err)
	}
	fx.Identity = w.identity
	fx.Start = w.backend.Start
	fx.Reissue = w.backend.Reissue
	fx.Poll = w.epochs.Poll
	fx.Forge = w.forge
	fx.Carry = carry
	fx.StableCredentials = true
	return w
}

func carry(resp, next http.Header) {
	if v := resp.Get(stateful.HeaderSessionToken); v != "" {
		next.Set("Authorization", "Bearer "+v)
	}
}

func (w *world) token(t *testing.T, c backendtest.Credentials) (string, core.Transport) {
	t.Helper()
	name := w.cookies.CookieName(cookie.StatefulSession)
	for _, ck := range c.Cookies {
		if ck.Name == name {
			return ck.Value, core.TransportCookies
		}
	}
	if v, ok := strings.CutPrefix(c.Header.Get("Authorization"), "Bearer "); ok {
		return v, core.TransportBearer
	}
	t.Fatal("no session token in the credentials")
	return "", 0
}

func (w *world) present(tok string, tr core.Transport) backendtest.Credentials {
	if tr == core.TransportCookies {
		return backendtest.Credentials{Cookies: []*http.Cookie{{Name: w.cookies.CookieName(cookie.StatefulSession), Value: tok}}, Header: http.Header{}}
	}
	return backendtest.Credentials{Header: http.Header{"Authorization": {"Bearer " + tok}}}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func (w *world) forge(t *testing.T, f backendtest.Forgery, c backendtest.Credentials) backendtest.Credentials {
	t.Helper()
	tok, tr := w.token(t, c)
	switch f {
	case backendtest.ForgeLegacy:
		return w.present(hex.EncodeToString(randomBytes(t, 32)), tr)
	case backendtest.ForgeRandomFamily:
		_, ten, _ := strings.Cut(tok, ".")
		return w.present(base64.RawURLEncoding.EncodeToString(randomBytes(t, 32))+"."+ten, tr)
	case backendtest.ForgeOtherTransport:
		if tr == core.TransportCookies {
			return w.present(tok, core.TransportBearer)
		}
		return w.present(tok, core.TransportCookies)
	}
	t.Fatalf("unknown forgery %d", f)
	return backendtest.Credentials{}
}

func tenant(t *testing.T) principal.TenantID {
	t.Helper()
	tn, err := principal.ParseTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

func mustUser(t *testing.T, w *world) principal.Subject {
	t.Helper()
	email, err := identity.NewIdentifier(identity.IdentifierEmail, "u-"+uuid.NewString()+"@example.test")
	if err != nil {
		t.Fatal(err)
	}
	out, err := w.identity.Apply(t.Context(), identity.CreateVerified{Tenant: tenant(t), Email: email})
	if err != nil {
		t.Fatal(err)
	}
	return out.Subject
}

func attrsFor(t *testing.T, w *world, s principal.Subject, tr core.Transport, remember bool) core.SessionAttrs {
	t.Helper()
	epoch, err := w.identity.CurrentEpoch(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	now := w.fx.Clock.Now()
	return principaltest.Attrs(principaltest.Spec{
		Lineage: uuid.New(), Subject: s, Factors: []core.Factor{core.FactorPassword}, PrimaryAt: now,
		Epoch: epoch, Transport: tr, RememberMe: remember, CreatedAt: now, ClaimsFetchedAt: now,
	})
}

func start(t *testing.T, w *world, a core.SessionAttrs) (string, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := w.backend.Start(t.Context(), rec, a, w.fx.Claims.Value()); err != nil {
		t.Fatal(err)
	}
	if a.Transport() == core.TransportBearer {
		return rec.Header().Get(stateful.HeaderSessionToken), rec
	}
	for _, ck := range (&http.Response{Header: rec.Header()}).Cookies() {
		if ck.Name == w.cookies.CookieName(cookie.StatefulSession) {
			return ck.Value, rec
		}
	}
	t.Fatal("Start wrote no session cookie")
	return "", rec
}

func cookieRequest(t *testing.T, w *world, tok string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://acme.example.test/", nil)
	r.AddCookie(&http.Cookie{Name: w.cookies.CookieName(cookie.StatefulSession), Value: tok})
	return r
}

func bearerRequest(t *testing.T, tok string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://acme.example.test/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

func sessionCookie(t *testing.T, w *world, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, ck := range (&http.Response{Header: rec.Header()}).Cookies() {
		if ck.Name == w.cookies.CookieName(cookie.StatefulSession) {
			return ck
		}
	}
	return nil
}
