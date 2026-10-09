package stateful_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/internal/session/backendtest"
	"github.com/JLugagne/egauth/internal/session/stateful"
	"github.com/JLugagne/egauth/store"
	sessionsmemory "github.com/JLugagne/egauth/store/sessions/memory"
)

func digest(t *testing.T, tok string) []byte {
	t.Helper()
	raw, _, _ := strings.Cut(tok, ".")
	secret, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(secret)
	return sum[:]
}

// TestAnonymousSessionCannotBeStarted closes T-16: attributes without a subject are refused before
// anything is stored or written, so no session row and no Resumed can lack a user.
func TestAnonymousSessionCannotBeStarted(t *testing.T) {
	w := buildWorld(t, backendtest.NewFixture(t))
	now := w.fx.Clock.Now()
	anonymous := []core.SessionAttrs{
		{},
		principaltest.Attrs(principaltest.Spec{
			Lineage: uuid.New(), Subject: core.Subject{Tenant: tenant(t)}, Factors: []core.Factor{core.FactorPassword},
			PrimaryAt: now, Transport: core.TransportCookies, CreatedAt: now, ClaimsFetchedAt: now,
		}),
	}
	for i, a := range anonymous {
		rec := httptest.NewRecorder()
		if err := w.backend.Start(t.Context(), rec, a, w.fx.Claims.Value()); !errors.Is(err, core.ErrInvalidArgument) {
			t.Fatalf("case %d: Start of an anonymous session: %v", i, err)
		}
		if len(rec.Header()) != 0 {
			t.Fatalf("case %d: a refused Start wrote %v", i, rec.Header())
		}
	}
	if n, err := w.sessions.ReapExpired(t.Context()); err != nil || n != 0 {
		t.Fatalf("a refused Start stored rows: %d, %v", n, err)
	}
}

// TestRowStoresTheSealedAttributes closes I-20 and T-17: the row holds the very sealed attributes
// and claims the session was admitted with, remember_me, must-change, factors and freshness
// included, and Resume replays them verbatim.
func TestRowStoresTheSealedAttributes(t *testing.T) {
	w := buildWorld(t, backendtest.NewFixture(t))
	s := mustUser(t, w)
	now := w.fx.Clock.Now()
	epoch, err := w.identity.CurrentEpoch(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	a := principaltest.Attrs(principaltest.Spec{
		Lineage: uuid.New(), Subject: s,
		Factors:     []core.Factor{core.FactorPasskey, core.FactorUserVerification, core.FactorTOTP},
		PasskeyUses: []principaltest.Credential{{Factor: core.FactorPasskey, ID: []byte{7, 7}}},
		PrimaryAt:   now.Add(-time.Minute), SecondAt: now, Epoch: epoch, RememberMe: true, MustChange: true,
		ReturnTo: "/after?x=1", Transport: core.TransportCookies, Provider: "google", CreatedAt: now, ClaimsFetchedAt: now,
	})
	tok, _ := start(t, w, a)
	rec, err := w.sessions.Get(t.Context(), s.Tenant, digest(t, tok))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := core.Unseal(rec.Sealed())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored, a) {
		t.Fatalf("stored attributes differ\n got: %#v\nwant: %#v", stored, a)
	}
	if string(rec.AppClaims()) != string(w.fx.Claims.Value().Bytes()) {
		t.Fatalf("stored claims %s", rec.AppClaims())
	}
	res, err := w.backend.Resume(t.Context(), httptest.NewRecorder(), cookieRequest(t, w, tok))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Attrs(), a) || res.Handle().ID() != rec.ID() {
		t.Fatal("Resume did not replay the stored session")
	}
}

// TestCookieTracksServerExpiry closes C-21: every idle extension rewrites the cookie with Max-Age =
// min(idle, absolute remaining) for a remembered session, and as a browser-session cookie
// otherwise, on Touch and on renewal alike.
func TestCookieTracksServerExpiry(t *testing.T) {
	w := buildWorld(t, backendtest.NewFixture(t))
	life := w.fx.Lifetimes
	s := mustUser(t, w)
	a := attrsFor(t, w, s, core.TransportCookies, true)
	tok, rec := start(t, w, a)
	if ck := sessionCookie(t, w, rec); ck == nil || ck.MaxAge != int(life.IdleTimeout/time.Second) {
		t.Fatalf("Start cookie: %+v", ck)
	}
	end := a.CreatedAt().Add(life.MaxLifetime)
	for _, step := range []time.Duration{time.Minute, life.RecheckEvery, 30 * time.Minute, 40 * time.Minute} {
		for w.fx.Clock.Now().Add(step).Before(end) {
			w.fx.Clock.Advance(step)
			rr := httptest.NewRecorder()
			if _, err := w.backend.Resume(t.Context(), rr, cookieRequest(t, w, tok)); err != nil {
				t.Fatal(err)
			}
			now := w.fx.Clock.Now()
			want := min(life.IdleTimeout, end.Sub(now))
			ck := sessionCookie(t, w, rr)
			if ck == nil || ck.Value != tok {
				t.Fatalf("at %s: cookie not rewritten with the same token: %+v", now, ck)
			}
			got := time.Duration(ck.MaxAge) * time.Second
			if got < want || got >= want+time.Second {
				t.Fatalf("at %s: Max-Age %s, want min(idle, absolute remaining) = %s", now, got, want)
			}
		}
	}
	w.fx.Clock.Set(end)
	if _, err := w.backend.Resume(t.Context(), httptest.NewRecorder(), cookieRequest(t, w, tok)); err == nil {
		t.Fatal("session served at its absolute end")
	}

	b := attrsFor(t, w, s, core.TransportCookies, false)
	tok, rec = start(t, w, b)
	for _, rr := range []*httptest.ResponseRecorder{rec, nil, nil} {
		if rr == nil {
			w.fx.Clock.Advance(life.RecheckEvery)
			rr = httptest.NewRecorder()
			if _, err := w.backend.Resume(t.Context(), rr, cookieRequest(t, w, tok)); err != nil {
				t.Fatal(err)
			}
		}
		if ck := sessionCookie(t, w, rr); ck == nil || ck.MaxAge != 0 {
			t.Fatalf("a session that is not remembered got a persistent or no cookie: %+v", ck)
		}
	}
}

func TestBearerResumeWritesNothing(t *testing.T) {
	w := buildWorld(t, backendtest.NewFixture(t))
	s := mustUser(t, w)
	tok, rec := start(t, w, attrsFor(t, w, s, core.TransportBearer, true))
	if rec.Header().Get("Cache-Control") != "no-store" || len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("Bearer Start headers: %v", rec.Header())
	}
	for _, d := range []time.Duration{time.Second, w.fx.Lifetimes.RecheckEvery} {
		w.fx.Clock.Advance(d)
		rr := httptest.NewRecorder()
		if _, err := w.backend.Resume(t.Context(), rr, bearerRequest(t, tok)); err != nil {
			t.Fatal(err)
		}
		if len(rr.Header()) != 0 {
			t.Fatalf("Bearer Resume wrote %v", rr.Header())
		}
	}
}

func TestBothTransportsAreRefused(t *testing.T) {
	w := buildWorld(t, backendtest.NewFixture(t))
	s := mustUser(t, w)
	ctok, _ := start(t, w, attrsFor(t, w, s, core.TransportCookies, true))
	btok, _ := start(t, w, attrsFor(t, w, s, core.TransportBearer, true))
	for name, auth := range map[string]string{"token": "Bearer " + btok, "scheme only": "Bearer"} {
		r := cookieRequest(t, w, ctok)
		r.Header.Set("Authorization", auth)
		rr := httptest.NewRecorder()
		if _, err := w.backend.Resume(t.Context(), rr, r); !errors.Is(err, stateful.ErrAmbiguousTransport) {
			t.Fatalf("%s: %v", name, err)
		}
		if len(rr.Header()) != 0 {
			t.Fatalf("%s: a refused Resume wrote %v", name, rr.Header())
		}
	}
}

func TestEndRevokesEveryPresentedToken(t *testing.T) {
	w := buildWorld(t, backendtest.NewFixture(t))
	s := mustUser(t, w)
	ctok, _ := start(t, w, attrsFor(t, w, s, core.TransportCookies, true))
	btok, _ := start(t, w, attrsFor(t, w, s, core.TransportBearer, true))
	r := cookieRequest(t, w, ctok)
	r.Header.Set("Authorization", "Bearer "+btok)
	rr := httptest.NewRecorder()
	if err := w.backend.End(t.Context(), rr, r); err != nil {
		t.Fatal(err)
	}
	if ck := sessionCookie(t, w, rr); ck == nil || ck.MaxAge >= 0 {
		t.Fatalf("End did not clear the cookie: %+v", ck)
	}
	if _, err := w.backend.Resume(t.Context(), httptest.NewRecorder(), cookieRequest(t, w, ctok)); !errors.Is(err, stateful.ErrInvalidToken) {
		t.Fatalf("cookie session after End: %v", err)
	}
	if _, err := w.backend.Resume(t.Context(), httptest.NewRecorder(), bearerRequest(t, btok)); !errors.Is(err, stateful.ErrInvalidToken) {
		t.Fatalf("Bearer session after End: %v", err)
	}
}

func TestEndClearsCookiesItCannotRead(t *testing.T) {
	w := buildWorld(t, backendtest.NewFixture(t))
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://acme.example.test/", nil)
	r.AddCookie(&http.Cookie{Name: w.cookies.CookieName(cookie.StatefulSession), Value: "not-a-token"})
	r.AddCookie(&http.Cookie{Name: w.cookies.CookieName(cookie.StatefulSession), Value: "a-duplicate"})
	rr := httptest.NewRecorder()
	if err := w.backend.End(t.Context(), rr, r); err != nil {
		t.Fatal(err)
	}
	if ck := sessionCookie(t, w, rr); ck == nil || ck.MaxAge >= 0 {
		t.Fatalf("End did not clear an unreadable cookie: %+v", ck)
	}
}

func TestTokenIsBoundToItsTenant(t *testing.T) {
	w := buildWorld(t, backendtest.NewFixture(t))
	s := mustUser(t, w)
	tok, _ := start(t, w, attrsFor(t, w, s, core.TransportBearer, true))
	raw, _, _ := strings.Cut(tok, ".")
	for _, forged := range []string{raw, raw + ".other", raw + ".BAD"} {
		if _, err := w.backend.Resume(t.Context(), httptest.NewRecorder(), bearerRequest(t, forged)); !errors.Is(err, stateful.ErrInvalidToken) {
			t.Fatalf("token %q of another tenant: %v", forged, err)
		}
	}
}

func TestStoreOutageIsUnavailable(t *testing.T) {
	w := buildWorld(t, backendtest.NewFixture(t))
	s := mustUser(t, w)
	tok, _ := start(t, w, attrsFor(t, w, s, core.TransportBearer, true))
	w.fx.Outage.Set(true)
	if _, err := w.backend.Resume(t.Context(), httptest.NewRecorder(), bearerRequest(t, tok)); !errors.Is(err, httpx.ErrUnavailable) {
		t.Fatalf("Resume during a store outage: %v", err)
	}
	w.fx.Outage.Set(false)
	if _, err := w.backend.Resume(t.Context(), httptest.NewRecorder(), bearerRequest(t, tok)); err != nil {
		t.Fatal(err)
	}
}

func TestReissueRevokesTheSessionOfAnUnknownSubject(t *testing.T) {
	w := buildWorld(t, backendtest.NewFixture(t))
	s := mustUser(t, w)
	a := attrsFor(t, w, s, core.TransportCookies, true)
	tok, _ := start(t, w, a)
	res, err := w.backend.Resume(t.Context(), httptest.NewRecorder(), cookieRequest(t, w, tok))
	if err != nil {
		t.Fatal(err)
	}
	w.fx.Claims.Forget()
	rr := httptest.NewRecorder()
	if err := w.backend.Reissue(t.Context(), rr, res.Handle(), a); !errors.Is(err, core.ErrClaimsSubjectUnknown) {
		t.Fatalf("Reissue for an unknown subject: %v", err)
	}
	if len(rr.Header()) != 0 {
		t.Fatalf("a refused Reissue wrote %v", rr.Header())
	}
	if w.fx.Events.Count(event.Logout) != 1 {
		t.Fatal("no Logout event for the revoked session")
	}
	w.fx.Claims.Recover()
	if _, err := w.backend.Resume(t.Context(), httptest.NewRecorder(), cookieRequest(t, w, tok)); !errors.Is(err, stateful.ErrInvalidToken) {
		t.Fatalf("session of an unknown subject survived: %v", err)
	}
}

// TestRenewalKeepsTheAbsoluteEndOfItsRow asserts that raising MaxLifetime never extends a live
// session: its row keeps the absolute end it was written with, and renewal still succeeds.
func TestRenewalKeepsTheAbsoluteEndOfItsRow(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx)
	s := mustUser(t, w)
	a := attrsFor(t, w, s, core.TransportBearer, true)
	tok, _ := start(t, w, a)
	longer := fx.Lifetimes
	longer.MaxLifetime *= 2
	renewer, err := session.NewRenewer(session.RenewConfig{
		Authority: authority{id: w.identity, enr: fx.Enrollment}, Claims: fx.Claims, Lifetimes: longer, Clock: fx.Clock.Clock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := stateful.New(stateful.Config{Sessions: w.sessions, Epochs: w.epochs, Renewer: renewer, Cookies: w.cookies, Clock: fx.Clock.Clock()})
	if err != nil {
		t.Fatal(err)
	}
	end := a.CreatedAt().Add(fx.Lifetimes.MaxLifetime)
	for fx.Clock.Now().Add(fx.Lifetimes.IdleTimeout / 2).Before(end) {
		fx.Clock.Advance(fx.Lifetimes.IdleTimeout / 2)
		if _, err := b.Resume(t.Context(), httptest.NewRecorder(), bearerRequest(t, tok)); err != nil {
			t.Fatalf("renewal under a longer MaxLifetime: %v", err)
		}
	}
	fx.Clock.Set(end)
	if _, err := b.Resume(t.Context(), httptest.NewRecorder(), bearerRequest(t, tok)); err == nil {
		t.Fatal("a longer MaxLifetime extended a live session")
	}
}

func TestNewValidatesItsConfiguration(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx)
	renewer, err := session.NewRenewer(session.RenewConfig{
		Authority: authority{id: w.identity, enr: fx.Enrollment}, Claims: fx.Claims, Lifetimes: fx.Lifetimes,
	})
	if err != nil {
		t.Fatal(err)
	}
	epochs, err := revoke.NewEpochs(w.identity, revoke.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ok := stateful.Config{Sessions: sessionsmemory.New(), Epochs: epochs, Renewer: renewer, Cookies: w.cookies}
	if _, err := stateful.New(ok); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*stateful.Config){
		"sessions": func(c *stateful.Config) { c.Sessions = nil },
		"epochs":   func(c *stateful.Config) { c.Epochs = nil },
		"renewer":  func(c *stateful.Config) { c.Renewer = nil },
		"cookies":  func(c *stateful.Config) { c.Cookies = cookie.Policy{} },
	} {
		cfg := ok
		mutate(&cfg)
		if _, err := stateful.New(cfg); !errors.Is(err, stateful.ErrInvalidConfig) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestDurabilityIsTheStores(t *testing.T) {
	w := buildWorld(t, backendtest.NewFixture(t))
	if w.backend.Durability() != store.Ephemeral {
		t.Fatal("durability is not the memory store's")
	}
}
