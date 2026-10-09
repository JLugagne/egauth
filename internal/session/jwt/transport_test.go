package jwt_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/session/backendtest"
	"github.com/JLugagne/egauth/internal/session/jwt"
)

func withCookies(r *http.Request, cks ...*http.Cookie) *http.Request {
	for _, ck := range cks {
		r.AddCookie(ck)
	}
	return r
}

func TestBearerSessionIgnoresUnrelatedCookies(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	ctx := t.Context()
	s := mustUser(t, w)
	access, refresh := startPair(t, w, passwordAttrs(t, w, s, core.TransportBearer))
	sticky := &http.Cookie{Name: "AWSALB", Value: "sticky"}
	if _, err := w.backend.Resume(ctx, httptest.NewRecorder(), withCookies(bearerRequest(t, access, refresh), sticky)); err != nil {
		t.Fatalf("Bearer session carrying an unrelated cookie: %v", err)
	}
	fx.Clock.Advance(fx.Lifetimes.RecheckEvery + time.Second)
	rec := httptest.NewRecorder()
	if _, err := w.backend.Resume(ctx, rec, withCookies(bearerRequest(t, access, refresh), sticky)); err != nil {
		t.Fatalf("renewal of a Bearer session carrying an unrelated cookie: %v", err)
	}
	if rec.Header().Get(jwt.HeaderAccessToken) == "" || len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("the renewal was not written on the Bearer transport")
	}
}

func TestCookieSessionKeepsCookieTransportBesideUnrelatedCookies(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	s := mustUser(t, w)
	access, refresh := startPair(t, w, passwordAttrs(t, w, s, core.TransportCookies))
	r := withCookies(cookieRequest(t, w, access, refresh), &http.Cookie{Name: "AWSALB", Value: "sticky"})
	r.Header.Set("Authorization", "Basic c3RhZ2luZzpzdGFnaW5n")
	if _, err := w.backend.Resume(t.Context(), httptest.NewRecorder(), r); err != nil {
		t.Fatalf("cookie session beside an unrelated cookie and Basic authorization: %v", err)
	}
}

func TestBothTransportsAreRefused(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	ctx := t.Context()
	s := mustUser(t, w)
	cookieAccess, cookieRefresh := startPair(t, w, passwordAttrs(t, w, s, core.TransportCookies))
	bearerAccess, bearerRefresh := startPair(t, w, passwordAttrs(t, w, s, core.TransportBearer))
	accessName := w.cookies.CookieName(cookie.AccessToken)
	cases := map[string]*http.Request{
		"Bearer pair beside the session cookies": withCookies(bearerRequest(t, bearerAccess, bearerRefresh),
			&http.Cookie{Name: accessName, Value: cookieAccess},
			&http.Cookie{Name: w.cookies.CookieName(cookie.RefreshToken), Value: cookieRefresh}),
		"Bearer refresh token beside the access cookie": withCookies(bearerRequest(t, "", bearerRefresh),
			&http.Cookie{Name: accessName, Value: cookieAccess}),
		"duplicated Bearer authorization beside the session cookies": duplicatedBearer(t, w, bearerAccess, cookieAccess, cookieRefresh),
	}
	for _, renewing := range []bool{false, true} {
		if renewing {
			fx.Clock.Advance(fx.Lifetimes.RecheckEvery + time.Second)
		}
		for name, r := range cases {
			rec := httptest.NewRecorder()
			_, err := w.backend.Resume(ctx, rec, r.Clone(ctx))
			if err == nil || errors.Is(err, httpx.ErrUnavailable) {
				t.Fatalf("%s (renewing %t): %v, want a refusal", name, renewing, err)
			}
			if len(rec.Header()) != 0 {
				t.Fatalf("%s (renewing %t): refused request wrote %v", name, renewing, rec.Header())
			}
		}
	}
	if _, err := w.backend.Resume(ctx, httptest.NewRecorder(), bearerRequest(t, bearerAccess, bearerRefresh)); err != nil {
		t.Fatalf("Bearer session after refused mixes: %v", err)
	}
	if _, err := w.backend.Resume(ctx, httptest.NewRecorder(), cookieRequest(t, w, cookieAccess, cookieRefresh)); err != nil {
		t.Fatalf("cookie session after refused mixes: %v", err)
	}
}

func duplicatedBearer(t *testing.T, w *world, bearerAccess, cookieAccess, cookieRefresh string) *http.Request {
	t.Helper()
	r := cookieRequest(t, w, cookieAccess, cookieRefresh)
	r.Header.Add("Authorization", "Bearer "+bearerAccess)
	r.Header.Add("Authorization", "Bearer "+bearerAccess)
	return r
}

func TestRefreshOnlyRequestRacingARotationIsRetryable(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	ctx := t.Context()
	s := mustUser(t, w)
	access, refresh := startPair(t, w, passwordAttrs(t, w, s, core.TransportBearer))
	fx.Clock.Advance(fx.Lifetimes.RecheckEvery + time.Second)
	rec := httptest.NewRecorder()
	if _, err := w.backend.Resume(ctx, rec, bearerRequest(t, access, refresh)); err != nil {
		t.Fatal(err)
	}
	next, nextRefresh := rec.Header().Get(jwt.HeaderAccessToken), rec.Header().Get(jwt.HeaderRefreshToken)
	fx.Clock.Advance(time.Second)
	rec = httptest.NewRecorder()
	_, err := w.backend.Resume(ctx, rec, bearerRequest(t, "", refresh))
	if !errors.Is(err, httpx.ErrUnavailable) {
		t.Fatalf("refresh-only request racing a rotation: %v, want a retryable refusal", err)
	}
	if len(rec.Header()) != 0 {
		t.Fatalf("racing request wrote %v", rec.Header())
	}
	if _, err := w.backend.Resume(ctx, httptest.NewRecorder(), bearerRequest(t, next, nextRefresh)); err != nil {
		t.Fatalf("family after the race: %v", err)
	}
}

func TestReissueRevokesTheFamilyOfAnUnknownSubject(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	ctx := t.Context()
	s := mustUser(t, w)
	a := passwordAttrs(t, w, s, core.TransportCookies)
	access, refresh := startPair(t, w, a)
	res, err := w.backend.Resume(ctx, httptest.NewRecorder(), cookieRequest(t, w, access, refresh))
	if err != nil {
		t.Fatal(err)
	}
	fx.Claims.Forget()
	rec := httptest.NewRecorder()
	err = w.backend.Reissue(ctx, rec, res.Handle(), a)
	if !errors.Is(err, core.ErrClaimsSubjectUnknown) || errors.Is(err, httpx.ErrUnavailable) {
		t.Fatalf("Reissue for a subject the claims source forgot: %v, want ErrClaimsSubjectUnknown as a refusal", err)
	}
	if len(rec.Header()) != 0 {
		t.Fatalf("refused Reissue wrote %v", rec.Header())
	}
	if fx.Events.Count(event.TokenFamilyRevoked) == 0 {
		t.Fatal("no TokenFamilyRevoked event")
	}
	fx.Claims.Recover()
	if _, err := w.backend.Resume(ctx, httptest.NewRecorder(), cookieRequest(t, w, access, refresh)); err == nil || errors.Is(err, httpx.ErrUnavailable) {
		t.Fatalf("the family of an unknown subject survived Reissue: %v", err)
	}
}

func TestEndClearsSessionCookiesItCannotRead(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	s := mustUser(t, w)
	access, _ := startPair(t, w, passwordAttrs(t, w, s, core.TransportCookies))
	name := w.cookies.CookieName(cookie.AccessToken)
	r := withCookies(httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://acme.example.test/logout", nil),
		&http.Cookie{Name: name, Value: access}, &http.Cookie{Name: name, Value: access})
	rec := httptest.NewRecorder()
	if err := w.backend.End(t.Context(), rec, r); err != nil {
		t.Fatal(err)
	}
	cleared := map[string]bool{}
	for _, ck := range (&http.Response{Header: rec.Header()}).Cookies() {
		cleared[ck.Name] = ck.MaxAge < 0
	}
	if !cleared[name] || !cleared[w.cookies.CookieName(cookie.RefreshToken)] {
		t.Fatalf("End beside a duplicated session cookie cleared %v", cleared)
	}
}
