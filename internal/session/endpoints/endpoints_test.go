package endpoints_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/clientaddr"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/keys"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/internal/session/backendtest"
	"github.com/JLugagne/egauth/internal/session/endpoints"
	"github.com/JLugagne/egauth/internal/session/jwt"
	"github.com/JLugagne/egauth/internal/session/stateful"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
	identitymemory "github.com/JLugagne/egauth/store/identity/memory"
	"github.com/JLugagne/egauth/store/limiter"
	"github.com/JLugagne/egauth/store/sessions"
	sessionsmemory "github.com/JLugagne/egauth/store/sessions/memory"
	tokensmemory "github.com/JLugagne/egauth/store/tokens/memory"
)

const (
	origin   = "https://acme.example.test"
	basePath = "/auth"
)

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

type acmeTenant struct{ t core.TenantID }

func (r acmeTenant) ResolveTenant(*http.Request) (core.TenantID, error) { return r.t, nil }

type allowAll struct{}

func (allowAll) Allow(context.Context, limiter.Key) (limiter.Decision, error) {
	return limiter.Decision{Allowed: true}, nil
}

type noIdentifiers struct{}

func (noIdentifiers) Normalize(string) (identity.Identifier, error) {
	return identity.Identifier{}, errors.New("no identifiers")
}

type notEnrolled struct{}

func (notEnrolled) MFARequired(context.Context, core.Subject) (bool, error) { return false, nil }

type flakyEnd struct {
	sessions.Store
	down bool
}

func (f *flakyEnd) RevokeForSubject(ctx context.Context, s principal.Subject, except uuid.UUID) error {
	if f.down {
		return errors.New("sessions store down")
	}
	return f.Store.RevokeForSubject(ctx, s, except)
}

func (f *flakyEnd) Revoke(ctx context.Context, t principal.TenantID, tokenHash []byte) error {
	if f.down {
		return errors.New("sessions store down")
	}
	return f.Store.Revoke(ctx, t, tokenHash)
}

type world struct {
	t        *testing.T
	fx       *backendtest.Fixture
	backend  *stateful.Backend
	store    *flakyEnd
	identity *identitymemory.Store
	cookies  cookie.Policy
	tenant   core.TenantID
	mux      *http.ServeMux
}

func newWorld(t *testing.T) *world {
	t.Helper()
	fx := backendtest.NewFixture(t)
	clk := fx.Clock.Clock()
	w := &world{t: t, fx: fx, identity: identitymemory.NewWithClock(clk)}
	w.store = &flakyEnd{Store: sessionsmemory.NewWithClock(clk)}
	var err error
	if w.tenant, err = principal.ParseTenantID("acme"); err != nil {
		t.Fatal(err)
	}
	epochs, err := revoke.NewEpochs(w.identity, revoke.Config{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	renewer, err := session.NewRenewer(session.RenewConfig{
		Authority: authority{id: w.identity, enr: fx.Enrollment}, Claims: fx.Claims, Lifetimes: fx.Lifetimes, Clock: clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	if w.cookies, err = cookie.NewPolicy(cookie.Options{PublicOrigin: "https://{tenant}.example.test"}); err != nil {
		t.Fatal(err)
	}
	if w.backend, err = stateful.New(stateful.Config{Sessions: w.store, Epochs: epochs, Renewer: renewer, Cookies: w.cookies, Clock: clk}); err != nil {
		t.Fatal(err)
	}
	w.mux = w.mount(w.backend)
	return w
}

func (w *world) mount(b session.Backend) *http.ServeMux {
	t := w.t
	t.Helper()
	eps, err := endpoints.Endpoints(endpoints.Config{Backend: b, Audit: httpx.SinkAudit(w.fx.Events)})
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := routes.NewTable(eps...)
	if err != nil {
		t.Fatal(err)
	}
	res, err := clientaddr.New(clientaddr.Direct(), nil)
	if err != nil {
		t.Fatal(err)
	}
	o, err := csrf.NewOrigins("https://{tenant}.example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := httpx.NewPreamble(httpx.Env{
		Tenants: acmeTenant{t: w.tenant}, Limiter: allowAll{}, Authenticator: b,
		Identifiers: noIdentifiers{}, Enrollment: notEnrolled{}, Clock: w.fx.Clock.Clock(), Audit: httpx.SinkAudit(w.fx.Events),
	}, httpx.Settings{Clients: res, Origins: o, Transports: httpx.CookiesAndBearer, ReauthWindow: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := tbl.Mount(mux, basePath, p); err != nil {
		t.Fatal(err)
	}
	return mux
}

func (w *world) user() principal.Subject {
	w.t.Helper()
	email, err := identity.NewIdentifier(identity.IdentifierEmail, "u-"+uuid.NewString()+"@example.test")
	if err != nil {
		w.t.Fatal(err)
	}
	out, err := w.identity.Apply(w.t.Context(), identity.CreateVerified{Tenant: w.tenant, Email: email})
	if err != nil {
		w.t.Fatal(err)
	}
	return out.Subject
}

func (w *world) spec(s principal.Subject, tr core.Transport) principaltest.Spec {
	w.t.Helper()
	epoch, err := w.identity.CurrentEpoch(w.t.Context(), s)
	if err != nil {
		w.t.Fatal(err)
	}
	now := w.fx.Clock.Now()
	return principaltest.Spec{
		Lineage: uuid.New(), Subject: s, Factors: []core.Factor{core.FactorPassword, core.FactorTOTP},
		PrimaryAt: now, SecondAt: now, Epoch: epoch, RememberMe: true, ReturnTo: "/inbox", Transport: tr,
		CreatedAt: now, ClaimsFetchedAt: now,
	}
}

type creds struct {
	cookie string
	bearer string
}

func (w *world) start(a core.SessionAttrs) creds {
	w.t.Helper()
	rec := httptest.NewRecorder()
	if err := w.backend.Start(w.t.Context(), rec, a, w.fx.Claims.Value()); err != nil {
		w.t.Fatal(err)
	}
	if a.Transport() == core.TransportBearer {
		return creds{bearer: rec.Header().Get(stateful.HeaderSessionToken)}
	}
	for _, ck := range (&http.Response{Header: rec.Header()}).Cookies() {
		if ck.Name == w.cookies.CookieName(cookie.StatefulSession) {
			return creds{cookie: ck.Value}
		}
	}
	w.t.Fatal("no session cookie")
	return creds{}
}

func (w *world) do(method, path string, c creds) *httptest.ResponseRecorder {
	w.t.Helper()
	r := httptest.NewRequestWithContext(w.t.Context(), method, origin+basePath+path, nil)
	r.RemoteAddr = "198.51.100.7:1"
	if method == http.MethodPost {
		r.Header.Set("Origin", origin)
	}
	if c.cookie != "" {
		r.AddCookie(&http.Cookie{Name: w.cookies.CookieName(cookie.StatefulSession), Value: c.cookie})
	}
	if c.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	rec := httptest.NewRecorder()
	w.mux.ServeHTTP(rec, r)
	return rec
}

func (w *world) expect(rec *httptest.ResponseRecorder, status int, what string) {
	w.t.Helper()
	if rec.Code != status {
		w.t.Fatalf("%s: status %d, want %d (%s)", what, rec.Code, status, rec.Body.String())
	}
}

func cleared(rec *httptest.ResponseRecorder, name string) bool {
	for _, ck := range (&http.Response{Header: rec.Header()}).Cookies() {
		if ck.Name == name && ck.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestSessionAnswersTheResumedAttributes(t *testing.T) {
	w := newWorld(t)
	s := w.user()
	spec := w.spec(s, core.TransportCookies)
	spec.MustChange = true
	c := w.start(principaltest.Attrs(spec))
	rec := w.do(http.MethodGet, routes.Session, c)
	w.expect(rec, http.StatusOK, "GET /session of a must-change session")
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var amr []any
	for _, v := range principaltest.Attrs(spec).AMR() {
		amr = append(amr, v)
	}
	want := map[string]any{
		"subject": s.User.String(), "tenant": "acme", "factors": []any{core.FactorPassword.Code(), core.FactorTOTP.Code()},
		"amr": amr, "remember_me": true, "return_to": "/inbox", "password_change_required": true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GET /session body\n got: %v\nwant: %v", got, want)
	}
	w.expect(w.do(http.MethodGet, routes.Session, creds{}), http.StatusUnauthorized, "GET /session without a session")
}

// TestLogoutEndsTheSessionOnItsBackend closes D-02: /logout ends the presented session on the
// backend that issued it, on both transports, and the old credentials are refused afterwards.
func TestLogoutEndsTheSessionOnItsBackend(t *testing.T) {
	w := newWorld(t)
	s := w.user()
	c := w.start(principaltest.Attrs(w.spec(s, core.TransportCookies)))
	w.expect(w.do(http.MethodGet, routes.Session, c), http.StatusOK, "live cookie session")
	rec := w.do(http.MethodPost, routes.Logout, c)
	w.expect(rec, http.StatusOK, "cookie logout")
	if !cleared(rec, w.cookies.CookieName(cookie.StatefulSession)) {
		t.Fatal("logout did not clear the session cookie")
	}
	w.expect(w.do(http.MethodGet, routes.Session, c), http.StatusUnauthorized, "old cookie after logout")

	b := w.start(principaltest.Attrs(w.spec(s, core.TransportBearer)))
	w.expect(w.do(http.MethodGet, routes.Session, b), http.StatusOK, "live Bearer session")
	w.expect(w.do(http.MethodPost, routes.Logout, b), http.StatusOK, "Bearer logout")
	w.expect(w.do(http.MethodGet, routes.Session, b), http.StatusUnauthorized, "old Bearer token after logout")

	w.expect(w.do(http.MethodPost, routes.Logout, b), http.StatusOK, "logout of an ended session")
	w.expect(w.do(http.MethodPost, routes.Logout, creds{}), http.StatusOK, "logout without credentials")
	if n := w.fx.Events.Count(event.Logout); n != 4 {
		t.Fatalf("%d Logout events, want 4", n)
	}
}

func TestLogoutOutageKeepsTheCredentials(t *testing.T) {
	w := newWorld(t)
	c := w.start(principaltest.Attrs(w.spec(w.user(), core.TransportCookies)))
	w.store.down = true
	rec := w.do(http.MethodPost, routes.Logout, c)
	w.expect(rec, http.StatusServiceUnavailable, "logout during an outage")
	if len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("a failed logout cleared the credentials the client needs to retry")
	}
	w.store.down = false
	w.expect(w.do(http.MethodPost, routes.Logout, c), http.StatusOK, "logout retry")
	w.expect(w.do(http.MethodGet, routes.Session, c), http.StatusUnauthorized, "session after the retried logout")
}

func TestLogoutEverywhereEndsEverySessionOfTheCaller(t *testing.T) {
	w := newWorld(t)
	s := w.user()
	spec := w.spec(s, core.TransportCookies)
	spec.PrimaryAt, spec.SecondAt = spec.PrimaryAt.Add(-24*time.Hour), time.Time{}
	spec.Factors = []core.Factor{core.FactorPassword}
	spec.CreatedAt = spec.CreatedAt.Add(-time.Hour)
	spec.ClaimsFetchedAt = spec.CreatedAt
	stale := w.start(principaltest.Attrs(spec))
	other := w.start(principaltest.Attrs(w.spec(s, core.TransportBearer)))
	stranger := w.start(principaltest.Attrs(w.spec(w.user(), core.TransportCookies)))
	rec := w.do(http.MethodPost, routes.LogoutEverywhere, stale)
	w.expect(rec, http.StatusOK, "logout-everywhere from a stale session")
	if !cleared(rec, w.cookies.CookieName(cookie.StatefulSession)) {
		t.Fatal("logout-everywhere did not clear the caller's cookie")
	}
	for _, sc := range rec.Header().Values("Set-Cookie") {
		if ck, err := http.ParseSetCookie(sc); err == nil && ck.MaxAge >= 0 {
			t.Fatalf("logout-everywhere answered a live credential: %s", sc)
		}
	}
	w.expect(w.do(http.MethodGet, routes.Session, stale), http.StatusUnauthorized, "caller session")
	w.expect(w.do(http.MethodGet, routes.Session, other), http.StatusUnauthorized, "other session of the caller")
	w.expect(w.do(http.MethodGet, routes.Session, stranger), http.StatusOK, "session of another subject")
	w.expect(w.do(http.MethodPost, routes.LogoutEverywhere, creds{}), http.StatusUnauthorized, "logout-everywhere without a session")
	if w.fx.Events.Count(event.Logout) != 1 {
		t.Fatal("no Logout event")
	}
}

func TestLogoutEverywhereOutageEndsNothing(t *testing.T) {
	w := newWorld(t)
	s := w.user()
	c := w.start(principaltest.Attrs(w.spec(s, core.TransportCookies)))
	other := w.start(principaltest.Attrs(w.spec(s, core.TransportBearer)))
	w.store.down = true
	rec := w.do(http.MethodPost, routes.LogoutEverywhere, c)
	w.expect(rec, http.StatusServiceUnavailable, "logout-everywhere during an outage")
	if cleared(rec, w.cookies.CookieName(cookie.StatefulSession)) {
		t.Fatal("a failed logout-everywhere cleared the credentials the client needs to retry")
	}
	w.store.down = false
	w.expect(w.do(http.MethodGet, routes.Session, other), http.StatusOK, "other session after the failed attempt")
	w.expect(w.do(http.MethodPost, routes.LogoutEverywhere, c), http.StatusOK, "logout-everywhere retry")
	w.expect(w.do(http.MethodGet, routes.Session, other), http.StatusUnauthorized, "other session after the retry")
}

func TestRefreshIsForBearerClients(t *testing.T) {
	w := newWorld(t)
	s := w.user()
	b := w.start(principaltest.Attrs(w.spec(s, core.TransportBearer)))
	w.fx.Claims.Set([]byte(`{"roles":["fresh"]}`))
	w.fx.Clock.Advance(w.fx.Lifetimes.RecheckEvery + time.Second)
	rec := w.do(http.MethodPost, routes.Refresh, b)
	w.expect(rec, http.StatusOK, "Bearer refresh")
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got["subject"] != s.User.String() {
		t.Fatalf("refresh body %s: %v", rec.Body.String(), err)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("refresh answer may be cached")
	}

	c := w.start(principaltest.Attrs(w.spec(s, core.TransportCookies)))
	rec = w.do(http.MethodPost, routes.Refresh, c)
	w.expect(rec, http.StatusUnauthorized, "refresh of a cookie session")
	if len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("a refused refresh wrote cookies")
	}
	moved := creds{bearer: c.cookie}
	w.expect(w.do(http.MethodPost, routes.Refresh, moved), http.StatusUnauthorized, "cookie session token presented as Bearer")
	w.expect(w.do(http.MethodPost, routes.Refresh, creds{}), http.StatusUnauthorized, "refresh without credentials")
}

type recorder struct {
	session.Backend
	calls []string
}

func (r *recorder) End(ctx context.Context, w http.ResponseWriter, req *http.Request) error {
	r.calls = append(r.calls, "End")
	return r.Backend.End(ctx, w, req)
}

func (r *recorder) OnDisabled(ctx context.Context, e lifecycle.AccountEvent) error {
	r.calls = append(r.calls, "OnDisabled")
	return r.Backend.OnDisabled(ctx, e)
}

func TestEndpointsUseOnlyTheGivenBackend(t *testing.T) {
	w := newWorld(t)
	rb := &recorder{Backend: w.backend}
	w.mux = w.mount(rb)
	c := w.start(principaltest.Attrs(w.spec(w.user(), core.TransportCookies)))
	w.expect(w.do(http.MethodPost, routes.LogoutEverywhere, c), http.StatusOK, "logout-everywhere")
	w.expect(w.do(http.MethodPost, routes.Logout, c), http.StatusOK, "logout")
	if !slices.Equal(rb.calls, []string{"OnDisabled", "End", "End"}) {
		t.Fatalf("backend calls %v", rb.calls)
	}
}

func TestEndpointsValidateTheirConfiguration(t *testing.T) {
	w := newWorld(t)
	for name, cfg := range map[string]endpoints.Config{
		"backend": {Audit: httpx.SinkAudit(nil)},
		"audit":   {Backend: w.backend},
	} {
		if _, err := endpoints.Endpoints(cfg); !errors.Is(err, endpoints.ErrInvalidConfig) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	eps, err := endpoints.Endpoints(endpoints.Config{Backend: w.backend, Audit: httpx.SinkAudit(nil)})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, e := range eps {
		paths = append(paths, e.Path)
		if e.Path == routes.LogoutEverywhere && (e.Meta.Sensitive || !e.Meta.Authenticated) {
			t.Fatal("/logout-everywhere must be established-only and not sensitive")
		}
	}
	if !slices.Equal(paths, []string{routes.Session, routes.Logout, routes.LogoutEverywhere, routes.Refresh}) {
		t.Fatalf("paths %v", paths)
	}
}

func (w *world) jwtBackend() *jwt.Backend {
	t := w.t
	t.Helper()
	clk := w.fx.Clock.Clock()
	signer, err := signing.EdDSA("k1", randomSeed(t))
	if err != nil {
		t.Fatal(err)
	}
	ks, err := keys.NewStatic(signer)
	if err != nil {
		t.Fatal(err)
	}
	toks := tokensmemory.NewWithClock(clk)
	families, err := revoke.NewFamilies(toks, revoke.Config{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	epochs, err := revoke.NewEpochs(w.identity, revoke.Config{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	renewer, err := session.NewRenewer(session.RenewConfig{
		Authority: authority{id: w.identity, enr: w.fx.Enrollment}, Claims: w.fx.Claims, Lifetimes: w.fx.Lifetimes, Clock: clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	codec, err := jwt.NewCodec(jwt.CodecConfig{PublicOrigin: "https://{tenant}.example.test", ClaimsFingerprint: "fp", RecheckEvery: w.fx.Lifetimes.RecheckEvery, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	b, err := jwt.New(jwt.Config{Codec: codec, Keys: ks, Tokens: toks, Families: families, Epochs: epochs, Renewer: renewer, Cookies: w.cookies, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func randomSeed(t *testing.T) []byte {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	return seed
}

func (w *world) doHeaders(method, path string, h http.Header) *httptest.ResponseRecorder {
	w.t.Helper()
	r := httptest.NewRequestWithContext(w.t.Context(), method, origin+basePath+path, nil)
	r.RemoteAddr = "198.51.100.7:1"
	maps.Copy(r.Header, h)
	rec := httptest.NewRecorder()
	w.mux.ServeHTTP(rec, r)
	return rec
}

func TestRefreshAndLogoutOnTheJWTBackend(t *testing.T) {
	w := newWorld(t)
	b := w.jwtBackend()
	w.mux = w.mount(b)
	s := w.user()
	rec := httptest.NewRecorder()
	if err := b.Start(t.Context(), rec, principaltest.Attrs(w.spec(s, core.TransportBearer)), w.fx.Claims.Value()); err != nil {
		t.Fatal(err)
	}
	refresh := rec.Header().Get(jwt.HeaderRefreshToken)
	w.fx.Clock.Advance(w.fx.Lifetimes.RecheckEvery + time.Second)
	got := w.doHeaders(http.MethodPost, routes.Refresh, http.Header{jwt.HeaderRefreshToken: {refresh}})
	w.expect(got, http.StatusOK, "JWT Bearer refresh")
	access, next := got.Header().Get(jwt.HeaderAccessToken), got.Header().Get(jwt.HeaderRefreshToken)
	if access == "" || next == "" || next == refresh {
		t.Fatal("refresh did not answer the rotated credentials")
	}
	live := http.Header{"Authorization": {"Bearer " + access}, jwt.HeaderRefreshToken: {next}}
	w.expect(w.doHeaders(http.MethodGet, routes.Session, live), http.StatusOK, "rotated credentials")
	w.expect(w.doHeaders(http.MethodPost, routes.Logout, live), http.StatusOK, "JWT logout")
	w.expect(w.doHeaders(http.MethodGet, routes.Session, live), http.StatusUnauthorized, "JWT credentials after logout")
	w.expect(w.doHeaders(http.MethodPost, routes.Refresh, http.Header{jwt.HeaderRefreshToken: {next}}), http.StatusUnauthorized, "refresh after logout")
}
