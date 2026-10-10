package egauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/memstore"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/identity"
)

const (
	rsAudience      = "http://localhost:9091"
	rsOtherAudience = "http://localhost:9092"
	rsPassword      = "correct horse battery staple"
)

type swapHandler struct {
	mu sync.Mutex
	h  http.Handler
}

func (s *swapHandler) set(h http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.h = h
}

func (s *swapHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	h := s.h
	s.mu.Unlock()
	if h == nil {
		http.NotFound(w, r)
		return
	}
	h.ServeHTTP(w, r)
}

type rsWorld struct {
	t      *testing.T
	clk    *egauthtest.Clock
	st     egauth.Storage
	srv    *httptest.Server
	origin string
	a      *egauth.Auth[gateClaims]
	h      http.Handler
	claims *ownerClaims
	sink   *wiringSink
}

func newRSWorld(t *testing.T, opts ...func(*egauth.Config[gateClaims])) *rsWorld {
	t.Helper()
	clk := egauthtest.NewClock(time.Time{})
	k := testKEK(t)
	swap := &swapHandler{}
	srv := httptest.NewServer(swap)
	t.Cleanup(srv.Close)
	w := &rsWorld{t: t, clk: clk, srv: srv, origin: srv.URL, st: memstore.NewWithClock(k, clk.Library()), claims: &ownerClaims{}, sink: &wiringSink{}}
	cfg := egauth.Config[gateClaims]{
		PublicOrigin: srv.URL,
		Audiences:    []string{rsAudience, rsOtherAudience},
		Proxy:        egauth.DirectClients(),
		Storage:      w.st,
		KEK:          k,
		Sessions:     egauth.JWT(egauth.StaticKeys(edSigner(t, "rs-1"))),
		Transport:    egauth.CookiesAndBearer,
		Admin:        egauth.RoleAdmin("admin"),
		Claims:       w.claims,
		Events:       event.Discard,
		Email:        &egauthtest.Mailbox{},
		Pages: egauth.Pages{
			Login: "/login", MFA: "/mfa", ConfirmRegistration: "/register/confirm", PasswordReset: "/reset", SecurityRevert: "/revert",
		},
		Modules:  egauth.Modules{Password: &egauth.PasswordModule{}, MFA: &egauth.MFAModule{}},
		Insecure: egauth.InsecureOptOuts{NoRateLimit: egauth.Acknowledge("resource server tests")},
	}
	for _, o := range opts {
		o(&cfg)
	}
	a, err := egauthtest.New(cfg, clk, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })
	w.a = a
	w.h, err = a.Routes().Protect("GET /account", (&seen{}).handler).Build()
	require.NoError(t, err)
	swap.set(w.h)
	return w
}

func (w *rsWorld) seedUser(email string, mustChange bool) principal.Subject {
	w.t.Helper()
	ctx := context.Background()
	phc, err := argon2.NewHasher().Hash(ctx, rsPassword)
	require.NoError(w.t, err)
	id, err := identity.NewIdentifier(identity.IdentifierEmail, email)
	require.NoError(w.t, err)
	applied, err := w.st.Identity.Apply(ctx, identity.CreateVerified{Email: id, PHC: identity.NewPasswordHash(phc), MustChange: mustChange})
	require.NoError(w.t, err)
	return applied.Subject
}

func (w *rsWorld) disable(s principal.Subject) {
	w.t.Helper()
	_, err := w.st.Identity.Apply(context.Background(), identity.SetDisabledState{Subject: s, Disable: true})
	require.NoError(w.t, err)
}

func (w *rsWorld) serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func (w *rsWorld) login(email string, bearer bool) credentials {
	w.t.Helper()
	body, err := json.Marshal(map[string]string{"identifier": email, "password": rsPassword})
	require.NoError(w.t, err)
	req := httptest.NewRequest(http.MethodPost, w.origin+"/auth/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", w.origin)
	req.Header.Set("Accept", "application/json")
	if bearer {
		req.Header.Set(egauth.HeaderTransport, "bearer")
	}
	rec := w.serve(w.h, req)
	out := credentials{cookies: rec.Result().Cookies(), code: rec.Code}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	for _, name := range []string{"X-Egauth-Access-Token", "X-Egauth-Session-Token"} {
		if v := rec.Header().Get(name); v != "" {
			out.bearer = v
		}
	}
	return out
}

func (w *rsWorld) resourceToken(c credentials, audience string) (int, string) {
	w.t.Helper()
	form := url.Values{egauth.FieldResource: {audience}}.Encode()
	req := httptest.NewRequest(http.MethodPost, w.origin+"/auth"+egauth.PathResourceToken, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", w.origin)
	if v := c.cookieHeader(); v != "" {
		req.Header.Set("Cookie", v)
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	rec := w.serve(w.h, req)
	var body struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body.Token
}

func (w *rsWorld) mint(email string, audience string) string {
	w.t.Helper()
	c := w.login(email, false)
	require.Equal(w.t, http.StatusOK, c.code, c.body)
	code, tok := w.resourceToken(c, audience)
	require.Equal(w.t, http.StatusOK, code)
	require.NotEmpty(w.t, tok)
	return tok
}

func (w *rsWorld) config() egauth.ResourceConfig {
	return egauth.ResourceConfig{
		AuthOrigin: w.origin,
		Audience:   rsAudience,
		Proxy:      egauth.DirectClients(),
		Revocation: egauth.FromStorage(w.st),
		Events:     w.sink,
	}
}

func (w *rsWorld) server(mut ...func(*egauth.ResourceConfig)) *egauth.ResourceServer[gateClaims] {
	w.t.Helper()
	cfg := w.config()
	for _, m := range mut {
		m(&cfg)
	}
	rs, err := egauth.NewLoopbackResourceServer[gateClaims](cfg, w.clk.Library())
	require.NoError(w.t, err)
	w.t.Cleanup(func() { _ = rs.Close() })
	return rs
}

func (w *rsWorld) call(h http.Handler, method, path, bearer string, mut ...func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://rs.example"+path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for _, m := range mut {
		m(req)
	}
	return w.serve(h, req)
}
