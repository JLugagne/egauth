package egauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/memstore"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/tokens"
)

const (
	gateOrigin    = "http://localhost:8080"
	gateAudience  = "http://localhost:9090"
	gatePassword  = "correct horse battery staple"
	gateTenantHdr = "X-Test-Tenant"
)

type gateClaims struct {
	Plan string `json:"plan"`
}

type ownerClaims struct {
	mu    sync.Mutex
	by    map[principal.Subject]egauth.AppClaims[gateClaims]
	calls int
}

func (o *ownerClaims) ClaimsFor(_ context.Context, s principal.Subject) (egauth.AppClaims[gateClaims], error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls++
	if c, ok := o.by[s]; ok {
		return c, nil
	}
	return egauth.AppClaims[gateClaims]{Roles: []string{"user"}, Scopes: []string{"items:read", "items:write"}, Custom: gateClaims{Plan: "pro"}}, nil
}

func (o *ownerClaims) set(s principal.Subject, c egauth.AppClaims[gateClaims]) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.by == nil {
		o.by = map[principal.Subject]egauth.AppClaims[gateClaims]{}
	}
	o.by[s] = c
}

func (o *ownerClaims) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.calls
}

type headerTenant struct{}

func (headerTenant) ResolveTenant(r *http.Request) (principal.TenantID, error) {
	return principal.ParseTenantID(r.Header.Get(gateTenantHdr))
}

type gateWorld struct {
	t      *testing.T
	clk    *egauthtest.Clock
	st     egauth.Storage
	claims *ownerClaims
	sink   *wiringSink
	cfg    egauth.Config[gateClaims]
	a      *egauth.Auth[gateClaims]
	tenant string
}

func stateful(c *egauth.Config[gateClaims]) {
	c.Sessions = egauth.Stateful()
	c.Audiences = nil
}

func perRequestTenancy(c *egauth.Config[gateClaims]) {
	c.Tenancy = egauth.TenantFromRequest(headerTenant{})
}

func newGateWorld(t *testing.T, opts ...func(*egauth.Config[gateClaims])) *gateWorld {
	t.Helper()
	clk := egauthtest.NewClock(time.Time{})
	k := testKEK(t)
	w := &gateWorld{t: t, clk: clk, st: memstore.NewWithClock(k, clk.Library()), claims: &ownerClaims{}, sink: &wiringSink{}}
	w.cfg = egauth.Config[gateClaims]{
		PublicOrigin: gateOrigin,
		Audiences:    []string{gateAudience},
		Proxy:        egauth.DirectClients(),
		Storage:      w.st,
		KEK:          k,
		Sessions:     egauth.JWT(egauth.StaticKeys(edSigner(t, "gate-1"))),
		Transport:    egauth.CookiesAndBearer,
		Admin:        egauth.RoleAdmin("admin"),
		Claims:       w.claims,
		Events:       w.sink,
		Email:        &egauthtest.Mailbox{},
		Pages: egauth.Pages{
			Login: "/login", MFA: "/mfa", ConfirmRegistration: "/register/confirm", PasswordReset: "/reset", SecurityRevert: "/revert",
		},
		Modules: egauth.Modules{
			Password: &egauth.PasswordModule{},
			MFA:      &egauth.MFAModule{},
			APIKeys:  &egauth.APIKeyModule{Kinds: []string{"service", "pat"}},
		},
		Insecure: egauth.InsecureOptOuts{NoRateLimit: egauth.Acknowledge("gate tests")},
	}
	for _, o := range opts {
		o(&w.cfg)
	}
	a, err := egauthtest.New(w.cfg, clk, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })
	w.a = a
	return w
}

func (w *gateWorld) tenantID() principal.TenantID {
	if w.tenant == "" {
		return principal.TenantID{}
	}
	tn, err := principal.ParseTenantID(w.tenant)
	require.NoError(w.t, err)
	return tn
}

func (w *gateWorld) seedUser(email string, mustChange bool) principal.Subject {
	w.t.Helper()
	ctx := context.Background()
	phc, err := argon2.NewHasher().Hash(ctx, gatePassword)
	require.NoError(w.t, err)
	id, err := identity.NewIdentifier(identity.IdentifierEmail, email)
	require.NoError(w.t, err)
	applied, err := w.st.Identity.Apply(ctx, identity.CreateVerified{
		Tenant: w.tenantID(), Email: id, PHC: identity.NewPasswordHash(phc), MustChange: mustChange,
	})
	require.NoError(w.t, err)
	return applied.Subject
}

func (w *gateWorld) enrollTOTP(s principal.Subject) {
	w.t.Helper()
	ctx := context.Background()
	now := w.clk.Now()
	e := mfa.Enrollment{Subject: s, Sealed: []byte("sealed-secret"), AADVersion: mfa.AADVersionCurrent, CreatedAt: now}
	require.NoError(w.t, w.st.MFA.SaveTOTP(ctx, e))
	e.ConfirmedAt = &now
	require.NoError(w.t, w.st.MFA.ConfirmEnrollment(ctx, e, []string{"code-hash"}))
}

func (w *gateWorld) disable(s principal.Subject, disabled bool) {
	w.t.Helper()
	_, err := w.st.Identity.Apply(context.Background(), identity.SetDisabledState{Subject: s, Disable: disabled})
	require.NoError(w.t, err)
}

func (w *gateWorld) build(rt *egauth.Routes[gateClaims]) http.Handler {
	w.t.Helper()
	h, err := rt.Build()
	require.NoError(w.t, err)
	return h
}

type credentials struct {
	cookies []*http.Cookie
	bearer  string
	body    map[string]any
	code    int
}

func (c credentials) cookieHeader() string {
	var parts []string
	for _, k := range c.cookies {
		if k.MaxAge >= 0 && k.Value != "" {
			parts = append(parts, k.Name+"="+k.Value)
		}
	}
	return strings.Join(parts, "; ")
}

func (w *gateWorld) serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	if w.tenant != "" && req.Header.Get(gateTenantHdr) == "" {
		req.Header.Set(gateTenantHdr, w.tenant)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func (w *gateWorld) login(h http.Handler, email string, bearer bool) credentials {
	w.t.Helper()
	body, err := json.Marshal(map[string]string{"identifier": email, "password": gatePassword})
	require.NoError(w.t, err)
	req := httptest.NewRequest(http.MethodPost, gateOrigin+"/auth/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", gateOrigin)
	req.Header.Set("Accept", "application/json")
	if bearer {
		req.Header.Set(egauth.HeaderTransport, "bearer")
	}
	rec := w.serve(h, req)
	out := credentials{cookies: rec.Result().Cookies(), code: rec.Code}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	for _, name := range []string{"X-Egauth-Access-Token", "X-Egauth-Session-Token"} {
		if v := rec.Header().Get(name); v != "" {
			out.bearer = v
		}
	}
	return out
}

func (w *gateWorld) request(h http.Handler, method, path string, c credentials, mut ...func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, gateOrigin+path, nil)
	if v := c.cookieHeader(); v != "" {
		req.Header.Set("Cookie", v)
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if method != http.MethodGet && method != http.MethodHead {
		req.Header.Set("Origin", gateOrigin)
	}
	for _, m := range mut {
		m(req)
	}
	return w.serve(h, req)
}

func clearsSessionCookies(rec *httptest.ResponseRecorder) bool {
	n := 0
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 && (strings.HasSuffix(c.Name, "access_token") || strings.HasSuffix(c.Name, "refresh_token") || strings.HasSuffix(c.Name, "session")) {
			n++
		}
	}
	return n > 0
}

type apiKeyGrant struct {
	Roles  []string `json:"roles"`
	Scopes []string `json:"scopes"`
	Groups []string `json:"groups"`
}

func (w *gateWorld) createAPIKey(owner principal.Subject, kind string, grant apiKeyGrant, mut ...func(*tokens.APIKey)) string {
	w.t.Helper()
	secret := "egk_" + strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", "")
	sum := sha256.Sum256([]byte(secret))
	raw, err := json.Marshal(grant)
	require.NoError(w.t, err)
	epoch, err := w.st.Identity.CurrentEpoch(context.Background(), owner)
	require.NoError(w.t, err)
	k := tokens.APIKey{
		ID: uuid.New(), Owner: owner, Kind: kind, Name: "ci", KeyHash: sum[:], AppClaims: raw, CreatedEpoch: epoch,
		CreatedAt: w.clk.Now(),
	}
	for _, m := range mut {
		m(&k)
	}
	require.NoError(w.t, w.st.Tokens.CreateAPIKey(context.Background(), k))
	return secret
}

type seen struct {
	mu sync.Mutex
	p  []egauth.Principal[gateClaims]
}

func (s *seen) handler(w http.ResponseWriter, _ *http.Request, p egauth.Principal[gateClaims]) {
	s.mu.Lock()
	s.p = append(s.p, p)
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (s *seen) last(t *testing.T) egauth.Principal[gateClaims] {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.p)
	return s.p[len(s.p)-1]
}

func (s *seen) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.p)
}

func readCloser(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }
