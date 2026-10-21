package backendtest

import (
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/identity"
)

const (
	statusOK          = http.StatusOK
	statusUnauth      = http.StatusUnauthorized
	statusUnavailable = http.StatusServiceUnavailable
	userAgent         = "backendtest/1"
	tenantName        = "acme"
	placeholderHash   = "backendtest-placeholder-not-a-hash"
)

type env struct {
	t  *testing.T
	b  session.Backend
	fx *Fixture
}

func newEnv(t *testing.T, b session.Backend, fx *Fixture) *env {
	return &env{t: t, b: b, fx: fx}
}

func (e *env) now() time.Time { return e.fx.Clock.Now() }

func (e *env) advance(d time.Duration) { e.fx.Clock.Advance(d) }

func (e *env) apply(m identity.Mutation) identity.Applied {
	e.t.Helper()
	out, err := e.fx.Identity.Apply(e.t.Context(), m)
	if err != nil {
		e.t.Fatalf("identity mutation %T: %v", m, err)
	}
	return out
}

func (e *env) newUser() principal.Subject {
	e.t.Helper()
	tenant, err := principal.ParseTenantID(tenantName)
	if err != nil {
		e.t.Fatal(err)
	}
	email, err := identity.NewIdentifier(identity.IdentifierEmail, "u-"+uuid.NewString()+"@example.test")
	if err != nil {
		e.t.Fatal(err)
	}
	return e.apply(identity.CreateVerified{Tenant: tenant, Email: email, PHC: identity.NewPasswordHash(placeholderHash)}).Subject
}

func (e *env) epoch(s principal.Subject) uint64 {
	e.t.Helper()
	n, err := e.fx.Identity.CurrentEpoch(e.t.Context(), s)
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) fullSpec(s principal.Subject, tr core.Transport) principaltest.Spec {
	now := e.now()
	return principaltest.Spec{
		Lineage: uuid.New(),
		Subject: s,
		Factors: []core.Factor{
			core.FactorPasskey, core.FactorUserVerification, core.FactorPassword, core.FactorTOTP,
			core.FactorPasskeyStepUp, core.FactorFederated,
		},
		PasskeyUses: []principaltest.Credential{
			{Factor: core.FactorPasskey, ID: []byte{1, 2, 3, 4}},
			{Factor: core.FactorPasskeyStepUp, ID: []byte{9, 8, 7}},
		},
		PrimaryAt:       now.Add(-10 * time.Minute),
		SecondAt:        now.Add(-9 * time.Minute),
		Epoch:           e.epoch(s),
		RememberMe:      true,
		ReturnTo:        "/settings/security?tab=mfa",
		Transport:       tr,
		Provider:        "google",
		CreatedAt:       now,
		ClaimsFetchedAt: now,
	}
}

func (e *env) passwordSpec(s principal.Subject, tr core.Transport) principaltest.Spec {
	now := e.now()
	return principaltest.Spec{
		Lineage:         uuid.New(),
		Subject:         s,
		Factors:         []core.Factor{core.FactorPassword},
		PrimaryAt:       now,
		Epoch:           e.epoch(s),
		RememberMe:      true,
		Transport:       tr,
		CreatedAt:       now,
		ClaimsFetchedAt: now,
	}
}

type jarCookie struct {
	c       *http.Cookie
	expires time.Time
}

type client struct {
	e       *env
	ua      string
	cookies map[string]jarCookie
	header  http.Header
}

func (e *env) client() *client {
	return &client{e: e, ua: userAgent, cookies: map[string]jarCookie{}, header: http.Header{}}
}

func (e *env) start(a core.SessionAttrs) *client {
	e.t.Helper()
	c, err := e.tryStart(a, e.fx.Claims.Value())
	if err != nil {
		e.t.Fatalf("Start: %v", err)
	}
	return c
}

func (e *env) tryStart(a core.SessionAttrs, claims core.SealedClaims) (*client, error) {
	c := e.client()
	rec := httptest.NewRecorder()
	if err := e.fx.Start(e.t.Context(), rec, a, claims); err != nil {
		e.mustNotWrite(rec, "a failed Start")
		return nil, err
	}
	c.absorb(rec)
	return c, nil
}

func (e *env) mustNotWrite(rec *httptest.ResponseRecorder, what string) {
	e.t.Helper()
	if len(rec.Header().Values("Set-Cookie")) > 0 {
		e.t.Errorf("%s wrote cookies: %v", what, rec.Header().Values("Set-Cookie"))
	}
	next := http.Header{}
	e.fx.Carry(rec.Header(), next)
	if len(next) > 0 {
		e.t.Errorf("%s wrote Bearer credentials", what)
	}
}

func (c *client) clone() *client {
	n := &client{e: c.e, ua: c.ua, cookies: map[string]jarCookie{}, header: c.header.Clone()}
	maps.Copy(n.cookies, c.cookies)
	return n
}

func (c *client) absorb(rec *httptest.ResponseRecorder) {
	now := c.e.now()
	for _, ck := range (&http.Response{Header: rec.Header()}).Cookies() {
		switch {
		case ck.MaxAge < 0:
			delete(c.cookies, ck.Name)
		case ck.MaxAge > 0:
			c.cookies[ck.Name] = jarCookie{c: ck, expires: now.Add(time.Duration(ck.MaxAge) * time.Second)}
		default:
			c.cookies[ck.Name] = jarCookie{c: ck}
		}
	}
	c.e.fx.Carry(rec.Header(), c.header)
}

func (c *client) live() []*http.Cookie {
	now := c.e.now()
	var out []*http.Cookie
	for name, jc := range c.cookies {
		if !jc.expires.IsZero() && !now.Before(jc.expires) {
			delete(c.cookies, name)
			continue
		}
		out = append(out, &http.Cookie{Name: jc.c.Name, Value: jc.c.Value})
	}
	return out
}

func (c *client) sameCredentials(o *client) bool {
	return reflect.DeepEqual(c.credentials().byName(), o.credentials().byName()) && reflect.DeepEqual(c.header, o.header)
}

func (cr Credentials) byName() map[string]string {
	out := map[string]string{}
	for _, ck := range cr.Cookies {
		out[ck.Name] = ck.Value
	}
	return out
}

func (c *client) credentials() Credentials {
	return Credentials{Cookies: c.live(), Header: c.header.Clone()}
}

func (e *env) withCredentials(cr Credentials) *client {
	c := e.client()
	for _, ck := range cr.Cookies {
		c.cookies[ck.Name] = jarCookie{c: ck}
	}
	if cr.Header != nil {
		c.header = cr.Header.Clone()
	}
	return c
}

func (c *client) request() *http.Request {
	r := httptest.NewRequestWithContext(c.e.t.Context(), http.MethodGet, "https://"+tenantName+".example.test/app", nil)
	for _, ck := range c.live() {
		r.AddCookie(ck)
	}
	for k, vs := range c.header {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	r.Header.Set("User-Agent", c.ua)
	return r
}

func (c *client) resume() (session.Resumed, error) {
	c.e.t.Helper()
	rec := httptest.NewRecorder()
	tenant, err := principal.ParseTenantID(tenantName)
	if err != nil {
		c.e.t.Fatal(err)
	}
	res, err := c.e.b.Resume(c.e.t.Context(), rec, c.request(), tenant)
	if err != nil {
		c.e.mustNotWrite(rec, "a refused Resume")
		return session.Resumed{}, err
	}
	c.absorb(rec)
	return res, nil
}

func (c *client) end() error {
	rec := httptest.NewRecorder()
	tenant, err := principal.ParseTenantID(tenantName)
	if err != nil {
		c.e.t.Fatal(err)
	}
	err = c.e.b.End(c.e.t.Context(), rec, c.request(), tenant)
	c.absorb(rec)
	return err
}

func status(err error) int {
	switch {
	case err == nil:
		return statusOK
	case errors.Is(err, httpx.ErrUnavailable):
		return statusUnavailable
	}
	return statusUnauth
}

func (c *client) expect(want int, what string) session.Resumed {
	c.e.t.Helper()
	res, err := c.resume()
	if got := status(err); got != want {
		c.e.t.Fatalf("%s: Resume answered %d, want %d (err: %v)", what, got, want, err)
	}
	return res
}

func (e *env) reissue(cur session.Handle, a core.SessionAttrs) (*client, error) {
	c := e.client()
	rec := httptest.NewRecorder()
	if err := e.fx.Reissue(e.t.Context(), rec, cur, a); err != nil {
		e.mustNotWrite(rec, "a failed Reissue")
		return nil, err
	}
	c.absorb(rec)
	return c, nil
}

func (e *env) sameAttrs(got, want core.SessionAttrs, what string) {
	e.t.Helper()
	if !reflect.DeepEqual(got, want) {
		e.t.Fatalf("%s: attributes changed\n got: %#v\nwant: %#v", what, got, want)
	}
}
