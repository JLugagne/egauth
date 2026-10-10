package journeytest_test

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/journeytest"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/principal"
)

type kind uint8

const (
	kAuth kind = iota + 1
	kProtect
	kOptional
	kAPI
	kPublic
)

type target struct {
	kind     kind
	method   string
	path     string
	registry string
	meta     routes.EndpointMeta
}

func (t target) label() string { return t.method + " " + t.path }

func (t target) unsafeMethod() bool {
	return t.method != http.MethodGet && t.method != http.MethodHead && t.method != http.MethodOptions
}

type observed struct {
	ran  bool
	anon bool
}

type env struct {
	w       *journeytest.World
	targets []target
}

func newEnv(w *journeytest.World) *env {
	e := &env{w: w}
	c := w.NewClient()
	for _, ep := range journeytest.Endpoints("/auth") {
		if journeytest.Served(c, ep) {
			e.targets = append(e.targets, target{kind: kAuth, method: ep.Method, path: ep.Path, registry: ep.Registry, meta: ep.Meta})
		}
	}
	kinds := map[journeytest.RouteKind]kind{
		journeytest.RouteProtect: kProtect, journeytest.RouteOptional: kOptional,
		journeytest.RoutePublic: kPublic, journeytest.RouteAPI: kAPI,
	}
	for _, d := range w.DeclaredRoutes() {
		e.targets = append(e.targets, target{kind: kinds[d.Kind], method: d.Method, path: d.Path})
	}
	return e
}

func (e *env) where(pred func(target) bool) []target {
	var out []target
	for _, t := range e.targets {
		if pred(t) {
			out = append(out, t)
		}
	}
	return out
}

func (e *env) hit(c *journeytest.Client, t target, mut ...func(*journeytest.Req)) (*journeytest.Resp, observed) {
	before := e.w.Seen.Count()
	r := journeytest.Req{Method: t.method, Path: t.path, Remote: c.FreshRemote()}
	for _, m := range mut {
		m(&r)
	}
	resp := c.Do(r)
	o := observed{ran: e.w.Seen.Count() > before}
	if p, ok := e.w.Seen.Last(); ok && o.ran {
		o.anon = p.Kind() == egauth.Anonymous
	}
	return resp, o
}

func lazy[T any](f func() T) func() T {
	var once sync.Once
	var v T
	return func() T {
		once.Do(func() { v = f() })
		return v
	}
}

func got(r *journeytest.Resp, o observed) string {
	return fmt.Sprintf("%s ran=%t anon=%t", journeytest.Describe(r), o.ran, o.anon)
}

func denied401(t target, r *journeytest.Resp, o observed) (string, bool) {
	if t.kind == kOptional {
		return got(r, o), r.Status == http.StatusUnauthorized || (r.Status == http.StatusOK && o.ran && o.anon)
	}
	return got(r, o), r.Status == http.StatusUnauthorized && !o.ran
}

func anonymousOnly(t target, r *journeytest.Resp, o observed) (string, bool) {
	return got(r, o), r.Status == http.StatusOK && o.ran && o.anon
}

func refused(status int, code string) func(target, *journeytest.Resp, observed) (string, bool) {
	return func(_ target, r *journeytest.Resp, o observed) (string, bool) {
		return got(r, o), r.Status == status && (code == "" || r.Code() == code) && !o.ran
	}
}

func served(_ target, r *journeytest.Resp, o observed) (string, bool) {
	return got(r, o), r.Status == http.StatusOK && o.ran
}

func (e *env) bearerAllowed() bool {
	return e.w.Config.Transport != egauth.Cookies
}

func (e *env) cookiesAllowed() bool {
	return e.w.Config.Transport != egauth.Bearer
}

func (e *env) transports() []bool {
	var out []bool
	if e.cookiesAllowed() {
		out = append(out, false)
	}
	if e.bearerAllowed() {
		out = append(out, true)
	}
	return out
}

func transportName(bearer bool) string {
	if bearer {
		return "bearer"
	}
	return "cookie"
}

func (e *env) user(prefix string, mustChange bool) (string, principal.Subject) {
	email := e.w.FreshEmail(prefix)
	return email, e.w.SeedUser(email, mustChange)
}

func (e *env) loggedIn(prefix string, bearer bool) (*journeytest.Client, principal.Subject) {
	email, sub := e.user(prefix, false)
	c := e.w.NewClient()
	c.Login(email, bearer)
	return c, sub
}

type state struct {
	name   string
	bearer bool
	make   func() *journeytest.Client
	filter func(target) bool
	expect func(target, *journeytest.Resp, observed) (string, bool)
	want   string
	mut    func(target) []func(*journeytest.Req)
}

func (e *env) stateProbes(category string, st state) []journeytest.Probe {
	shared := lazy(st.make)
	var ps []journeytest.Probe
	for _, t := range e.where(st.filter) {
		ps = append(ps, journeytest.Probe{
			Category: category,
			Name:     category + "/" + st.name + "/" + transportName(st.bearer) + "/" + t.label(),
			Want:     st.want,
			Run: func() (string, bool) {
				c := shared()
				if t.meta.EndsSession {
					c = st.make()
				}
				var muts []func(*journeytest.Req)
				if st.mut != nil {
					muts = st.mut(t)
				}
				r, o := e.hit(c, t, muts...)
				return st.expect(t, r, o)
			},
		})
	}
	return ps
}

func isSession(t target) bool {
	return t.kind == kProtect || t.kind == kOptional || (t.kind == kAuth && t.meta.Authenticated)
}

func isCredentialed(t target) bool { return isSession(t) || t.kind == kAPI }

func advance(w *journeytest.World, d time.Duration) { w.Clock.Advance(d) }
