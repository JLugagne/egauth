package egauth

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/internal/routes"
)

const unservedBasePath = "/egauth-unserved"

// APIRoutes is the deny-by-default builder of a resource server's routes: serve the handler Build
// returns at the server root and every request outside the declared routes is 404. An APIRoutes is
// not safe for concurrent use; the handler Build returns is.
type APIRoutes[C any] struct {
	rs       *ResourceServer[C]
	decls    routes.UserRoutes
	handlers []PrincipalHandler[C]
	problems []string
}

// Routes returns a new, empty builder for the resource server's routes.
func (rs *ResourceServer[C]) Routes() *APIRoutes[C] {
	return &APIRoutes[C]{rs: rs}
}

// Protect serves h only to a Bearer resource token minted for the server's Audience whose session
// is still live and passes every requirement in opts, as Routes.Protect does for sessions. Session
// access tokens, cookies and API keys are refused. Patterns are ServeMux patterns with a method and
// no host.
func (rt *APIRoutes[C]) Protect(pattern string, h PrincipalHandler[C], opts ...RouteOption) *APIRoutes[C] {
	d := routes.Declaration{Pattern: pattern, Kind: routes.KindProtect}
	for i, o := range opts {
		if !present(o) || !applied(func() { o.applySession(&d.Session) }) {
			rt.problems = append(rt.problems, pattern+": option "+strconv.Itoa(i)+" is nil")
		}
	}
	if h == nil {
		rt.problems = append(rt.problems, pattern+": nil handler")
	}
	rt.decls.Add(d)
	rt.handlers = append(rt.handlers, h)
	return rt
}

// Build validates every declaration and returns all problems joined: a pattern with no method or
// with a host, a pattern overlapping another declaration, an invalid requirement, a nil handler or
// option. It returns ErrClosed after ResourceServer.Close.
func (rt *APIRoutes[C]) Build() (http.Handler, error) {
	if rt.rs == nil || rt.rs.codec == nil {
		return nil, errors.Join(routes.ErrInvalidDeclaration, errors.New("APIRoutes must come from ResourceServer.Routes"))
	}
	if rt.rs.closed.Load() {
		return nil, ErrClosed
	}
	var errs []error
	for _, p := range rt.problems {
		errs = append(errs, errors.Join(routes.ErrInvalidDeclaration, errors.New(p)))
	}
	errs = append(errs, rt.decls.Validate(routes.Deployment{BasePath: unservedBasePath}))
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	root := &servedMux{mux: http.NewServeMux()}
	for i, d := range rt.decls.Declarations() {
		if err := root.handle(d.Pattern, &resourceGate[C]{rs: rt.rs, spec: d.Session, h: rt.handlers[i]}); err != nil {
			return nil, err
		}
	}
	return &builtHandler{
		mux: root.mux, patterns: root.patterns, events: rt.rs.events,
		anonymous: func(r *http.Request) *http.Request { return withPrincipal(r, Principal[C]{}) },
		layout:    "serve the Build handler at the server root",
	}, nil
}

type resourceGate[C any] struct {
	rs   *ResourceServer[C]
	spec routes.SessionSpec
	h    PrincipalHandler[C]
}

func (g *resourceGate[C]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	p, ref := g.authenticate(r)
	if ref.status != 0 {
		refuse(w, ref.status, ref.code)
		return
	}
	g.h(w, withPrincipal(r, p), p)
}

func (g *resourceGate[C]) authenticate(r *http.Request) (Principal[C], refusal) {
	rs := g.rs
	raw, ok := bearerCredential(r)
	if !ok {
		return Principal[C]{}, refuseNoCredential
	}
	tok, err := rs.codec.VerifyResource(r.Context(), raw, rs.keys, rs.cfg.Audience)
	if err != nil {
		return Principal[C]{}, resourceRefusal(err)
	}
	a := tok.Attrs()
	if a.IsZero() || a.Subject().IsZero() || a.Subject().Tenant.String() != rs.cfg.Tenant {
		return Principal[C]{}, refuseMismatch
	}
	if rs.families != nil {
		if err := rs.families.Live(r.Context(), a.Subject(), revoke.Family{ID: tok.Family(), Lineage: a.Lineage()}); err != nil {
			return Principal[C]{}, resourceRefusal(err)
		}
		if err := rs.epochs.Check(r.Context(), a.Subject(), a.Epoch()); err != nil {
			return Principal[C]{}, resourceRefusal(err)
		}
	}
	claims, err := decodeClaims[C](tok.Claims().Bytes())
	if err != nil {
		return Principal[C]{}, refuseMismatch
	}
	switch err := g.spec.Check(a, routes.Claims{Roles: claims.Roles, Scopes: claims.Scopes, Groups: claims.Groups}, rs.clock.Now()); {
	case errors.Is(err, routes.ErrMustChange):
		return Principal[C]{}, refuseMustChange
	case err != nil:
		return Principal[C]{}, refuseRequirement
	}
	p, err := resourcePrincipal(a, claims)
	if err != nil {
		return Principal[C]{}, refuseMismatch
	}
	return p, refusal{}
}

func resourceRefusal(err error) refusal {
	if errors.Is(err, httpx.ErrUnavailable) || errors.Is(err, revoke.ErrUnavailable) {
		return refuseUnavailable
	}
	return refuseMismatch
}
