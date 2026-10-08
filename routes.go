package egauth

import (
	"errors"
	"net/http"
	"slices"
	"strconv"

	"github.com/JLugagne/egauth/internal/principalctx"
	"github.com/JLugagne/egauth/internal/routes"
)

// Routes is the deny-by-default builder of the application's routes. Declare every route on it,
// then serve the handler returned by Build: it serves the auth endpoints under BasePath, the
// discovery document and exactly the declared routes; every other request is 404. A Routes is not
// safe for concurrent use; the handler Build returns is.
type Routes[C any] struct {
	auth     *Auth[C]
	decls    routes.UserRoutes
	handlers []declared[C]
	problems []string
}

type declared[C any] struct {
	kind      routes.Kind
	principal PrincipalHandler[C]
	public    http.Handler
}

// Routes returns a new, empty builder for the application's own routes.
func (a *Auth[C]) Routes() *Routes[C] {
	return &Routes[C]{auth: a}
}

// Protect serves h only to an established human session that passes every session gate and every
// requirement in opts. Patterns are ServeMux patterns with a method and no host, for example
// "GET /account/{id}".
func (rt *Routes[C]) Protect(pattern string, h PrincipalHandler[C], opts ...RouteOption) *Routes[C] {
	return rt.session(routes.KindProtect, pattern, h, opts)
}

// Optional serves h to everyone; a principal that fails any Protect gate or requirement is
// presented as Anonymous, never as a weaker authenticated principal.
func (rt *Routes[C]) Optional(pattern string, h PrincipalHandler[C], opts ...RouteOption) *Routes[C] {
	return rt.session(routes.KindOptional, pattern, h, opts)
}

// ProtectAPI serves h only to an API key of one of kinds that meets every requirement in opts;
// session credentials are refused. Build rejects it when Modules.APIKeys is nil or a kind is not
// in APIKeyModule.Kinds.
func (rt *Routes[C]) ProtectAPI(pattern string, h PrincipalHandler[C], kinds APIKinds, opts ...APIRouteOption) *Routes[C] {
	d := routes.Declaration{Pattern: pattern, Kind: routes.KindProtectAPI}
	if len(kinds.kinds) > 0 {
		d.API.SetKinds(kinds.kinds[0], kinds.kinds[1:]...)
	}
	for i, k := range kinds.kinds {
		if j := slices.Index(kinds.kinds, k); j < i {
			rt.fail(pattern, "kind "+strconv.Itoa(i)+" duplicates kind "+strconv.Itoa(j))
		}
	}
	for i, o := range opts {
		if o == nil {
			rt.fail(pattern, "option "+strconv.Itoa(i)+" is nil")
			continue
		}
		o.applyAPI(&d.API)
	}
	if h == nil {
		rt.fail(pattern, "nil handler")
	}
	rt.decls.Add(d)
	rt.handlers = append(rt.handlers, declared[C]{kind: d.Kind, principal: h})
	return rt
}

// Public serves h without authentication; every public pattern is listed in one startup event.
func (rt *Routes[C]) Public(pattern string, h http.Handler) *Routes[C] {
	if h == nil {
		rt.fail(pattern, "nil handler")
	}
	rt.decls.Add(routes.Declaration{Pattern: pattern, Kind: routes.KindPublic})
	rt.handlers = append(rt.handlers, declared[C]{kind: routes.KindPublic, public: h})
	return rt
}

func (rt *Routes[C]) session(kind routes.Kind, pattern string, h PrincipalHandler[C], opts []RouteOption) *Routes[C] {
	d := routes.Declaration{Pattern: pattern, Kind: kind}
	for i, o := range opts {
		if o == nil {
			rt.fail(pattern, "option "+strconv.Itoa(i)+" is nil")
			continue
		}
		o.applySession(&d.Session)
	}
	if h == nil {
		rt.fail(pattern, "nil handler")
	}
	rt.decls.Add(d)
	rt.handlers = append(rt.handlers, declared[C]{kind: kind, principal: h})
	return rt
}

func (rt *Routes[C]) fail(pattern, problem string) {
	rt.problems = append(rt.problems, pattern+": "+problem)
}

// Build validates every declaration and returns all problems joined: a pattern with no method or
// with a host; a pattern overlapping BasePath, the discovery document or another declaration; an
// invalid requirement (zero Factor or Freshness, blank role, scope or group); a nil handler or
// option; ProtectAPI with Modules.APIKeys nil or with an undeclared or repeated kind.
func (rt *Routes[C]) Build() (http.Handler, error) {
	if rt.auth == nil {
		return nil, errors.Join(routes.ErrInvalidDeclaration, errors.New("Routes must come from Auth.Routes"))
	}
	var errs []error
	for _, p := range rt.problems {
		errs = append(errs, errors.Join(routes.ErrInvalidDeclaration, errors.New(p)))
	}
	errs = append(errs, rt.decls.Validate(rt.auth.deployment()))
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	for i, d := range rt.decls.Declarations() {
		mux.Handle(d.Pattern, rt.serve(rt.handlers[i]))
	}
	return mux, nil
}

func (rt *Routes[C]) serve(d declared[C]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		anonymous := Principal[C]{}
		r = r.WithContext(principalctx.Set(r.Context(), anonymous))
		switch d.kind {
		case routes.KindPublic:
			d.public.ServeHTTP(w, r)
		case routes.KindOptional:
			d.principal(w, r, anonymous)
		default:
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
}
