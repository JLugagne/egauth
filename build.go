package egauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sync/atomic"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session/jwt"
	"github.com/JLugagne/egauth/internal/session/stateful"
)

const (
	codeUnauthenticated = "unauthenticated"
	codeForbidden       = "forbidden"
	codeMustChange      = "password_change_required"
	codeCrossSite       = "cross_site_request"
	codeUnavailable     = "unavailable"
	codeNotFound        = "not_found"
	codeInternal        = "internal_error"
	reasonPublicRoutes  = "public_routes"
	reasonStripped      = "stripped_prefix"
)

type builtHandler struct {
	mux       *http.ServeMux
	patterns  []string
	anonymous func(*http.Request) *http.Request
	events    event.Sink
	layout    string
	poke      func()
	reported  atomic.Bool
}

func (h *builtHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = h.anonymous(r)
	if !servedAtRoot(r) {
		if h.reported.CompareAndSwap(false, true) {
			_ = audit.Emit(r.Context(), h.events, event.MountMismatch, audit.Scope{}, audit.Detail{Reason: reasonStripped}, nil,
				audit.A(event.KeyPurpose, h.layout), audit.A(event.KeyEndpoint, r.URL.Path))
		}
		refuse(w, http.StatusInternalServerError, codeInternal)
		return
	}
	if _, pattern := h.mux.Handler(r); pattern == "" {
		refuse(w, http.StatusNotFound, codeNotFound)
		return
	}
	if h.poke != nil {
		h.poke()
	}
	h.mux.ServeHTTP(w, r)
}

func servedAtRoot(r *http.Request) bool {
	if r.RequestURI == "" || r.RequestURI == "*" {
		return true
	}
	u, err := url.ParseRequestURI(r.RequestURI)
	return err == nil && u.Path == r.URL.Path
}

func refuse(w http.ResponseWriter, status int, code string) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"`+code+`"}`+"\n")
}

func noStore(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

func discardCredentials(w http.ResponseWriter) {
	cookie.Discard(w)
	h := w.Header()
	h.Del(jwt.HeaderAccessToken)
	h.Del(jwt.HeaderRefreshToken)
	h.Del(stateful.HeaderSessionToken)
}

type servedMux struct {
	mux      *http.ServeMux
	patterns []string
}

func (s *servedMux) handle(pattern string, h http.Handler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Join(routes.ErrConflict, errors.New(pattern+": "+fmt.Sprint(r)))
		}
	}()
	s.mux.Handle(pattern, h)
	s.patterns = append(s.patterns, pattern)
	return nil
}

func (a *Auth[C]) build(decls []routes.Declaration, handlers []declared[C]) (http.Handler, error) {
	o, base := a.owned, a.cfg.BasePath
	table, err := a.authTable()
	if err != nil {
		return nil, err
	}
	auth := http.NewServeMux()
	if err := table.Mount(auth, base, o.preamble); err != nil {
		return nil, err
	}
	root := &servedMux{mux: http.NewServeMux()}
	for _, p := range table.Patterns(base) {
		if err := root.handle(p, auth); err != nil {
			return nil, err
		}
	}
	discovery, err := a.discovery()
	if err != nil {
		return nil, err
	}
	if err := root.handle(http.MethodGet+" "+routes.WellKnown, discovery); err != nil {
		return nil, err
	}
	keys := newAPIKeyCache[C]()
	var public []string
	for i, d := range decls {
		if err := root.handle(d.Pattern, a.userHandler(d, handlers[i], keys)); err != nil {
			return nil, err
		}
		if d.Kind == routes.KindPublic {
			public = append(public, d.Pattern)
		}
	}
	if len(public) > 0 {
		slices.Sort(public)
		_ = audit.Emit(context.Background(), o.events, event.InsecureConfiguration, audit.Scope{}, audit.Detail{Reason: reasonPublicRoutes}, nil,
			audit.A(event.KeyPurpose, "Routes.Public"), audit.A(event.KeyEndpoint, public), audit.A(event.KeyCount, len(public)))
	}
	built := &builtHandler{
		mux: root.mux, patterns: root.patterns, events: o.events,
		anonymous: func(r *http.Request) *http.Request { return withPrincipal(r, Principal[C]{}) },
		layout:    "serve the Build handler at the server root; auth endpoints live under " + base + " and the discovery document at " + routes.WellKnown,
	}
	if o.reaper != nil {
		built.poke = o.reaper.Poke
	}
	return built, nil
}

func (a *Auth[C]) userHandler(d routes.Declaration, h declared[C], keys *apiKeyCache[C]) http.Handler {
	switch d.Kind {
	case routes.KindProtect, routes.KindOptional:
		return &sessionGate[C]{a: a, optional: d.Kind == routes.KindOptional, spec: d.Session, h: h.principal}
	case routes.KindProtectAPI:
		return &apiGate[C]{a: a, spec: d.API, h: h.principal, cache: keys}
	}
	return publicRoute[C]{h: h.public}
}

type publicRoute[C any] struct {
	h http.Handler
}

func (p publicRoute[C]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.h.ServeHTTP(w, withPrincipal(r, Principal[C]{}))
}

func (a *Auth[C]) authTable() (routes.Table, error) {
	eps := a.owned.table.Endpoints()
	extra, err := a.discoveryEndpoints()
	if err != nil {
		return routes.Table{}, err
	}
	return routes.NewTable(append(eps, extra...)...)
}
