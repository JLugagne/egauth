package egauth_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/routes"
)

func TestBuildAnswersAStrippedPrefixWith500AndOneMountMismatch(t *testing.T) {
	w := newGateWorld(t)
	h := w.build(w.a.Routes().Public("GET /health", http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	})))
	require.Equal(t, http.StatusNoContent, w.request(h, http.MethodGet, "/health", credentials{}).Code)

	mounted := http.StripPrefix("/app", h)
	for range 3 {
		rec := w.request(mounted, http.MethodGet, "/app/health", credentials{})
		require.Equal(t, http.StatusInternalServerError, rec.Code)
		rec = w.request(mounted, http.MethodGet, "/app/auth/session", credentials{})
		require.Equal(t, http.StatusInternalServerError, rec.Code)
	}
	events := w.sink.of(event.MountMismatch)
	require.Len(t, events, 1)
	require.Equal(t, event.SeverityError, events[0].Type.Severity())
}

func TestBuildServesNothingUndeclared(t *testing.T) {
	w := newGateWorld(t)
	s := &seen{}
	h := w.build(w.a.Routes().Protect("GET /account", s.handler).Optional("GET /{$}", s.handler))
	for _, probe := range []struct{ method, path string }{
		{http.MethodGet, "/undeclared"},
		{http.MethodPost, "/account"},
		{http.MethodDelete, "/account"},
		{http.MethodGet, "/auth/login"},
		{http.MethodGet, "/auth/unknown"},
		{http.MethodPost, "/auth/magic-link"},
		{http.MethodGet, "/.well-known/other"},
		{http.MethodOptions, "/auth/login"},
		{http.MethodGet, "/x/"},
	} {
		rec := w.request(h, probe.method, probe.path, credentials{})
		require.Equal(t, http.StatusNotFound, rec.Code, probe.method+" "+probe.path)
		require.Empty(t, rec.Header().Get("Allow"))
	}
	require.Equal(t, 0, s.count())
}

func TestBuildListsEveryPublicRouteInOneStartupEvent(t *testing.T) {
	w := newGateWorld(t)
	ok := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })
	w.build(w.a.Routes().Public("GET /health", ok).Public("GET /docs/{page}", ok).Protect("GET /account", (&seen{}).handler))
	var listed []event.Event
	for _, e := range w.sink.of(event.InsecureConfiguration) {
		if e.Reason == "public_routes" {
			listed = append(listed, e)
		}
	}
	require.Len(t, listed, 1)
	require.Equal(t, []string{"GET /docs/{page}", "GET /health"}, listed[0].Attrs[string(event.KeyEndpoint)])
	require.Equal(t, 2, listed[0].Attrs[string(event.KeyCount)])

	w.build(w.a.Routes().Protect("GET /account", (&seen{}).handler))
	n := 0
	for _, e := range w.sink.of(event.InsecureConfiguration) {
		if e.Reason == "public_routes" {
			n++
		}
	}
	require.Equal(t, 1, n, "a build without public routes lists nothing")
}

type embeddedNilRequirement struct {
	*egauth.SessionRequirement
}

type embeddedNilClaim struct {
	*egauth.ClaimRequirement
}

func TestBuildReportsAnEmbeddedNilRequirementInsteadOfPanicking(t *testing.T) {
	w := newGateWorld(t)
	noop := func(http.ResponseWriter, *http.Request, egauth.Principal[gateClaims]) {}
	for name, rt := range map[string]func() *egauth.Routes[gateClaims]{
		"protect": func() *egauth.Routes[gateClaims] {
			return w.a.Routes().Protect("GET /x", noop, embeddedNilRequirement{})
		},
		"optional": func() *egauth.Routes[gateClaims] { return w.a.Routes().Optional("GET /x", noop, embeddedNilClaim{}) },
		"api": func() *egauth.Routes[gateClaims] {
			return w.a.Routes().ProtectAPI("GET /x", noop, egauth.Kinds("service"), embeddedNilClaim{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			var h http.Handler
			var err error
			require.NotPanics(t, func() { h, err = rt().Build() })
			require.ErrorIs(t, err, routes.ErrInvalidDeclaration)
			require.Nil(t, h)
		})
	}
}

func TestBuildIsSafeForConcurrentRequests(t *testing.T) {
	w := newGateWorld(t)
	sub := w.seedUser("pat@example.com", false)
	s := &seen{}
	h := w.build(w.a.Routes().
		Protect("GET /account", s.handler).
		ProtectAPI("GET /api/items", s.handler, egauth.Kinds("service")))
	c := w.login(h, "pat@example.com", true)
	key := w.createAPIKey(sub, "service", apiKeyGrant{})
	done := make(chan int, 64)
	for i := range 64 {
		go func() {
			cred, path := c, "/account"
			if i%2 == 0 {
				cred, path = credentials{bearer: key}, "/api/items"
			}
			req := httptest.NewRequest(http.MethodGet, gateOrigin+path, nil)
			req.Header.Set("Authorization", "Bearer "+cred.bearer)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			done <- rec.Code
		}()
	}
	for range 64 {
		require.Equal(t, http.StatusOK, <-done)
	}
}

func servedSet(h http.Handler) []string {
	out := slices.Clone(egauth.ServedPatterns(h))
	slices.Sort(out)
	return out
}

func probedSet(h http.Handler, declared ...string) []string {
	paths := []string{"/", "/auth", "/auth/", "/auth/zz", "/.well-known/", "/.well-known/zz", routes.WellKnown, "/zz", "/debug", "/metrics"}
	for _, p := range routes.All() {
		target := "/auth" + strings.ReplaceAll(strings.ReplaceAll(p, "{provider}", "corp"), "{name}", "ldap")
		paths = append(paths, target, target+"/", target+"/zz", strings.TrimPrefix(target, "/auth"))
	}
	for _, d := range declared {
		_, path, _ := strings.Cut(d, " ")
		paths = append(paths, path, path+"/", path+"/zz")
	}
	methods := []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions}
	var out []string
	for _, path := range paths {
		for _, m := range methods {
			if got := egauth.MatchedPattern(h, httptest.NewRequest(m, path, nil)); got != "" && !slices.Contains(out, got) {
				out = append(out, got)
			}
		}
	}
	slices.Sort(out)
	return out
}

func TestG19ServedRoutesEqualTheRouteTable(t *testing.T) {
	a := newAuth(t)
	ok := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })
	noop := func(http.ResponseWriter, *http.Request, egauth.Principal[struct{}]) {}
	h, err := a.Routes().Public("GET /health", ok).Protect("POST /items", noop).ProtectAPI("GET /api/items", noop, egauth.Kinds("service")).Build()
	require.NoError(t, err)

	table := egauth.TablePatterns(a)
	want := append(slices.Clone(table), "GET "+routes.WellKnown, "GET /health", "POST /items", "GET /api/items")
	slices.Sort(want)
	require.Equal(t, want, servedSet(h))
	require.Equal(t, want, probedSet(h, "GET /health", "POST /items", "GET /api/items"), "probing the mux finds exactly the served set")

	var registry []string
	for _, p := range routes.All() {
		registry = append(registry, routes.Method(p)+" /auth"+p)
	}
	slices.Sort(registry)
	sortedTable := slices.Clone(table)
	slices.Sort(sortedTable)
	require.Equal(t, registry, sortedTable, "a fully enabled deployment serves every registry entry and nothing else")

	for _, p := range routes.All() {
		target := "/auth" + strings.ReplaceAll(strings.ReplaceAll(p, "{provider}", "corp"), "{name}", "ldap")
		for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
			got := egauth.MatchedPattern(h, httptest.NewRequest(m, target, nil))
			if m == routes.Method(p) {
				require.Equal(t, m+" /auth"+p, got, m+" "+target)
				continue
			}
			require.Empty(t, got, m+" "+target)
		}
	}
	require.Equal(t, "GET "+routes.WellKnown, egauth.MatchedPattern(h, httptest.NewRequest(http.MethodGet, routes.WellKnown, nil)))
}

func TestG19DisabledModulesAreNotServed(t *testing.T) {
	a := mustNew(t, minimalConfig(t))
	h, err := a.Routes().Build()
	require.NoError(t, err)
	table := egauth.TablePatterns(a)
	want := append(slices.Clone(table), "GET "+routes.WellKnown)
	slices.Sort(want)
	require.Equal(t, want, servedSet(h))
	require.Equal(t, want, probedSet(h), "probing the mux finds exactly the served set")
	for _, p := range routes.All() {
		pattern := routes.Method(p) + " /auth" + p
		target := "/auth" + strings.ReplaceAll(strings.ReplaceAll(p, "{provider}", "corp"), "{name}", "ldap")
		got := egauth.MatchedPattern(h, httptest.NewRequest(routes.Method(p), target, nil))
		if slices.Contains(table, pattern) {
			require.Equal(t, pattern, got)
			continue
		}
		require.Empty(t, got, pattern+" belongs to a disabled module")
	}
	for _, p := range []string{routes.Register, routes.Login, routes.ResourceToken, routes.JWKS, routes.OAuthBegin, routes.MFAChallenge} {
		require.NotContains(t, table, routes.Method(p)+" /auth"+p)
	}
}
