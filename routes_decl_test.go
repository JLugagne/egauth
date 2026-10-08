package egauth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/principalctx"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/principal"
)

func newAuth(t *testing.T, mut ...func(*egauth.Config[struct{}])) *egauth.Auth[struct{}] {
	t.Helper()
	cfg := fullConfig(t)
	for _, m := range mut {
		m(&cfg)
	}
	a, err := egauth.New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, a.Close()) })
	return a
}

func noop(http.ResponseWriter, *http.Request, egauth.Principal[struct{}]) {}

func TestRoutesDeclValidBuildServesOnlyDeclaredRoutes(t *testing.T) {
	a := newAuth(t)
	var optional egauth.Principal[struct{}]
	var inRequest bool
	h, err := a.Routes().
		Public("GET /health", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inRequest = principalctx.InRequest(r.Context())
			w.WriteHeader(http.StatusNoContent)
		})).
		Optional("GET /{$}", func(w http.ResponseWriter, _ *http.Request, p egauth.Principal[struct{}]) {
			optional = p
			w.WriteHeader(http.StatusOK)
		}).
		Protect("POST /account", noop, egauth.RequireMFA(), egauth.RequireFreshAuth(egauth.Fresh5m), egauth.RequireAnyRole("user")).
		Protect("GET /admin", noop, egauth.RequireAllRoles("admin", "ops"), egauth.RequireFactor(principal.FactorPasskey), egauth.AcceptMustChange()).
		ProtectAPI("GET /api/items", noop, egauth.Kinds("service", "pat"), egauth.RequireAnyScope("items:read")).
		Build()
	require.NoError(t, err)

	serve := func(method, target string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
		return rec.Code
	}
	require.Equal(t, http.StatusNoContent, serve(http.MethodGet, "/health"))
	require.True(t, inRequest)
	require.Equal(t, http.StatusOK, serve(http.MethodGet, "/"))
	require.Equal(t, egauth.Anonymous, optional.Kind())
	require.Equal(t, http.StatusUnauthorized, serve(http.MethodPost, "/account"))
	require.Equal(t, http.StatusUnauthorized, serve(http.MethodGet, "/admin"))
	require.Equal(t, http.StatusUnauthorized, serve(http.MethodGet, "/api/items"))
	require.Equal(t, http.StatusNotFound, serve(http.MethodGet, "/undeclared"))
}

func TestRoutesDeclRejectsInvalidDeclarations(t *testing.T) {
	cases := []struct {
		name  string
		build func(*egauth.Routes[struct{}]) *egauth.Routes[struct{}]
	}{
		{"no method", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] { return r.Protect("/x", noop) }},
		{"host in pattern", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] {
			return r.Protect("GET example.com/x", noop)
		}},
		{"overlaps base path", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] { return r.Protect("GET /auth/session", noop) }},
		{"wildcard over base path", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] {
			return r.Public("GET /{any...}", http.NotFoundHandler())
		}},
		{"overlaps discovery", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] {
			return r.Public("GET /.well-known/{doc}", http.NotFoundHandler())
		}},
		{"overlapping declarations", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] {
			return r.Protect("GET /items/{id}", noop).Optional("GET /items/{name}", noop)
		}},
		{"zero factor", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] {
			return r.Protect("GET /x", noop, egauth.RequireFactor(principal.Factor{}))
		}},
		{"zero freshness", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] {
			return r.Protect("GET /x", noop, egauth.RequireFreshAuth(0))
		}},
		{"blank role", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] {
			return r.Protect("GET /x", noop, egauth.RequireAnyRole(""))
		}},
		{"blank extra scope", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] {
			return r.ProtectAPI("GET /x", noop, egauth.Kinds("service"), egauth.RequireAllScopes("a", " "))
		}},
		{"zero claim requirement", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] {
			return r.Optional("GET /x", noop, egauth.ClaimRequirement{})
		}},
		{"zero session requirement", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] {
			return r.Protect("GET /x", noop, egauth.SessionRequirement{})
		}},
		{"nil option", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] { return r.Protect("GET /x", noop, nil) }},
		{"nil principal handler", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] { return r.Protect("GET /x", nil) }},
		{"nil public handler", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] { return r.Public("GET /x", nil) }},
		{"undeclared api kind", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] {
			return r.ProtectAPI("GET /x", noop, egauth.Kinds("robot"))
		}},
		{"zero api kinds", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] {
			return r.ProtectAPI("GET /x", noop, egauth.APIKinds{})
		}},
		{"duplicate api kinds", func(r *egauth.Routes[struct{}]) *egauth.Routes[struct{}] {
			return r.ProtectAPI("GET /x", noop, egauth.Kinds("service", "service"))
		}},
	}
	a := newAuth(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := tc.build(a.Routes()).Build()
			require.Error(t, err)
			require.Nil(t, h)
		})
	}
}

func TestRoutesDeclProtectAPINeedsTheAPIKeysModule(t *testing.T) {
	a := newAuth(t, func(c *egauth.Config[struct{}]) {
		c.Modules.APIKeys = nil
		c.Storage.Tokens = nil
		c.Sessions = egauth.Stateful()
		c.Audiences = nil
	})
	_, err := a.Routes().ProtectAPI("GET /x", noop, egauth.Kinds("service")).Build()
	require.ErrorIs(t, err, routes.ErrInvalidDeclaration)
}

func TestRoutesDeclReportsEveryProblemJoined(t *testing.T) {
	a := newAuth(t)
	_, err := a.Routes().
		Protect("/nomethod", noop).
		Protect("GET /auth/login", noop).
		Protect("GET /x", nil, egauth.RequireFreshAuth(0)).
		ProtectAPI("GET /y", noop, egauth.Kinds("robot")).
		Build()
	require.Error(t, err)
	require.GreaterOrEqual(t, countLeaves(err), 5)
	for _, s := range []string{"/nomethod", "GET /auth/login", "GET /x", "GET /y"} {
		require.Contains(t, err.Error(), s)
	}
}

func TestRoutesDeclBuilderNeedsAnAuth(t *testing.T) {
	var rt egauth.Routes[struct{}]
	h, err := rt.Public("GET /x", http.NotFoundHandler()).Build()
	require.Error(t, err)
	require.Nil(t, h)
}

func TestRoutesDeclPrincipalAccessors(t *testing.T) {
	var zero egauth.Principal[struct{}]
	require.Equal(t, egauth.Anonymous, zero.Kind())
	_, ok := zero.Session()
	require.False(t, ok)
	_, ok = zero.SessionID()
	require.False(t, ok)
	_, ok = zero.APIKey()
	require.False(t, ok)
	require.Zero(t, zero.Caller().Kind())

	attrs := principaltest.Full()
	claims := egauth.AppClaims[struct{}]{Roles: []string{"user"}}
	p, err := egauth.NewSessionPrincipal(attrs, claims)
	require.NoError(t, err)
	require.Equal(t, egauth.Session, p.Kind())
	require.Equal(t, attrs.Subject(), p.Subject())
	got, ok := p.Session()
	require.True(t, ok)
	require.Equal(t, attrs, got)
	id, ok := p.SessionID()
	require.True(t, ok)
	require.Equal(t, attrs.Lineage(), id)
	require.Equal(t, principal.CallerSession, p.Caller().Kind())
	_, ok = p.APIKey()
	require.False(t, ok)
	claims.Roles[0] = "admin"
	c := p.Claims()
	require.Equal(t, []string{"user"}, c.Roles)
	c.Roles[0] = "admin"
	require.Equal(t, []string{"user"}, p.Claims().Roles)

	_, err = egauth.NewSessionPrincipal(principal.SessionAttrs{}, claims)
	require.Error(t, err)

	info := egauth.APIKeyInfo{ID: uuid.New(), Kind: "service", Owner: attrs.Subject(), Scopes: []string{"items:read"}, CreatedAt: time.Unix(1, 0)}
	k, err := egauth.NewAPIKeyPrincipal(info, egauth.AppClaims[struct{}]{Scopes: []string{"items:read"}})
	require.NoError(t, err)
	require.Equal(t, egauth.APIKey, k.Kind())
	require.Equal(t, attrs.Subject(), k.Subject())
	gotInfo, ok := k.APIKey()
	require.True(t, ok)
	require.Equal(t, info, gotInfo)
	gotInfo.Scopes[0] = "items:write"
	again, _ := k.APIKey()
	require.Equal(t, []string{"items:read"}, again.Scopes)
	_, ok = k.Session()
	require.False(t, ok)
	require.Equal(t, principal.CallerAPIKey, k.Caller().Kind())

	_, err = egauth.NewAPIKeyPrincipal(egauth.APIKeyInfo{}, egauth.AppClaims[struct{}]{})
	require.True(t, err != nil && !errors.Is(err, egauth.ErrClosed))
}

func countLeaves(err error) int {
	u, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return 1
	}
	parts := u.Unwrap()
	if len(parts) > 0 && (parts[0] == routes.ErrInvalidDeclaration || parts[0] == routes.ErrConflict) {
		return 1
	}
	n := 0
	for _, e := range parts {
		n += countLeaves(e)
	}
	return n
}
