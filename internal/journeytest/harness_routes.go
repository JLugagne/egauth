package journeytest

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/keys"
	"github.com/JLugagne/egauth/store/tokens"
)

// Facade probe routes: each calls one facade with the caller its principal carries and answers
// {"result": name} with the name of the sentinel the facade returned, or "ok".
const (
	FacadeSystemRoute  = "/app/facade/system"
	FacadeDisableRoute = "/app/facade/disable/"
	FacadeAPIRoute     = "/api/facade/disable/"
	FacadeKeyRoute     = "/app/facade/key"
)

var sentinels = []struct {
	name string
	err  error
}{
	{"ErrSystemCallerInRequest", egauth.ErrSystemCallerInRequest},
	{"ErrAPIKeyCaller", egauth.ErrAPIKeyCaller},
	{"ErrResourceTokenCaller", egauth.ErrResourceTokenCaller},
	{"ErrSessionEnded", egauth.ErrSessionEnded},
	{"ErrClaimsNotSubset", egauth.ErrClaimsNotSubset},
	{"ErrReauthRequired", egauth.ErrReauthRequired},
	{"ErrTenantMismatch", egauth.ErrTenantMismatch},
	{"ErrForbidden", egauth.ErrForbidden},
}

func sentinelName(err error) string {
	if err == nil {
		return "ok"
	}
	for _, s := range sentinels {
		if errors.Is(err, s.err) {
			return s.name
		}
	}
	return "other: " + err.Error()
}

func answer(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"result": sentinelName(err)})
}

// RouteKind is how a declared route is protected.
type RouteKind uint8

// Route kinds of the declared routes of a World.
const (
	RouteProtect RouteKind = iota + 1
	RouteOptional
	RoutePublic
	RouteAPI
)

// DeclaredRoute is one route BuildWorld declares, with the path a request can use.
type DeclaredRoute struct {
	Kind   RouteKind
	Method string
	Path   string
}

type routeDecl struct {
	DeclaredRoute
	pattern string
	handler egauth.PrincipalHandler[Claims]
	public  http.Handler
	opts    []egauth.RouteOption
	kinds   *egauth.APIKinds
}

func (w *World) recorded(h func(http.ResponseWriter, *http.Request, egauth.Principal[Claims])) egauth.PrincipalHandler[Claims] {
	return func(rw http.ResponseWriter, r *http.Request, p egauth.Principal[Claims]) {
		w.Seen.record(p)
		h(rw, r, p)
	}
}

func (w *World) routeTable() []routeDecl {
	decl := func(kind RouteKind, method, pattern string, h egauth.PrincipalHandler[Claims], opts ...egauth.RouteOption) routeDecl {
		path := strings.ReplaceAll(pattern, "{id}", uuid.Nil.String())
		return routeDecl{DeclaredRoute: DeclaredRoute{Kind: kind, Method: method, Path: path}, pattern: method + " " + pattern, handler: h, opts: opts}
	}
	get, post := http.MethodGet, http.MethodPost
	seen := w.Seen.handler
	table := []routeDecl{
		decl(RouteProtect, get, ProtectRoute, seen),
		decl(RouteProtect, post, ProtectRoute, seen),
		decl(RouteProtect, get, MFARoute, seen, egauth.RequireMFA()),
		decl(RouteProtect, get, FreshRoute, seen, egauth.RequireFreshAuth(egauth.Fresh5m)),
		decl(RouteProtect, get, AdminRoute, seen, egauth.RequireAnyRole(AdminRole)),
		decl(RouteOptional, get, OptionalRoute, seen),
		decl(RouteOptional, post, OptionalRoute, seen),
		{
			DeclaredRoute: DeclaredRoute{Kind: RoutePublic, Method: get, Path: PublicRoute}, pattern: get + " " + PublicRoute,
			public: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) }),
		},
		decl(RouteProtect, post, FacadeSystemRoute, w.recorded(w.facadeSystem)),
		decl(RouteProtect, post, FacadeDisableRoute+"{id}", w.recorded(w.facadeDisable)),
		decl(RouteProtect, post, FacadeKeyRoute, w.recorded(w.facadeKey)),
	}
	if w.Config.Modules.APIKeys != nil {
		kinds := egauth.Kinds(APIKeyKind)
		api := func(method, pattern string, h egauth.PrincipalHandler[Claims]) routeDecl {
			d := decl(RouteAPI, method, pattern, h)
			d.kinds = &kinds
			return d
		}
		table = append(table,
			api(get, APIRoute, seen),
			api(post, APIRoute, seen),
			api(post, FacadeAPIRoute+"{id}", w.recorded(w.facadeDisable)),
		)
	}
	return table
}

// DeclaredRoutes lists every route BuildWorld declared on the World's handler, so that the probes
// derive their targets from the same table the handler was built from.
func (w *World) DeclaredRoutes() []DeclaredRoute {
	out := make([]DeclaredRoute, 0, len(w.declared))
	for _, d := range w.declared {
		out = append(out, d.DeclaredRoute)
	}
	return out
}

func (w *World) applyRoutes(rt *egauth.Routes[Claims]) *egauth.Routes[Claims] {
	for _, d := range w.declared {
		switch d.Kind {
		case RouteProtect:
			rt = rt.Protect(d.pattern, d.handler, d.opts...)
		case RouteOptional:
			rt = rt.Optional(d.pattern, d.handler, d.opts...)
		case RoutePublic:
			rt = rt.Public(d.pattern, d.public)
		case RouteAPI:
			rt = rt.ProtectAPI(d.pattern, d.handler, *d.kinds)
		}
	}
	return rt
}

func (w *World) facadeSystem(rw http.ResponseWriter, r *http.Request, p egauth.Principal[Claims]) {
	caller, err := w.Auth.System(p.Subject().Tenant, "journeytest probe")
	if err != nil {
		answer(rw, err)
		return
	}
	answer(rw, w.Auth.Accounts().Disable(r.Context(), caller, uuid.New()))
}

func (w *World) facadeDisable(rw http.ResponseWriter, r *http.Request, p egauth.Principal[Claims]) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		answer(rw, err)
		return
	}
	answer(rw, w.Auth.Accounts().Disable(r.Context(), p.Caller(), id))
}

func (w *World) facadeKey(rw http.ResponseWriter, r *http.Request, p egauth.Principal[Claims]) {
	req := egauth.APIKeyRequest{Kind: APIKeyKind, Name: "probe", Lifetime: keys.DefaultExpiry()}
	if role := r.URL.Query().Get("role"); role != "" {
		req.Roles = []string{role}
	}
	_, err := w.Auth.APIKeys().Create(r.Context(), p.Caller(), req)
	answer(rw, err)
}

// SeedAPIKey stores an API key of kind owned by owner and returns its secret. The key carries the
// roles and scopes given; it is written through storage so that it exists whatever the facades
// permit.
func (w *World) SeedAPIKey(owner principal.Subject, kind string, roles, scopes []string) string {
	w.T.Helper()
	secret := "egk_" + strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", "")
	sum := sha256.Sum256([]byte(secret))
	raw, err := json.Marshal(map[string][]string{"roles": nonNil(roles), "scopes": nonNil(scopes), "groups": {}})
	if err != nil {
		w.T.Fatalf("journeytest: encoding the key grant: %v", err)
	}
	epoch, err := w.Storage.Identity.CurrentEpoch(context.Background(), owner)
	if err != nil {
		w.T.Fatalf("journeytest: reading the epoch: %v", err)
	}
	k := tokens.APIKey{
		ID: uuid.New(), Owner: owner, Kind: kind, Name: "journeytest", KeyHash: sum[:], AppClaims: raw,
		CreatedEpoch: epoch, CreatedAt: w.Clock.Now(),
	}
	if err := w.Storage.Tokens.CreateAPIKey(context.Background(), k); err != nil {
		w.T.Fatalf("journeytest: storing the key: %v", err)
	}
	return secret
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
