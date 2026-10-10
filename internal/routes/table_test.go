package routes_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/clientaddr"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/limiter"
)

func ok(rw http.ResponseWriter, r *httpx.Request) { r.Respond(rw, httpx.Response{}) }

func endpoint(t *testing.T, path string) routes.Endpoint {
	t.Helper()
	e, err := routes.NewEndpoint(path, ok)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestNewEndpointComputesMethodAndMeta(t *testing.T) {
	e := endpoint(t, routes.PasswordChange)
	m, _ := routes.MetaFor(routes.PasswordChange)
	if e.Method != http.MethodPost || e.Meta != m || e.Path != routes.PasswordChange {
		t.Fatalf("endpoint %+v", e)
	}
	if _, err := routes.NewEndpoint("/nope", ok); !errors.Is(err, routes.ErrUnknownPath) {
		t.Fatalf("unknown path: %v", err)
	}
	if _, err := routes.NewEndpoint(routes.Login, nil); !errors.Is(err, routes.ErrInvalidEndpoint) {
		t.Fatalf("nil func: %v", err)
	}
}

func TestTableRefusesTamperedEndpoints(t *testing.T) {
	downgraded := endpoint(t, routes.AccountDelete)
	downgraded.Meta.Sensitive = false
	wrongMethod := endpoint(t, routes.Login)
	wrongMethod.Method = http.MethodGet
	bigger := endpoint(t, routes.Login)
	bigger.Meta.BodyCap = httpx.WebAuthnBodyCap
	unknown := routes.Endpoint{Method: http.MethodPost, Path: "/admin", Func: ok}
	for name, e := range map[string]routes.Endpoint{"downgraded meta": downgraded, "wrong method": wrongMethod, "bigger cap": bigger, "unknown": unknown} {
		if _, err := routes.NewTable(e); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := routes.NewTable(endpoint(t, routes.Login), endpoint(t, routes.Login)); !errors.Is(err, routes.ErrConflict) {
		t.Fatalf("duplicate path: %v", err)
	}
	_, err := routes.NewTable(downgraded, wrongMethod)
	if !errors.Is(err, routes.ErrInvalidEndpoint) {
		t.Fatalf("problems must be joined: %v", err)
	}
}

func TestBasePathValidation(t *testing.T) {
	for _, bad := range []string{"", "/", "auth", "/auth/", "/{x}", "/a b", "/a?b", "/a%2f", "/a/../b", "/a//b", "//a", "/./a", "/a/.", "/.."} {
		if err := routes.ValidateBasePath(bad); !errors.Is(err, routes.ErrInvalidBasePath) {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"/auth", "/api/v1/auth", "/a.b/..c"} {
		if err := routes.ValidateBasePath(good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
}

type anyTenant struct{}

func (anyTenant) ResolveTenant(*http.Request) (core.TenantID, error) { return core.TenantID{}, nil }

type allowAll struct{}

func (allowAll) Allow(context.Context, limiter.Key) (limiter.Decision, error) {
	return limiter.Decision{Allowed: true}, nil
}

type noSession struct{}

func (noSession) Resume(context.Context, http.ResponseWriter, *http.Request, core.TenantID) (session.Resumed, error) {
	return session.Resumed{}, errors.New("no session")
}

type noIdentifiers struct{}

func (noIdentifiers) Normalize(string) (identity.Identifier, error) {
	return identity.Identifier{}, errors.New("x")
}

type notEnrolled struct{}

func (notEnrolled) MFARequired(context.Context, core.Subject) (bool, error) { return false, nil }

func preamble(t *testing.T) *httpx.Preamble {
	t.Helper()
	res, err := clientaddr.New(clientaddr.Direct(), nil)
	if err != nil {
		t.Fatal(err)
	}
	o, err := csrf.NewOrigins("https://app.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := httpx.NewPreamble(httpx.Env{
		Tenants: httpx.SingleTenant(), Limiter: allowAll{}, Authenticator: noSession{},
		Identifiers: noIdentifiers{}, Enrollment: notEnrolled{}, Audit: httpx.SinkAudit(nil),
	}, httpx.Settings{Clients: res, Origins: o, Transports: httpx.CookiesAndBearer, ReauthWindow: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMountServesEveryEndpointBehindThePreamble(t *testing.T) {
	var eps []routes.Endpoint
	for _, p := range routes.All() {
		eps = append(eps, endpoint(t, p))
	}
	tbl, err := routes.NewTable(eps...)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := tbl.Mount(mux, "/auth", preamble(t)); err != nil {
		t.Fatal(err)
	}
	patterns := tbl.Patterns("/auth")
	if len(patterns) != len(routes.All()) || !slices.Contains(patterns, "POST /auth/login") || !slices.Contains(patterns, "GET /auth/oauth/{provider}/callback") {
		t.Fatalf("patterns %v", patterns)
	}
	r := httptest.NewRequest(http.MethodPost, "https://app.example.com/auth/account/delete", nil)
	r.Header.Set("Origin", "https://app.example.com")
	r.RemoteAddr = "198.51.100.1:1"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an authenticated endpoint served without a session: %d", w.Code)
	}
	cross := httptest.NewRequest(http.MethodPost, "https://app.example.com/auth/login", nil)
	cross.Header.Set("Origin", "https://evil.example")
	cross.RemoteAddr = "198.51.100.1:1"
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, cross)
	if w.Code != http.StatusForbidden {
		t.Fatalf("login CSRF not refused: %d", w.Code)
	}
}

func TestMountReportsConflicts(t *testing.T) {
	tbl, err := routes.NewTable(endpoint(t, routes.Login))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("POST /auth/login", http.NotFoundHandler())
	if err := tbl.Mount(mux, "/auth", preamble(t)); !errors.Is(err, routes.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	if err := tbl.Mount(http.NewServeMux(), "/auth/", preamble(t)); !errors.Is(err, routes.ErrInvalidBasePath) {
		t.Fatalf("want ErrInvalidBasePath, got %v", err)
	}
	if err := tbl.Mount(http.NewServeMux(), "/auth", nil); err == nil {
		t.Fatal("nil preamble accepted")
	}
}
