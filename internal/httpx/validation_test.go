package httpx_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/store/limiter"
)

func TestNewPreambleRefusesIncompleteEnvAndSettings(t *testing.T) {
	cases := map[string]func(*httpx.Env, *httpx.Settings){
		"nil tenants":       func(e *httpx.Env, _ *httpx.Settings) { e.Tenants = nil },
		"nil limiter":       func(e *httpx.Env, _ *httpx.Settings) { e.Limiter = nil },
		"nil authenticator": func(e *httpx.Env, _ *httpx.Settings) { e.Authenticator = nil },
		"nil identifiers":   func(e *httpx.Env, _ *httpx.Settings) { e.Identifiers = nil },
		"nil enrollment":    func(e *httpx.Env, _ *httpx.Settings) { e.Enrollment = nil },
		"nil clients":       func(_ *httpx.Env, s *httpx.Settings) { s.Clients = nil },
		"zero transports":   func(_ *httpx.Env, s *httpx.Settings) { s.Transports = 0 },
		"zero window":       func(_ *httpx.Env, s *httpx.Settings) { s.ReauthWindow = 0 },
		"negative window":   func(_ *httpx.Env, s *httpx.Settings) { s.ReauthWindow = -time.Minute },
		"window over 1h":    func(_ *httpx.Env, s *httpx.Settings) { s.ReauthWindow = time.Hour + time.Second },
		"no origins":        func(_ *httpx.Env, s *httpx.Settings) { s.Origins = csrf.Origins{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			env, set := w.env(), w.set
			mutate(&env, &set)
			_, err := httpx.NewPreamble(env, set)
			if !errors.Is(err, httpx.ErrIncompleteEnv) && !errors.Is(err, httpx.ErrInvalidSettings) {
				t.Fatalf("want a refusal, got %v", err)
			}
		})
	}
	w := newWorld(t)
	env, set := w.env(), w.set
	env.BeforeEndpoint, env.Issuer = nil, nil
	set.Origins = csrf.Origins{}
	set.Insecure.NoOriginCheck = true
	if _, err := httpx.NewPreamble(env, set); err != nil {
		t.Fatalf("optional members and an acknowledged NoOriginCheck: %v", err)
	}
}

func TestEnvValidateNamesEveryMissingMember(t *testing.T) {
	err := httpx.Env{}.Validate()
	if !errors.Is(err, httpx.ErrIncompleteEnv) {
		t.Fatalf("got %v", err)
	}
	for _, name := range []string{"Tenants", "Limiter", "Authenticator", "Issuer", "Identifiers", "Enrollment", "Audit"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("%s not reported in %v", name, err)
		}
	}
}

func TestMetaValidate(t *testing.T) {
	good := []httpx.Meta{
		{BodyCap: httpx.FormBodyCap},
		{BodyCap: httpx.WebAuthnBodyCap, Authenticated: true, Sensitive: true},
		{BodyCap: httpx.FormBodyCap, IdentifierKeyed: true, IdentifierLimit: limiter.CodeRequestIdentifier, ClientLimit: limiter.CodeRequestClient},
		{BodyCap: httpx.FormBodyCap, Authenticated: true, SessionLimit: limiter.LoginClient},
		{BodyCap: httpx.FormBodyCap, Mutation: true, EndsSession: true},
	}
	for _, m := range good {
		if err := m.Validate(); err != nil {
			t.Errorf("%+v: %v", m, err)
		}
	}
	bad := []httpx.Meta{
		{},
		{BodyCap: httpx.WebAuthnBodyCap + 1},
		{BodyCap: httpx.FormBodyCap, Sensitive: true},
		{BodyCap: httpx.FormBodyCap, IdentifierKeyed: true},
		{BodyCap: httpx.FormBodyCap, IdentifierLimit: limiter.LoginIdentifier},
		{BodyCap: httpx.FormBodyCap, IdentifierKeyed: true, IdentifierLimit: limiter.LoginClient},
		{BodyCap: httpx.FormBodyCap, ClientLimit: limiter.LoginIdentifier},
		{BodyCap: httpx.FormBodyCap, ClientLimit: limiter.Class(99)},
		{BodyCap: httpx.FormBodyCap, SessionLimit: limiter.LoginClient},
		{BodyCap: httpx.FormBodyCap, Authenticated: true, SessionLimit: limiter.LoginIdentifier},
		{BodyCap: httpx.FormBodyCap, Authenticated: true, SessionLimit: limiter.Class(99)},
		{BodyCap: httpx.FormBodyCap, EndsSession: true},
		{BodyCap: httpx.FormBodyCap, Mutation: true, EndsSession: true, Authenticated: true, Sensitive: true},
		{BodyCap: httpx.FormBodyCap, Mutation: true, EndsSession: true, IdentifierKeyed: true, IdentifierLimit: limiter.LoginIdentifier},
	}
	for _, m := range bad {
		if err := m.Validate(); !errors.Is(err, httpx.ErrInvalidMeta) {
			t.Errorf("%+v: want ErrInvalidMeta, got %v", m, err)
		}
	}
	w := newWorld(t)
	p, err := httpx.NewPreamble(w.env(), w.set)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Wrap("/x", httpx.Meta{}, func(http.ResponseWriter, *httpx.Request) {}); !errors.Is(err, httpx.ErrInvalidMeta) {
		t.Fatalf("Wrap with invalid meta: %v", err)
	}
	if _, err := p.Wrap("", httpx.Meta{BodyCap: httpx.FormBodyCap}, func(http.ResponseWriter, *httpx.Request) {}); !errors.Is(err, httpx.ErrInvalidMeta) {
		t.Fatalf("Wrap with empty endpoint: %v", err)
	}
	if _, err := p.Wrap("/x", httpx.Meta{BodyCap: httpx.FormBodyCap}, nil); !errors.Is(err, httpx.ErrInvalidMeta) {
		t.Fatalf("Wrap with nil func: %v", err)
	}
}

func TestChange(t *testing.T) {
	f, ok := httpx.FactorEnrolledChange(core.FactorTOTP).EnrolledFactor()
	if !ok || f != core.FactorTOTP {
		t.Fatal("enrolled factor")
	}
	if _, ok := httpx.FactorEnrolledChange(core.Factor{}).EnrolledFactor(); ok {
		t.Fatal("zero factor accepted")
	}
	if !httpx.PasswordChangedChange().PasswordChanged() || (httpx.Change{}).PasswordChanged() {
		t.Fatal("password change")
	}
	if _, ok := (httpx.Change{}).EnrolledFactor(); ok {
		t.Fatal("zero change carries a factor")
	}
}

func TestSubdomainTenancy(t *testing.T) {
	res, err := httpx.TenantBySubdomain("https://{tenant}.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		want string
		ok   bool
	}{
		{"acme.example.com", "acme", true},
		{"ACME.Example.com", "acme", true},
		{"acme.example.com:443", "acme", true},
		{"acme-2.example.com", "acme-2", true},
		{"acme.example.com:8443", "", false},
		{"example.com", "", false},
		{".example.com", "", false},
		{"a.b.example.com", "", false},
		{"acme.example.com.evil.test", "", false},
		{"acme_x.example.com", "", false},
		{"evilexample.com", "", false},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = tc.host
		got, err := res.ResolveTenant(r)
		if tc.ok && (err != nil || got.String() != tc.want) {
			t.Errorf("%s: %v %v", tc.host, got, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: resolved %q", tc.host, got)
		}
	}
	for _, bad := range []string{"https://app.example.com", "https://x.{tenant}.example.com", "{tenant}.example.com", "ftp://{tenant}.example.com", "https://{tenant}.example.com/path"} {
		if _, err := httpx.TenantBySubdomain(bad); !errors.Is(err, httpx.ErrInvalidTenancy) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	port, err := httpx.TenantBySubdomain("http://{tenant}.localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "acme.localhost:8080"
	if got, err := port.ResolveTenant(r); err != nil || got.String() != "acme" {
		t.Fatalf("port origin: %v %v", got, err)
	}
	r.Host = "acme.localhost"
	if _, err := port.ResolveTenant(r); err == nil {
		t.Fatal("missing port accepted")
	}
}

func TestSingleTenantResolver(t *testing.T) {
	got, err := httpx.SingleTenant().ResolveTenant(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil || !got.IsZero() {
		t.Fatalf("%v %v", got, err)
	}
}
