package routes_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/routes"
)

var dep = routes.Deployment{BasePath: "/auth", APIKinds: []string{"service", "pat"}, APIKeys: true}

func validate(decls ...routes.Declaration) error {
	var u routes.UserRoutes
	for _, d := range decls {
		u.Add(d)
	}
	return u.Validate(dep)
}

func sessionSpec(f func(*routes.SessionSpec)) routes.SessionSpec {
	var s routes.SessionSpec
	f(&s)
	return s
}

func apiSpec(f func(*routes.APISpec)) routes.APISpec {
	var a routes.APISpec
	f(&a)
	return a
}

func TestValidDeclarations(t *testing.T) {
	err := validate(
		routes.Declaration{Pattern: "GET /{$}", Kind: routes.KindPublic},
		routes.Declaration{Pattern: "GET /app/", Kind: routes.KindProtect, Session: sessionSpec(func(s *routes.SessionSpec) {
			s.RequireMFA()
			s.RequireFresh(routes.Fresh15m)
			s.RequireFactor(core.FactorTOTP)
			s.AddClaim(routes.NewClaimRequirement(routes.ClaimRoles, routes.MatchAny, "admin", "owner"))
		})},
		routes.Declaration{Pattern: "GET /feed", Kind: routes.KindOptional},
		routes.Declaration{Pattern: "POST /api/items", Kind: routes.KindProtectAPI, API: apiSpec(func(a *routes.APISpec) {
			a.SetKinds("service")
			a.AddClaim(routes.NewClaimRequirement(routes.ClaimScopes, routes.MatchAll, "items:write"))
		})},
		routes.Declaration{Pattern: "GET /authx", Kind: routes.KindPublic},
		routes.Declaration{Pattern: "GET /files/{rest...}", Kind: routes.KindProtect},
		routes.Declaration{Pattern: "POST /files/{id}/meta", Kind: routes.KindProtect},
		routes.Declaration{Pattern: "GET /docs/{$}", Kind: routes.KindPublic},
		routes.Declaration{Pattern: "GET /docs", Kind: routes.KindPublic},
		routes.Declaration{Pattern: "GET /blog/{id}", Kind: routes.KindPublic},
		routes.Declaration{Pattern: "GET /blogs/{id}", Kind: routes.KindProtect},
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestInvalidDeclarations(t *testing.T) {
	protect := func(p string) routes.Declaration { return routes.Declaration{Pattern: p, Kind: routes.KindProtect} }
	cases := map[string]struct {
		decls []routes.Declaration
		want  error
	}{
		"no method":              {[]routes.Declaration{protect("/x")}, routes.ErrInvalidDeclaration},
		"host pattern":           {[]routes.Declaration{protect("GET example.com/x")}, routes.ErrInvalidDeclaration},
		"unknown method":         {[]routes.Declaration{protect("TRACE /x")}, routes.ErrInvalidDeclaration},
		"zero kind":              {[]routes.Declaration{{Pattern: "GET /x"}}, routes.ErrInvalidDeclaration},
		"catch-all overlaps":     {[]routes.Declaration{protect("GET /")}, routes.ErrConflict},
		"base path itself":       {[]routes.Declaration{protect("GET /auth")}, routes.ErrConflict},
		"under base path":        {[]routes.Declaration{protect("GET /auth/custom")}, routes.ErrConflict},
		"subtree of base path":   {[]routes.Declaration{protect("POST /auth/")}, routes.ErrConflict},
		"wildcard under base":    {[]routes.Declaration{protect("GET /{a}/custom")}, routes.ErrConflict},
		"multi wildcard at root": {[]routes.Declaration{protect("GET /{rest...}")}, routes.ErrConflict},
		"wildcard over endpoint": {[]routes.Declaration{protect("POST /{a}/login")}, routes.ErrConflict},
		"well-known":             {[]routes.Declaration{protect("GET /.well-known/egauth-configuration")}, routes.ErrConflict},
		"well-known subtree":     {[]routes.Declaration{protect("GET /.well-known/")}, routes.ErrConflict},
		"duplicate":              {[]routes.Declaration{protect("GET /x"), protect("GET /x")}, routes.ErrConflict},
		"ambiguous wildcards":    {[]routes.Declaration{protect("GET /{a}/b"), protect("GET /a/{b}")}, routes.ErrConflict},
		"public hole in protect subtree": {[]routes.Declaration{
			{Pattern: "GET /admin/", Kind: routes.KindProtect, Session: sessionSpec(func(s *routes.SessionSpec) {
				s.AddClaim(routes.NewClaimRequirement(routes.ClaimRoles, routes.MatchAny, "admin"))
			})},
			{Pattern: "GET /admin/{id}", Kind: routes.KindPublic},
		}, routes.ErrConflict},
		"optional hole declared first": {[]routes.Declaration{
			{Pattern: "GET /admin/users/{id}", Kind: routes.KindOptional},
			protect("GET /admin/{rest...}"),
		}, routes.ErrConflict},
		"literal under wildcard":   {[]routes.Declaration{protect("GET /items/{id}"), {Pattern: "GET /items/new", Kind: routes.KindPublic}}, routes.ErrConflict},
		"same kind overlap":        {[]routes.Declaration{protect("GET /files/{rest...}"), protect("GET /files/{id}/meta")}, routes.ErrConflict},
		"head under get":           {[]routes.Declaration{protect("GET /x"), {Pattern: "HEAD /x", Kind: routes.KindPublic}}, routes.ErrConflict},
		"exact root under subtree": {[]routes.Declaration{protect("GET /admin/"), {Pattern: "GET /admin/{$}", Kind: routes.KindPublic}}, routes.ErrConflict},
		"zero factor":              {[]routes.Declaration{{Pattern: "GET /x", Kind: routes.KindProtect, Session: sessionSpec(func(s *routes.SessionSpec) { s.RequireFactor(core.Factor{}) })}}, routes.ErrInvalidDeclaration},
		"zero freshness":           {[]routes.Declaration{{Pattern: "GET /x", Kind: routes.KindProtect, Session: sessionSpec(func(s *routes.SessionSpec) { s.RequireFresh(0) })}}, routes.ErrInvalidDeclaration},
		"empty role": {[]routes.Declaration{{Pattern: "GET /x", Kind: routes.KindOptional, Session: sessionSpec(func(s *routes.SessionSpec) {
			s.AddClaim(routes.NewClaimRequirement(routes.ClaimRoles, routes.MatchAll, ""))
		})}}, routes.ErrInvalidDeclaration},
		"zero claim requirement": {[]routes.Declaration{{Pattern: "GET /x", Kind: routes.KindProtect, Session: sessionSpec(func(s *routes.SessionSpec) { s.AddClaim(routes.ClaimRequirement{}) })}}, routes.ErrInvalidDeclaration},
		"unknown API kind":       {[]routes.Declaration{{Pattern: "GET /x", Kind: routes.KindProtectAPI, API: apiSpec(func(a *routes.APISpec) { a.SetKinds("root") })}}, routes.ErrInvalidDeclaration},
		"API without kinds":      {[]routes.Declaration{{Pattern: "GET /x", Kind: routes.KindProtectAPI}}, routes.ErrInvalidDeclaration},
		"session reqs on API":    {[]routes.Declaration{{Pattern: "GET /x", Kind: routes.KindProtectAPI, API: apiSpec(func(a *routes.APISpec) { a.SetKinds("pat") }), Session: sessionSpec(func(s *routes.SessionSpec) { s.RequireMFA() })}}, routes.ErrInvalidDeclaration},
		"API reqs on session":    {[]routes.Declaration{{Pattern: "GET /x", Kind: routes.KindProtect, API: apiSpec(func(a *routes.APISpec) { a.SetKinds("pat") })}}, routes.ErrInvalidDeclaration},
		"requirements on public": {[]routes.Declaration{{Pattern: "GET /x", Kind: routes.KindPublic, Session: sessionSpec(func(s *routes.SessionSpec) { s.AcceptMustChange() })}}, routes.ErrInvalidDeclaration},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validate(tc.decls...); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestProtectAPIWithModuleOff(t *testing.T) {
	var u routes.UserRoutes
	u.Add(routes.Declaration{Pattern: "GET /x", Kind: routes.KindProtectAPI, API: apiSpec(func(a *routes.APISpec) { a.SetKinds("service") })})
	if err := u.Validate(routes.Deployment{BasePath: "/auth"}); !errors.Is(err, routes.ErrInvalidDeclaration) {
		t.Fatalf("got %v", err)
	}
}

func TestValidateJoinsEveryProblem(t *testing.T) {
	err := validate(
		routes.Declaration{Pattern: "/x", Kind: routes.KindProtect},
		routes.Declaration{Pattern: "GET /auth/x", Kind: routes.KindProtect},
	)
	if !errors.Is(err, routes.ErrInvalidDeclaration) || !errors.Is(err, routes.ErrConflict) {
		t.Fatalf("got %v", err)
	}
	var u routes.UserRoutes
	if err := u.Validate(routes.Deployment{BasePath: "/auth/"}); !errors.Is(err, routes.ErrInvalidBasePath) {
		t.Fatalf("base path: %v", err)
	}
}

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func sessionAttrs(f core.ForTestAttrs) core.SessionAttrs {
	f.Lineage = uuid.MustParse("0b3a8e8a-27e6-4d8e-8f0e-6d0b7a0b6e11")
	f.Subject = core.Subject{User: uuid.MustParse("6f1c3d1e-7a51-4c55-9a43-6bde0e1f5a10")}
	f.Transport, f.CreatedAt = core.TransportCookies, now
	return core.ForTestSessionAttrs(f)
}

func TestSessionSpecCheck(t *testing.T) {
	pwd := sessionAttrs(core.ForTestAttrs{Factors: []core.Factor{core.FactorPassword}, PrimaryAt: now})
	mfa := sessionAttrs(core.ForTestAttrs{Factors: []core.Factor{core.FactorPassword, core.FactorTOTP}, PrimaryAt: now, SecondAt: now})
	stale := sessionAttrs(core.ForTestAttrs{Factors: []core.Factor{core.FactorPassword, core.FactorTOTP}, PrimaryAt: now.Add(-20 * time.Minute), SecondAt: now.Add(-20 * time.Minute)})
	change := sessionAttrs(core.ForTestAttrs{Factors: []core.Factor{core.FactorPassword}, PrimaryAt: now, MustChange: true})
	admin := routes.Claims{Roles: []string{"admin"}}
	cases := []struct {
		name string
		spec routes.SessionSpec
		a    core.SessionAttrs
		c    routes.Claims
		want error
	}{
		{"no requirement", routes.SessionSpec{}, pwd, routes.Claims{}, nil},
		{"must change refused", routes.SessionSpec{}, change, routes.Claims{}, routes.ErrMustChange},
		{"must change accepted", sessionSpec(func(s *routes.SessionSpec) { s.AcceptMustChange() }), change, routes.Claims{}, nil},
		{"MFA unmet", sessionSpec(func(s *routes.SessionSpec) { s.RequireMFA() }), pwd, routes.Claims{}, routes.ErrRequirementUnmet},
		{"MFA met", sessionSpec(func(s *routes.SessionSpec) { s.RequireMFA() }), mfa, routes.Claims{}, nil},
		{"fresh met", sessionSpec(func(s *routes.SessionSpec) { s.RequireFresh(routes.Fresh5m) }), mfa, routes.Claims{}, nil},
		{"strictest freshness applies", sessionSpec(func(s *routes.SessionSpec) { s.RequireFresh(routes.Fresh1h); s.RequireFresh(routes.Fresh15m) }), stale, routes.Claims{}, routes.ErrRequirementUnmet},
		{"factor unmet", sessionSpec(func(s *routes.SessionSpec) { s.RequireFactor(core.FactorPasskey) }), mfa, routes.Claims{}, routes.ErrRequirementUnmet},
		{"factor met", sessionSpec(func(s *routes.SessionSpec) { s.RequireFactor(core.FactorTOTP) }), mfa, routes.Claims{}, nil},
		{"role met", sessionSpec(func(s *routes.SessionSpec) {
			s.AddClaim(routes.NewClaimRequirement(routes.ClaimRoles, routes.MatchAny, "admin"))
		}), pwd, admin, nil},
		{"role unmet", sessionSpec(func(s *routes.SessionSpec) {
			s.AddClaim(routes.NewClaimRequirement(routes.ClaimRoles, routes.MatchAny, "owner"))
		}), pwd, admin, routes.ErrRequirementUnmet},
		{"invalid spec never passes", sessionSpec(func(s *routes.SessionSpec) { s.RequireFactor(core.Factor{}) }), mfa, routes.Claims{}, routes.ErrRequirementUnmet},
		{"zero attrs never pass", routes.SessionSpec{}, core.SessionAttrs{}, routes.Claims{}, routes.ErrRequirementUnmet},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.spec.Check(tc.a, tc.c, now.Add(time.Minute))
			if (tc.want == nil) != (err == nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestClaimRequirementAnyAndAll(t *testing.T) {
	c := routes.Claims{Roles: []string{"a", "b"}, Scopes: []string{"s"}, Groups: []string{"g"}}
	cases := []struct {
		r    routes.ClaimRequirement
		want bool
	}{
		{routes.NewClaimRequirement(routes.ClaimRoles, routes.MatchAny, "x", "b"), true},
		{routes.NewClaimRequirement(routes.ClaimRoles, routes.MatchAll, "a", "b"), true},
		{routes.NewClaimRequirement(routes.ClaimRoles, routes.MatchAll, "a", "x"), false},
		{routes.NewClaimRequirement(routes.ClaimScopes, routes.MatchAny, "s"), true},
		{routes.NewClaimRequirement(routes.ClaimGroups, routes.MatchAny, "a"), false},
		{routes.NewClaimRequirement(routes.ClaimGroups, routes.MatchAll, "g", ""), false},
		{routes.ClaimRequirement{}, false},
	}
	for i, tc := range cases {
		if got := tc.r.Satisfied(c); got != tc.want {
			t.Errorf("case %d: got %v", i, got)
		}
	}
}

func TestAPISpecCheck(t *testing.T) {
	a := apiSpec(func(a *routes.APISpec) {
		a.SetKinds("service", "pat")
		a.AddClaim(routes.NewClaimRequirement(routes.ClaimScopes, routes.MatchAll, "read"))
	})
	if err := a.Check("pat", routes.Claims{Scopes: []string{"read"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.Check("other", routes.Claims{Scopes: []string{"read"}}); !errors.Is(err, routes.ErrRequirementUnmet) {
		t.Fatalf("undeclared kind: %v", err)
	}
	if err := a.Check("pat", routes.Claims{}); !errors.Is(err, routes.ErrRequirementUnmet) {
		t.Fatalf("missing scope: %v", err)
	}
	if err := (routes.APISpec{}).Check("pat", routes.Claims{}); !errors.Is(err, routes.ErrRequirementUnmet) {
		t.Fatalf("zero spec: %v", err)
	}
}

func TestFreshnessDurations(t *testing.T) {
	if routes.Fresh5m.Duration() != 5*time.Minute || routes.Fresh15m.Duration() != 15*time.Minute || routes.Fresh1h.Duration() != time.Hour || routes.Freshness(0).Duration() != 0 {
		t.Fatal("freshness durations")
	}
}

func TestReservedProbesCoverEveryEndpoint(t *testing.T) {
	probes := routes.ReservedProbes("/auth")
	if len(probes) != len(routes.All())+4 {
		t.Fatalf("probes %d", len(probes))
	}
	for _, p := range probes {
		for _, c := range p {
			if c == '{' || c == '}' {
				t.Fatalf("unfilled parameter in %s", p)
			}
		}
	}
}
