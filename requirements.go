package egauth

import (
	"slices"

	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/principal"
)

// RouteOption is a requirement of a Protect or Optional route: a ClaimRequirement or a
// SessionRequirement.
type RouteOption interface {
	applySession(s *routes.SessionSpec)
}

// APIRouteOption is a requirement of a ProtectAPI route: a ClaimRequirement only, so a session-only
// requirement cannot be attached to an API-key route.
type APIRouteOption interface {
	applyAPI(a *routes.APISpec)
}

// ClaimRequirement requires roles, scopes or groups of the principal's current claims. It is both a
// RouteOption and an APIRouteOption. The zero value is invalid and fails Build.
type ClaimRequirement struct {
	r routes.ClaimRequirement
}

func (c ClaimRequirement) applySession(s *routes.SessionSpec) { s.AddClaim(c.r) }

func (c ClaimRequirement) applyAPI(a *routes.APISpec) { a.AddClaim(c.r) }

func claimRequirement(set routes.ClaimSet, m routes.Match, first string, more []string) ClaimRequirement {
	return ClaimRequirement{r: routes.NewClaimRequirement(set, m, first, slices.Clone(more)...)}
}

// RequireAnyRole requires at least one of the roles; Build rejects a blank role.
func RequireAnyRole(role string, more ...string) ClaimRequirement {
	return claimRequirement(routes.ClaimRoles, routes.MatchAny, role, more)
}

// RequireAllRoles requires every one of the roles; Build rejects a blank role.
func RequireAllRoles(role string, more ...string) ClaimRequirement {
	return claimRequirement(routes.ClaimRoles, routes.MatchAll, role, more)
}

// RequireAnyScope requires at least one of the scopes; Build rejects a blank scope.
func RequireAnyScope(scope string, more ...string) ClaimRequirement {
	return claimRequirement(routes.ClaimScopes, routes.MatchAny, scope, more)
}

// RequireAllScopes requires every one of the scopes; Build rejects a blank scope.
func RequireAllScopes(scope string, more ...string) ClaimRequirement {
	return claimRequirement(routes.ClaimScopes, routes.MatchAll, scope, more)
}

// RequireAnyGroup requires at least one of the groups; Build rejects a blank group.
func RequireAnyGroup(group string, more ...string) ClaimRequirement {
	return claimRequirement(routes.ClaimGroups, routes.MatchAny, group, more)
}

// RequireAllGroups requires every one of the groups; Build rejects a blank group.
func RequireAllGroups(group string, more ...string) ClaimRequirement {
	return claimRequirement(routes.ClaimGroups, routes.MatchAll, group, more)
}

type sessionRequirementKind uint8

const (
	requireMFA sessionRequirementKind = iota + 1
	requireFresh
	requireFactor
	acceptMustChange
)

// SessionRequirement is a requirement only a session can meet, so it is a RouteOption and not an
// APIRouteOption. The zero value is invalid and fails Build.
type SessionRequirement struct {
	kind   sessionRequirementKind
	fresh  Freshness
	factor principal.Factor
}

func (r SessionRequirement) applySession(s *routes.SessionSpec) {
	switch r.kind {
	case requireMFA:
		s.RequireMFA()
	case requireFresh:
		s.RequireFresh(r.fresh)
	case requireFactor:
		s.RequireFactor(r.factor)
	case acceptMustChange:
		s.AcceptMustChange()
	default:
		s.RequireFactor(principal.Factor{})
	}
}

// RequireMFA requires a session that completed a second factor.
func RequireMFA() SessionRequirement {
	return SessionRequirement{kind: requireMFA}
}

// RequireFreshAuth requires a session authenticated within f; with several, the strictest
// applies. Build rejects the zero Freshness.
func RequireFreshAuth(f Freshness) SessionRequirement {
	return SessionRequirement{kind: requireFresh, fresh: f}
}

// RequireFactor requires a session that verified f; Build rejects the zero Factor.
func RequireFactor(f principal.Factor) SessionRequirement {
	return SessionRequirement{kind: requireFactor, factor: f}
}

// AcceptMustChange lets a session whose password must change through; by default such a session
// gets 403 on Protect and is anonymous on Optional.
func AcceptMustChange() SessionRequirement {
	return SessionRequirement{kind: acceptMustChange}
}

// Freshness is a reauthentication bound a route can require. The zero Freshness is invalid.
type Freshness = routes.Freshness

// Freshness bounds.
const (
	Fresh5m  = routes.Fresh5m
	Fresh15m = routes.Fresh15m
	Fresh1h  = routes.Fresh1h
)

// APIKinds is the non-empty set of API-key kinds a ProtectAPI route accepts; every kind must be
// declared in APIKeyModule.Kinds. Build it with Kinds; the zero value fails Build.
type APIKinds struct {
	kinds []string
}

// Kinds returns the API-key kinds a ProtectAPI route accepts.
func Kinds(kind string, more ...string) APIKinds {
	return APIKinds{kinds: append([]string{kind}, more...)}
}
