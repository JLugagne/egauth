package routes

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/JLugagne/egauth/internal/core"
)

var (
	// ErrInvalidDeclaration is returned by UserRoutes.Validate for a declaration that cannot be
	// served safely.
	ErrInvalidDeclaration = errors.New("routes: invalid route declaration")
	// ErrMustChange is returned by SessionSpec.Check for a must-change session on a route that does not
	// accept it.
	ErrMustChange = errors.New("routes: password change required")
	// ErrRequirementUnmet is returned by SessionSpec.Check and APISpec.Check when a declared requirement
	// does not hold.
	ErrRequirementUnmet = errors.New("routes: route requirement unmet")
)

// Kind is the surface a user route is declared on. The zero Kind is invalid.
type Kind uint8

const (
	KindProtect Kind = iota + 1
	KindOptional
	KindProtectAPI
	KindPublic
)

// ClaimSet names the application-claims list a requirement reads.
type ClaimSet uint8

const (
	ClaimRoles ClaimSet = iota + 1
	ClaimScopes
	ClaimGroups
)

// Match says whether any or all values of a requirement must be held.
type Match uint8

const (
	MatchAny Match = iota + 1
	MatchAll
)

// Claims are the application claims a requirement is evaluated against.
type Claims struct {
	Roles  []string
	Scopes []string
	Groups []string
}

func (c Claims) list(s ClaimSet) []string {
	switch s {
	case ClaimRoles:
		return c.Roles
	case ClaimScopes:
		return c.Scopes
	case ClaimGroups:
		return c.Groups
	}
	return nil
}

// ClaimRequirement requires any or all of a non-empty list of claim values. The zero value is
// invalid and never satisfied.
type ClaimRequirement struct {
	set    ClaimSet
	match  Match
	values []string
}

// NewClaimRequirement builds a requirement on set. The first value is mandatory, so an empty list
// cannot be written; an empty string among the values is reported by Validate.
func NewClaimRequirement(set ClaimSet, m Match, first string, more ...string) ClaimRequirement {
	return ClaimRequirement{set: set, match: m, values: append([]string{first}, more...)}
}

func (c ClaimRequirement) validate() error {
	if c.set < ClaimRoles || c.set > ClaimGroups || (c.match != MatchAny && c.match != MatchAll) || len(c.values) == 0 {
		return errors.New("invalid claim requirement")
	}
	if slices.ContainsFunc(c.values, func(v string) bool { return strings.TrimSpace(v) == "" }) {
		return errors.New("empty claim value")
	}
	return nil
}

// Satisfied reports whether cl meets c; it is false for an invalid requirement.
func (c ClaimRequirement) Satisfied(cl Claims) bool {
	if c.validate() != nil {
		return false
	}
	held := cl.list(c.set)
	if c.match == MatchAny {
		return slices.ContainsFunc(c.values, func(v string) bool { return slices.Contains(held, v) })
	}
	return !slices.ContainsFunc(c.values, func(v string) bool { return !slices.Contains(held, v) })
}

// Freshness is a reauthentication bound a route can require. The zero Freshness is invalid.
type Freshness uint8

const (
	Fresh5m Freshness = iota + 1
	Fresh15m
	Fresh1h
)

// Duration returns the bound, or 0 for an invalid Freshness.
func (f Freshness) Duration() time.Duration {
	switch f {
	case Fresh5m:
		return 5 * time.Minute
	case Fresh15m:
		return 15 * time.Minute
	case Fresh1h:
		return time.Hour
	}
	return 0
}

// SessionSpec is the requirement set of a Protect or Optional route. Requirements accumulate; invalid
// ones are kept and reported by Validate, never dropped.
type SessionSpec struct {
	claims       []ClaimRequirement
	mfa          bool
	fresh        []Freshness
	factors      []core.Factor
	acceptChange bool
}

func (s *SessionSpec) AddClaim(c ClaimRequirement) { s.claims = append(s.claims, c) }

func (s *SessionSpec) RequireMFA() { s.mfa = true }

// RequireFresh requires authentication within f; with several, the strictest applies.
func (s *SessionSpec) RequireFresh(f Freshness) { s.fresh = append(s.fresh, f) }

func (s *SessionSpec) RequireFactor(f core.Factor) { s.factors = append(s.factors, f) }

// AcceptMustChange lets a must-change session through this route.
func (s *SessionSpec) AcceptMustChange() { s.acceptChange = true }

func (s SessionSpec) AcceptsMustChange() bool { return s.acceptChange }

func (s SessionSpec) isZero() bool {
	return len(s.claims) == 0 && !s.mfa && len(s.fresh) == 0 && len(s.factors) == 0 && !s.acceptChange
}

// Validate reports a zero factor, an invalid Freshness and an invalid claim requirement.
func (s SessionSpec) Validate() error {
	var errs []error
	for _, f := range s.factors {
		if !f.Valid() {
			errs = append(errs, errors.New("invalid factor requirement"))
		}
	}
	for _, f := range s.fresh {
		if f.Duration() == 0 {
			errs = append(errs, errors.New("invalid freshness requirement"))
		}
	}
	for _, c := range s.claims {
		if err := c.validate(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Check evaluates the requirements against an established session a with claims c at now. It
// returns ErrMustChange first, then ErrRequirementUnmet; an invalid SessionSpec never passes.
func (s SessionSpec) Check(a core.SessionAttrs, c Claims, now time.Time) error {
	if a.IsZero() || s.Validate() != nil {
		return ErrRequirementUnmet
	}
	if a.MustChangePassword() && !s.acceptChange {
		return ErrMustChange
	}
	if s.mfa && !a.MultiFactor() {
		return errors.Join(ErrRequirementUnmet, errors.New("multi-factor"))
	}
	for _, f := range s.fresh {
		if !a.FreshWithin(f.Duration(), now) {
			return errors.Join(ErrRequirementUnmet, errors.New("freshness"))
		}
	}
	for _, f := range s.factors {
		if !a.HasFactor(f) {
			return errors.Join(ErrRequirementUnmet, errors.New("factor "+f.Code()))
		}
	}
	for _, r := range s.claims {
		if !r.Satisfied(c) {
			return errors.Join(ErrRequirementUnmet, errors.New("claims"))
		}
	}
	return nil
}

// APISpec is the requirement set of a ProtectAPI route: the accepted API-key kinds and claim
// requirements only, so session-only requirements cannot be attached.
type APISpec struct {
	kinds  []string
	claims []ClaimRequirement
}

// SetKinds sets the accepted API-key kinds; the first is mandatory.
func (a *APISpec) SetKinds(kind string, more ...string) { a.kinds = append([]string{kind}, more...) }

func (a *APISpec) AddClaim(c ClaimRequirement) { a.claims = append(a.claims, c) }

func (a APISpec) Kinds() []string { return slices.Clone(a.kinds) }

func (a APISpec) isZero() bool { return len(a.kinds) == 0 && len(a.claims) == 0 }

// Validate reports no kind, a kind outside declared (APIKeyModule.Kinds) and an invalid claim
// requirement.
func (a APISpec) Validate(declared []string) error {
	var errs []error
	if len(a.kinds) == 0 {
		errs = append(errs, errors.New("no API key kind"))
	}
	for _, k := range a.kinds {
		if k == "" || !slices.Contains(declared, k) {
			errs = append(errs, errors.New("undeclared API key kind "+k))
		}
	}
	for _, c := range a.claims {
		if err := c.validate(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Check evaluates the requirements against a key of kind with effective claims c.
func (a APISpec) Check(kind string, c Claims) error {
	if len(a.kinds) == 0 || !slices.Contains(a.kinds, kind) {
		return errors.Join(ErrRequirementUnmet, errors.New("API key kind"))
	}
	for _, r := range a.claims {
		if r.validate() != nil || !r.Satisfied(c) {
			return errors.Join(ErrRequirementUnmet, errors.New("claims"))
		}
	}
	return nil
}

// Declaration is one user route: a "METHOD /path" pattern, its surface and its requirements.
// Session applies to Protect and Optional, API to ProtectAPI, and Public carries neither.
type Declaration struct {
	Pattern string
	Kind    Kind
	Session SessionSpec
	API     APISpec
}

// Deployment is what UserRoutes.Validate checks declarations against.
type Deployment struct {
	BasePath string
	// APIKinds is APIKeyModule.Kinds.
	APIKinds []string
	// APIKeys reports whether Modules.APIKeys is enabled; ProtectAPI is refused when it is not.
	APIKeys bool
}

// UserRoutes is the core of the deny-by-default route builder: it collects declarations and
// validates them all at once.
type UserRoutes struct {
	decls []Declaration
}

func (u *UserRoutes) Add(d Declaration) { u.decls = append(u.decls, d) }

// Declarations returns a copy of the declarations in insertion order.
func (u UserRoutes) Declarations() []Declaration { return slices.Clone(u.decls) }

var allowedMethods = []string{
	http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions,
}

// Validate returns every problem joined: a pattern with no method, a host or an unparsable path; a
// pattern that overlaps BasePath, the discovery document or another declaration; a requirement set
// that does not fit the surface or is invalid; ProtectAPI with the APIKeys module off or with an
// undeclared kind (ErrInvalidDeclaration, ErrConflict, ErrInvalidBasePath).
func (u UserRoutes) Validate(d Deployment) error {
	if err := ValidateBasePath(d.BasePath); err != nil {
		return err
	}
	var errs []error
	var registered []string
	all := http.NewServeMux()
	for _, decl := range u.decls {
		if err := decl.validate(d); err != nil {
			errs = append(errs, errors.Join(ErrInvalidDeclaration, errors.New(decl.Pattern), err))
			continue
		}
		if err := overlapsReserved(decl.Pattern, d.BasePath); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := register(all, decl.Pattern, http.NotFoundHandler()); err != nil {
			errs = append(errs, err)
			continue
		}
		for _, prev := range registered {
			if patternsOverlap(prev, decl.Pattern) {
				errs = append(errs, errors.Join(ErrConflict, errors.New(decl.Pattern+" overlaps "+prev)))
			}
		}
		registered = append(registered, decl.Pattern)
	}
	return errors.Join(errs...)
}

func patternsOverlap(a, b string) bool {
	return probeMatchesBoth(a, b) || probeMatchesBoth(b, a)
}

type probeTarget struct{}

func (*probeTarget) ServeHTTP(http.ResponseWriter, *http.Request) {}

func probeMatchesBoth(from, into string) bool {
	fromMux, intoMux := http.NewServeMux(), http.NewServeMux()
	fromTarget, intoTarget := &probeTarget{}, &probeTarget{}
	if register(fromMux, from, fromTarget) != nil || register(intoMux, into, intoTarget) != nil {
		return true
	}
	_, path, _ := strings.Cut(from, " ")
	probe := fillParams(path)
	for _, p := range []string{probe, probe + "x", probe + "/x"} {
		for _, m := range allowedMethods {
			req, err := http.NewRequest(m, "http://probe.invalid"+p, nil)
			if err != nil {
				return true
			}
			fromHandler, _ := fromMux.Handler(req)
			intoHandler, _ := intoMux.Handler(req)
			if fromHandler == http.Handler(fromTarget) && intoHandler == http.Handler(intoTarget) {
				return true
			}
		}
	}
	return false
}

func (decl Declaration) validate(d Deployment) error {
	method, path, ok := strings.Cut(decl.Pattern, " ")
	if !ok || !slices.Contains(allowedMethods, method) || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \t") {
		return errors.New("pattern must be \"METHOD /path\" with no host")
	}
	switch decl.Kind {
	case KindProtect, KindOptional:
		if !decl.API.isZero() {
			return errors.New("API requirements on a session route")
		}
		return decl.Session.Validate()
	case KindProtectAPI:
		if !d.APIKeys {
			return errors.New("ProtectAPI needs the APIKeys module")
		}
		if !decl.Session.isZero() {
			return errors.New("session requirements on an API route")
		}
		return decl.API.Validate(d.APIKinds)
	case KindPublic:
		if !decl.Session.isZero() || !decl.API.isZero() {
			return errors.New("requirements on a public route")
		}
		return nil
	}
	return errors.New("invalid route kind")
}

// ReservedProbes returns the request paths a user pattern must never match: BasePath itself, every
// registry endpoint under it (parameters filled), an arbitrary path under it, and the discovery
// document.
func ReservedProbes(basePath string) []string {
	out := []string{basePath, basePath + "/", basePath + "/zz-unregistered", WellKnown}
	for _, p := range All() {
		out = append(out, basePath+fillParams(p))
	}
	return out
}

func fillParams(p string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(p, '{')
		if i < 0 {
			b.WriteString(p)
			return b.String()
		}
		j := strings.IndexByte(p[i:], '}')
		if j < 0 {
			b.WriteString(p)
			return b.String()
		}
		b.WriteString(p[:i])
		if p[i:i+j+1] != "{$}" {
			b.WriteString("x")
		}
		p = p[i+j+1:]
	}
}

func underBase(path, basePath string) string {
	base := strings.Split(strings.TrimPrefix(basePath, "/"), "/")
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	out := slices.Clone(base)
	for i, s := range segs {
		if i < len(base) {
			continue
		}
		if strings.HasPrefix(s, "{") {
			s = "x"
		}
		out = append(out, s)
	}
	return "/" + strings.Join(out, "/")
}

func overlapsReserved(pattern, basePath string) error {
	mux := http.NewServeMux()
	if err := register(mux, pattern, http.NotFoundHandler()); err != nil {
		return errors.Join(ErrInvalidDeclaration, err)
	}
	_, path, _ := strings.Cut(pattern, " ")
	for _, probe := range append(ReservedProbes(basePath), underBase(path, basePath)) {
		for _, m := range allowedMethods {
			req, err := http.NewRequest(m, "http://probe.invalid"+probe, nil)
			if err != nil {
				return errors.Join(ErrInvalidBasePath, err)
			}
			if _, matched := mux.Handler(req); matched != "" {
				return errors.Join(ErrConflict, errors.New(pattern+" overlaps "+probe))
			}
		}
	}
	return nil
}
