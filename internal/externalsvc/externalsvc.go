// Package externalsvc owns the application-verified primary factor (DESIGN §5.6): POST
// /external/{name}/login asks the named Verifier to check the identifier and secret, maps the
// ExternalID it vouches for to an account through the federation store as provider
// "external:<name>", creates accounts only under the registration rules and never links an
// existing one (D6, federationsvc.Directory), and ends in the single admission path,
// httpx.Issuer.Complete, with the ext factor, so the MFA decision and the account state apply.
package externalsvc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"regexp"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/federationsvc"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	storefed "github.com/JLugagne/egauth/store/federation"
)

const (
	redacted = "REDACTED"
	pathName = "name"
)

var namePattern = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

var (
	// ErrInvalidConfig is returned by New, joined with one error per missing or invalid member.
	ErrInvalidConfig = errors.New("externalsvc: invalid service configuration")
	// ErrNilIssuer is returned by Endpoints for a nil issuer.
	ErrNilIssuer = errors.New("externalsvc: nil issuer")
)

// The problems /external/{name}/login answers besides those of httpx and federationsvc.Directory.
var (
	ErrUnknownVerifier = httpx.NewProblem(http.StatusNotFound, "unknown_provider")
	// ErrInvalidCredentials answers every refusal of the Verifier and every unusable answer of it,
	// whatever the cause, so the response never tells which part was wrong.
	ErrInvalidCredentials = httpx.NewProblem(http.StatusUnauthorized, "invalid_credentials")
)

// Request is what a Verifier checks: the identifier and secret fields of the login request. fmt and
// slog render Secret as REDACTED.
type Request struct {
	Tenant     core.TenantID
	Identifier string
	Secret     string
}

func (r Request) String() string {
	return "externalsvc.Request{Tenant: " + r.Tenant.String() + ", Identifier: " + r.Identifier + ", Secret: " + redacted + "}"
}

func (r Request) GoString() string { return r.String() }

func (r Request) LogValue() slog.Value {
	return slog.GroupValue(slog.String("tenant", r.Tenant.String()), slog.String("identifier", r.Identifier),
		slog.String("secret", redacted))
}

// Identity is the account a Verifier vouches for. ExternalID is stable for the account at the
// source; Email becomes the account email of a new account only when EmailVerified.
type Identity struct {
	ExternalID    string
	Email         string
	EmailVerified bool
}

// Verifier is one application-verified primary factor; the composition adapts
// egauth.ExternalFactor to it. Name is a token of 1 to 32 characters of [a-z0-9_-]. Verify returns
// an error for credentials it refuses; it must be safe for concurrent use and never log Secret.
type Verifier interface {
	Name() string
	Verify(ctx context.Context, req Request) (Identity, error)
}

// Config is what New needs; every member is required and the zero Clock reads the wall clock.
type Config struct {
	Verifiers []Verifier
	// Directory maps the vouched identity to an account under the registration rules
	// (federationsvc.NewDirectory with the federation store, so links share one namespace).
	Directory *federationsvc.Directory
	Clock     clock.Clock
	Audit     httpx.Audit
}

// Service serves /external/{name}/login. It is safe for concurrent use.
type Service struct {
	verifiers map[string]Verifier
	directory *federationsvc.Directory
	clock     clock.Clock
	audit     httpx.Audit
}

// New validates cfg, reporting every problem at once as ErrInvalidConfig joined with the member
// names: no verifier, a nil one, a name that is not a token, or two sharing a name.
func New(cfg Config) (*Service, error) {
	var errs []error
	if len(cfg.Verifiers) == 0 {
		errs = append(errs, errors.New("Verifiers"))
	}
	if cfg.Directory == nil {
		errs = append(errs, errors.New("Directory"))
	}
	if !present(cfg.Audit) {
		errs = append(errs, errors.New("Audit"))
	}
	byName := make(map[string]Verifier, len(cfg.Verifiers))
	for _, v := range cfg.Verifiers {
		if !present(v) {
			errs = append(errs, errors.Join(errors.New("Verifiers"), errors.New("nil verifier")))
			continue
		}
		name := v.Name()
		if !namePattern.MatchString(name) {
			errs = append(errs, errors.New("Verifiers: name "+name+" is not a token"))
			continue
		}
		if _, dup := byName[name]; dup {
			errs = append(errs, errors.New("Verifiers: duplicate name "+name))
			continue
		}
		byName[name] = v
	}
	if len(errs) > 0 {
		return nil, errors.Join(ErrInvalidConfig, errors.Join(errs...))
	}
	return &Service{verifiers: byName, directory: cfg.Directory, clock: cfg.Clock, audit: cfg.Audit}, nil
}

// Endpoints returns /external/{name}/login served through issuer. It returns ErrNilIssuer or the
// error of routes.NewEndpoint.
//
// The endpoint seals the Pending of issuer.Begin before calling the Verifier, answers
// ErrInvalidCredentials for any refusal, signs the vouched identity in through
// federationsvc.Directory.SignIn as provider "external:<name>" (never linking an existing account)
// and ends in issuer.Complete with the ext factor.
func (s *Service) Endpoints(issuer httpx.Issuer) ([]routes.Endpoint, error) {
	if issuer == nil {
		return nil, ErrNilIssuer
	}
	h := &handlers{Service: s, issuer: issuer}
	ep, err := routes.NewEndpoint(routes.ExternalLogin, h.login)
	if err != nil {
		return nil, err
	}
	return []routes.Endpoint{ep}, nil
}

type handlers struct {
	*Service
	issuer httpx.Issuer
}

func present(v any) bool {
	if v == nil {
		return false
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return !rv.IsNil()
	}
	return true
}

func (h *handlers) login(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	name := r.HTTP().PathValue(pathName)
	v, ok := h.verifiers[name]
	if !ok {
		r.Fail(w, ErrUnknownVerifier)
		return
	}
	p, err := h.issuer.Begin(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	id, err := v.Verify(ctx, Request{Tenant: r.Tenant(), Identifier: r.Field(routes.FieldIdentifier), Secret: r.Field(routes.FieldPassword)})
	if err != nil || id.ExternalID == "" {
		_ = h.audit.Emit(ctx, event.LoginFailed, audit.Scope{TenantID: r.Tenant().String()}, audit.Detail{Reason: ErrInvalidCredentials.Code()}, nil,
			audit.A(event.KeyProvider, factors.ExternalProviderPrefix+name))
		r.Fail(w, ErrInvalidCredentials)
		return
	}
	sub, err := h.directory.SignIn(ctx, r.Tenant(), federationsvc.ProviderIdentity{
		Provider: factors.ExternalProviderPrefix + name, Subject: id.ExternalID, Authority: storefed.StaticAuthority,
		Email: id.Email, EmailVerified: id.EmailVerified,
	})
	if err != nil {
		r.Fail(w, err)
		return
	}
	verified, err := factors.External(sub, name, h.clock.Now())
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	resp, err := h.issuer.Complete(ctx, w, r, p, verified)
	if err != nil {
		r.Fail(w, err)
		return
	}
	r.RespondPending(w, p, resp)
}
