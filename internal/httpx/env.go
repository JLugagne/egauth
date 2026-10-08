package httpx

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/limiter"
)

// ErrUnavailable marks an infrastructure failure (store, revocation source) behind an Env
// dependency. An Authenticator or EnrollmentReader joins it into its error so that the preamble
// answers 503 instead of 401 or 403; every other error is treated as a refusal.
var ErrUnavailable = errors.New("httpx: dependency unavailable")

// ErrIncompleteEnv is returned by Env.Validate and NewPreamble when a required dependency is nil.
var ErrIncompleteEnv = errors.New("httpx: incomplete environment")

// TenantResolver resolves the tenant of a request. An error is answered 401 with no fallback, and
// so is a zero TenantID from any resolver other than SingleTenant (DESIGN §6.10, P-08).
type TenantResolver interface {
	ResolveTenant(r *http.Request) (core.TenantID, error)
}

// Limiter charges one token of a rate-limit bucket; limiter.Limiter satisfies it. An error fails
// closed with 503.
type Limiter interface {
	Allow(ctx context.Context, key limiter.Key) (limiter.Decision, error)
}

// Authenticator resumes the session presented by a request: session.Backend.Resume.
type Authenticator interface {
	Resume(ctx context.Context, w http.ResponseWriter, r *http.Request) (session.Resumed, error)
}

// IdentifierNormalizer is identitysvc.Normalize, the only identifier normaliser; the preamble uses
// it to key the per-identifier limiter bucket.
type IdentifierNormalizer interface {
	Normalize(raw string) (identity.Identifier, error)
}

// EnrollmentReader answers the persisted MFA enrollment decision (D1) for the sensitive gate.
type EnrollmentReader interface {
	MFARequired(ctx context.Context, s core.Subject) (bool, error)
}

// Issuer is the single admission path, implemented by internal/issuance. Endpoint bodies reach the
// core producers only through it (G6).
type Issuer interface {
	// Begin starts a login journey from r's remember and return_to fields and requested transport.
	Begin(ctx context.Context, r *Request) (core.Pending, error)
	// Complete admits p with v: it starts a session or parks an MFA flow, writes credentials on w
	// and returns the response to send.
	Complete(ctx context.Context, w http.ResponseWriter, r *Request, p core.Pending, v core.Verified) (Response, error)
	// Reauthenticate refreshes the freshness of r's session with v, keeping its lineage.
	Reauthenticate(ctx context.Context, w http.ResponseWriter, r *Request, v core.Verified) (Response, error)
	// Reissue replaces r's session after c, atomically against concurrent revocation.
	Reissue(ctx context.Context, w http.ResponseWriter, r *Request, c Change) error
}

type changeKind uint8

const (
	changeFactorEnrolled changeKind = iota + 1
	changePasswordChanged
)

// Change is the security change a Reissue records. The zero Change is invalid.
type Change struct {
	kind   changeKind
	factor core.Factor
}

// FactorEnrolledChange records the enrollment of second factor f (core.FactorEnrolled).
func FactorEnrolledChange(f core.Factor) Change {
	return Change{kind: changeFactorEnrolled, factor: f}
}

// PasswordChangedChange records a password change by the session itself (core.PasswordChanged).
func PasswordChangedChange() Change {
	return Change{kind: changePasswordChanged}
}

// EnrolledFactor returns the enrolled factor, and false unless c is a FactorEnrolledChange with a
// valid factor.
func (c Change) EnrolledFactor() (core.Factor, bool) {
	return c.factor, c.kind == changeFactorEnrolled && c.factor.Valid()
}

func (c Change) PasswordChanged() bool { return c.kind == changePasswordChanged }

// EndpointCall is what the BeforeEndpoint hook sees: never the body. The captcha token is
// unexported and left out of fmt, slog and reflection-based encoders; read it with CaptchaToken.
type EndpointCall struct {
	Endpoint     string
	Client       netip.Addr
	Tenant       core.TenantID
	captchaToken string
}

// CaptchaToken returns the captcha_token field of the request; it is a client secret.
func (c EndpointCall) CaptchaToken() string { return c.captchaToken }

func (c EndpointCall) String() string {
	return "EndpointCall{Endpoint:" + c.Endpoint + " Client:" + c.Client.String() + " Tenant:" + c.Tenant.String() + "}"
}

func (c EndpointCall) GoString() string { return c.String() }

func (c EndpointCall) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("endpoint", c.Endpoint),
		slog.String("tenant", c.Tenant.String()),
	)
}

// BeforeEndpointHook is Hooks.BeforeEndpoint. An error refuses the request with 403.
type BeforeEndpointHook interface {
	BeforeEndpoint(ctx context.Context, c EndpointCall) error
}

// Audit emits library events through internal/audit.
type Audit interface {
	Emit(ctx context.Context, t event.Type, s audit.Scope, d audit.Detail, cause error, attrs ...audit.Attr) error
}

type sinkAudit struct{ sink event.Sink }

func (a sinkAudit) Emit(ctx context.Context, t event.Type, s audit.Scope, d audit.Detail, cause error, attrs ...audit.Attr) error {
	return audit.Emit(ctx, a.sink, t, s, d, cause, attrs...)
}

// SinkAudit adapts sink to Audit through audit.Emit, so the attribute registry is enforced.
func SinkAudit(sink event.Sink) Audit {
	return sinkAudit{sink: sink}
}

// Env is the single dependency seam shared by every service and filled once by the composition.
// BeforeEndpoint is the only optional member; the zero Clock reads the wall clock.
type Env struct {
	Tenants        TenantResolver
	Limiter        Limiter
	Authenticator  Authenticator
	Issuer         Issuer
	Identifiers    IdentifierNormalizer
	Enrollment     EnrollmentReader
	BeforeEndpoint BeforeEndpointHook
	Clock          clock.Clock
	Audit          Audit
}

// Validate returns ErrIncompleteEnv naming every nil required member.
func (e Env) Validate() error {
	var errs []error
	if e.Issuer == nil {
		errs = append(errs, errors.New("Issuer"))
	}
	if e.Audit == nil {
		errs = append(errs, errors.New("Audit"))
	}
	errs = append(errs, e.preambleMissing(false)...)
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(ErrIncompleteEnv, errors.Join(errs...))
}

func (e Env) preambleMissing(noRateLimit bool) []error {
	var errs []error
	if e.Tenants == nil {
		errs = append(errs, errors.New("Tenants"))
	}
	if e.Limiter == nil && !noRateLimit {
		errs = append(errs, errors.New("Limiter"))
	}
	if e.Authenticator == nil {
		errs = append(errs, errors.New("Authenticator"))
	}
	if e.Identifiers == nil {
		errs = append(errs, errors.New("Identifiers"))
	}
	if e.Enrollment == nil {
		errs = append(errs, errors.New("Enrollment"))
	}
	return errs
}
