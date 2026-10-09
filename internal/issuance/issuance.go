// Package issuance is the single admission path (DESIGN §5). It implements httpx.Issuer and is the
// only caller of the core producers (NewPending, PendingForReauth, Pending.Add, Admit,
// Reauthenticate, FactorEnrolled, PasswordChanged) and, through Enrollment, of NewMFADecision (G6).
// Every primary endpoint ends in Complete, which reads the account state and the persisted MFA
// enrollment itself, so no endpoint can forget the MFA gate (T-07, I-03, I-05) and no caller can
// hand it a weaker decision. A login that still needs a second factor never yields a session
// credential: it is parked as an MFAFlow record that only internal/flow consumes (T-01, I-06).
package issuance

import (
	"context"
	"errors"
	"net/http"
	"reflect"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/store/ceremony"
)

// The states a journey step answers in its "state" member.
const (
	StateAuthenticated   = "authenticated"
	StateMFARequired     = "mfa_required"
	StateReauthenticated = "reauthenticated"
)

var (
	// ErrInvalidConfig is returned by New and NewEnrollment, joined with one error per problem.
	ErrInvalidConfig = errors.New("issuance: invalid configuration")
	// ErrAuthUnavailable answers a login whose MFA enrollment could not be read (DESIGN §5.2): it
	// fails closed and never admits.
	ErrAuthUnavailable = httpx.NewProblem(http.StatusServiceUnavailable, "auth_unavailable")
	// ErrClaimsUnavailable answers a login whose application claims could not be fetched or are
	// too large (DESIGN §4.4): no session is started.
	ErrClaimsUnavailable = httpx.NewProblem(http.StatusServiceUnavailable, "claims_unavailable")
	// ErrInvalidReturnTo answers a return_to that internal/redirect refuses.
	ErrInvalidReturnTo = httpx.NewProblem(http.StatusBadRequest, "invalid_return_to")
)

// Accounts answers the authoritative account state; identitysvc.Service satisfies it. A store
// failure must be joined with httpx.ErrUnavailable.
type Accounts interface {
	AccountState(ctx context.Context, s core.Subject) (core.AccountState, error)
}

// Claims fetches the application claims at admission with the policy of DESIGN §4.4;
// session.Renewer satisfies it.
type Claims interface {
	FetchClaims(ctx context.Context, s core.Subject) (core.SealedClaims, error)
}

// FlowWriter stores the MFAFlow record of a parked login; ceremony.Store satisfies it. Issuance
// only writes flows: reading them is internal/flow's alone (T-06).
type FlowWriter interface {
	Put(ctx context.Context, r ceremony.Record) (evicted int, err error)
}

// OriginResolver returns the redirect origins of a tenant (its expanded public origin and the extra
// origins), against which return_to and the configured pages are validated.
type OriginResolver interface {
	Origins(t core.TenantID) (redirect.Origins, error)
}

// Completer reports whether the deployment serves an endpoint that completes second factor f;
// flow.Service satisfies it, so the factors offered to a parked login are exactly those its
// endpoints accept.
type Completer interface {
	Completes(f core.Factor) bool
}

// Pages are the application pages a cookie-transport browser is sent to with a 303: AfterLogin when
// a login completes without return_to, MFA when it is parked, Reauth when /reauth still needs a
// second factor. Each is optional and, when set, a path-absolute reference on the public origin:
// New refuses any other value through internal/redirect, so no login can fail on a page later.
type Pages struct {
	AfterLogin string
	MFA        string
	Reauth     string
}

// Config is what New needs. Every member is required except Pages and Clock, whose zero value
// reads the wall clock.
type Config struct {
	Accounts   Accounts
	Enrollment *Enrollment
	Backend    session.Backend
	Claims     Claims
	Flows      FlowWriter
	Completer  Completer
	Cookies    cookie.Policy
	Origins    OriginResolver
	RememberMe core.RememberMePolicy
	Pages      Pages
	Clock      clock.Clock
	Audit      httpx.Audit
}

// Issuer is the httpx.Issuer of the deployment. It is immutable and safe for concurrent use.
type Issuer struct {
	accounts   Accounts
	enrollment *Enrollment
	backend    session.Backend
	claims     Claims
	flows      FlowWriter
	completer  Completer
	cookies    cookie.Policy
	origins    OriginResolver
	remember   core.RememberMePolicy
	pages      Pages
	clock      clock.Clock
	audit      httpx.Audit
}

var _ httpx.Issuer = (*Issuer)(nil)

// New validates cfg and reports every problem at once as ErrInvalidConfig joined with the member
// names; a typed nil counts as missing.
func New(cfg Config) (*Issuer, error) {
	var errs []error
	need := func(ok bool, name string) {
		if !ok {
			errs = append(errs, errors.New(name))
		}
	}
	need(present(cfg.Accounts), "Accounts")
	need(cfg.Enrollment != nil, "Enrollment")
	need(present(cfg.Backend), "Backend")
	need(present(cfg.Claims), "Claims")
	need(present(cfg.Flows), "Flows")
	need(present(cfg.Completer), "Completer")
	need(cfg.Cookies != (cookie.Policy{}), "Cookies")
	need(present(cfg.Origins), "Origins")
	need(validRemember(cfg.RememberMe), "RememberMe")
	need(present(cfg.Audit), "Audit")
	errs = append(errs, validPages(cfg.Pages)...)
	if len(errs) > 0 {
		return nil, errors.Join(ErrInvalidConfig, errors.Join(errs...))
	}
	return &Issuer{
		accounts:   cfg.Accounts,
		enrollment: cfg.Enrollment,
		backend:    cfg.Backend,
		claims:     cfg.Claims,
		flows:      cfg.Flows,
		completer:  cfg.Completer,
		cookies:    cfg.Cookies,
		origins:    cfg.Origins,
		remember:   cfg.RememberMe,
		pages:      cfg.Pages,
		clock:      cfg.Clock,
		audit:      cfg.Audit,
	}, nil
}

const pagesOrigin = "https://pages.invalid"

func validPages(p Pages) []error {
	o, err := redirect.NewOrigins(pagesOrigin, nil)
	if err != nil {
		return []error{errors.Join(errors.New("Pages"), err)}
	}
	var errs []error
	for _, page := range []struct{ name, raw string }{{"AfterLogin", p.AfterLogin}, {"MFA", p.MFA}, {"Reauth", p.Reauth}} {
		if _, err := redirect.Parse(page.raw, o); err != nil {
			errs = append(errs, errors.Join(errors.New("Pages."+page.name), err))
		}
	}
	return errs
}

func validRemember(p core.RememberMePolicy) bool {
	return p == core.RememberUserChoice || p == core.RememberAlways || p == core.RememberNever
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

func (i *Issuer) state(ctx context.Context, s core.Subject) (core.AccountState, error) {
	st, err := i.accounts.AccountState(ctx, s)
	if err != nil {
		return core.AccountState{}, errors.Join(httpx.ErrServiceUnavailable, err)
	}
	return st, nil
}

func (i *Issuer) decision(ctx context.Context, s core.Subject) (core.MFADecision, error) {
	d, err := i.enrollment.enrolled(ctx, s)
	if err != nil {
		return core.MFADecision{}, errors.Join(ErrAuthUnavailable, err)
	}
	return d, nil
}

func (i *Issuer) target(t core.TenantID, raw string) (tg redirect.Target, err error) {
	if raw == "" {
		return tg, nil
	}
	o, err := i.origins.Origins(t)
	if err != nil {
		return tg, errors.Join(httpx.ErrInternal, err)
	}
	tg, err = redirect.Parse(raw, o)
	if err != nil {
		return tg, errors.Join(ErrInvalidReturnTo, err)
	}
	return tg, nil
}

func (i *Issuer) landing(t core.TenantID, returnTo, page string) (redirect.Target, error) {
	raw := returnTo
	if raw == "" {
		raw = page
	}
	tg, err := i.target(t, raw)
	if err != nil {
		return tg, errors.Join(httpx.ErrInternal, err)
	}
	return tg, nil
}

func (i *Issuer) clearSession(w http.ResponseWriter, r *httpx.Request, t core.Transport) {
	if t != core.TransportCookies && !cookie.Present(r.HTTP()) {
		return
	}
	for _, n := range []cookie.Name{cookie.AccessToken, cookie.RefreshToken, cookie.StatefulSession} {
		i.cookies.Clear(w, n)
	}
}

func (i *Issuer) offered(needs []core.Factor, accepted ...core.Factor) []core.Factor {
	var out []core.Factor
	for _, f := range accepted {
		for _, n := range needs {
			if n == f && i.completer.Completes(f) {
				out = append(out, f)
			}
		}
	}
	return out
}

var flowFactors = []core.Factor{core.FactorTOTP, core.FactorRecoveryCode, core.FactorPasskeyStepUp}

var reauthFactors = []core.Factor{core.FactorTOTP, core.FactorRecoveryCode, core.FactorPasskeyStepUp}

func factorNames(fs []core.Factor) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		switch f {
		case core.FactorTOTP:
			out = append(out, "totp")
		case core.FactorRecoveryCode:
			out = append(out, "recovery_code")
		case core.FactorPasskeyStepUp:
			out = append(out, "passkey")
		}
	}
	return out
}

func factorCodes(fs []core.Factor) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Code()
	}
	return out
}

func primaryCode(fs []core.Factor) string {
	for _, f := range fs {
		if f.Role() == core.RolePrimary {
			return f.Code()
		}
	}
	return ""
}

func unavailable(err error) error {
	return errors.Join(httpx.ErrServiceUnavailable, err)
}
