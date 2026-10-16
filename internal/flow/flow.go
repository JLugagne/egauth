// Package flow serves the second step of the single MFA handshake (DESIGN §5.1 step 3) and /reauth
// (§5.3). It is the only reader of the MFAFlow ceremony kind and of the flow cookie (T-06, I-01,
// W-06): no session gate, /session or other endpoint ever looks at a parked login, so a flow handle
// can never authenticate. A parked login completes only through issuance.Complete with the Pending
// sealed in its record, after the record is consumed exactly once.
package flow

import (
	"context"
	"errors"
	"net/http"
	"reflect"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/passkeysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/ceremony"
)

var (
	// ErrInvalidConfig is returned by New, joined with one error per missing member.
	ErrInvalidConfig = errors.New("flow: invalid configuration")
	ErrNilIssuer     = errors.New("flow: nil issuer")
)

// The problems the flow endpoints answer besides those of httpx and of the factor services.
var (
	// ErrInvalidFlow answers a missing, malformed, expired, consumed or foreign flow handle, or one
	// presented on another transport than the one sealed in its flow.
	ErrInvalidFlow = httpx.NewProblem(http.StatusUnauthorized, "invalid_flow")
	// ErrReauthUnavailable answers a password /reauth on a deployment without the password module.
	ErrReauthUnavailable = httpx.NewProblem(http.StatusBadRequest, "reauth_method_unavailable")
)

// Flows reads and consumes MFAFlow records; ceremony.Store satisfies it.
type Flows interface {
	Peek(ctx context.Context, t principal.TenantID, k ceremony.Kind, handleHash []byte) (ceremony.Record, error)
	Consume(ctx context.Context, t principal.TenantID, k ceremony.Kind, handleHash []byte) (ceremony.Record, error)
	RecordFailure(ctx context.Context, t principal.TenantID, k ceremony.Kind, handleHash []byte) (remaining int, err error)
}

// SecondFactors is mfasvc.Service.Verify, the only TOTP and recovery-code check: it charges the
// per-subject lockouts and the step-replay guard shared by the flow, /reauth, confirm and disable
// (C-40, I-22).
type SecondFactors interface {
	Verify(ctx context.Context, sub core.Subject, f core.Factor, code string) (core.Verified, error)
}

// StepUp is the passkey ceremony of passkeysvc.Service bound to a subject, always with user
// verification: FinishStepUp yields pk_stepup for a parked login, refused by Pending.Add when it is
// the primary passkey's credential (C-28); FinishReauth yields pk and uv for a /reauth begun from
// issuance's reauthentication Pending.
type StepUp interface {
	BeginStepUp(ctx context.Context, p core.Pending) (passkeysvc.StepUpChallenge, error)
	FinishStepUp(ctx context.Context, t core.TenantID, handle string, assertionJSON []byte) (core.Pending, core.Verified, error)
	FinishReauth(ctx context.Context, t core.TenantID, handle string, assertionJSON []byte) (core.Pending, core.Verified, error)
}

// Passwords checks the password of a known subject for /reauth, with the login lockout;
// identitysvc.Service satisfies it. It must refuse a subject without a stored password. Its error
// is answered as is: an httpx problem (401 for a refused password, 503 for an outage) keeps its
// status, anything else is 500.
type Passwords interface {
	CheckPassword(ctx context.Context, s core.Subject, password string) error
}

// Issuer is the admission path the flow ends in; issuance.Issuer satisfies it.
type Issuer interface {
	Complete(ctx context.Context, w http.ResponseWriter, r *httpx.Request, p core.Pending, v core.Verified) (httpx.Response, error)
	BeginReauth(ctx context.Context, r *httpx.Request) (core.Pending, error)
	Reauthenticate(ctx context.Context, w http.ResponseWriter, r *httpx.Request, v core.Verified) (httpx.Response, error)
	ReauthenticateAll(ctx context.Context, w http.ResponseWriter, r *httpx.Request, vs []core.Verified) (httpx.Response, error)
}

// Config is what New needs. Flows, Cookies and Audit are required. SecondFactors, StepUp and
// Passwords are present exactly when the MFA, Passkey and Password modules are enabled; their
// presence alone decides which factors Completes reports, so the factors offered to a parked login
// and the endpoints served cannot disagree. The zero Clock reads the wall clock.
type Config struct {
	Flows         Flows
	Cookies       cookie.Policy
	SecondFactors SecondFactors
	StepUp        StepUp
	Passwords     Passwords
	Clock         clock.Clock
	Audit         httpx.Audit
}

// Service serves the MFA flow and /reauth. It is immutable and safe for concurrent use.
type Service struct {
	flows     Flows
	cookies   cookie.Policy
	second    SecondFactors
	stepUp    StepUp
	passwords Passwords
	clock     clock.Clock
	audit     httpx.Audit
}

// New validates cfg and reports every missing required member at once as ErrInvalidConfig joined
// with the member names; a typed nil counts as missing, and a typed nil optional member as absent.
func New(cfg Config) (*Service, error) {
	var errs []error
	need := func(ok bool, name string) {
		if !ok {
			errs = append(errs, errors.New(name))
		}
	}
	need(present(cfg.Flows), "Flows")
	need(cfg.Cookies != (cookie.Policy{}), "Cookies")
	need(present(cfg.Audit), "Audit")
	if len(errs) > 0 {
		return nil, errors.Join(ErrInvalidConfig, errors.Join(errs...))
	}
	s := &Service{flows: cfg.Flows, cookies: cfg.Cookies, clock: cfg.Clock, audit: cfg.Audit}
	if present(cfg.SecondFactors) {
		s.second = cfg.SecondFactors
	}
	if present(cfg.StepUp) {
		s.stepUp = cfg.StepUp
	}
	if present(cfg.Passwords) {
		s.passwords = cfg.Passwords
	}
	return s, nil
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

// Completes reports whether a served endpoint completes second factor f: totp and recovery_code
// through /mfa/challenge and /reauth with SecondFactors, pk_stepup through /mfa/passkey/* and the
// passkey /reauth with StepUp.
func (s *Service) Completes(f core.Factor) bool {
	switch f {
	case core.FactorTOTP, core.FactorRecoveryCode:
		return s.second != nil
	case core.FactorPasskeyStepUp:
		return s.stepUp != nil
	}
	return false
}

// Endpoints returns /reauth, plus /mfa/challenge with SecondFactors and /mfa/passkey/begin and
// /mfa/passkey/finish with StepUp, all served through issuer. It returns ErrNilIssuer or the error
// of routes.NewEndpoint.
//
// Their guarantees:
//   - The flow handle is read from the "flow" field under Bearer and from the flow cookie under
//     cookies; a handle presented on the other transport than the one sealed in its flow is refused
//     with ErrInvalidFlow.
//   - /mfa/challenge requires an explicit factor ("totp" or "recovery_code"; anything else is 400
//     invalid_factor, so a TOTP typo never burns a recovery code) and verifies it through
//     SecondFactors for the subject sealed in the flow. A failed code also charges the flow record,
//     which dies after ceremony.MFAFlow.MaxAttempts; the per-subject lockout stays the bound.
//   - /mfa/passkey/begin returns {state, options, handle} for a step-up bound to the flow's subject;
//     /mfa/passkey/finish verifies the assertion, which must come from this flow, with a
//     credential other than the primary passkey of the flow.
//   - On success the flow record is consumed exactly once, the flow cookie cleared, and the sealed
//     Pending plus the new factor go to issuer.Complete, which issues the session (or refuses it
//     when the account or epoch changed meanwhile).
//   - /reauth needs an established session and reauthenticates it on its own lineage through
//     issuer. With "factor":"passkey" (StepUp present) one assertion with user verification
//     suffices (DESIGN §5.3), so neither a password nor the Password module is needed: without
//     "handle" it answers {state:"passkey_challenge", options, handle} for the session's subject;
//     with "handle" and the assertion in the same JSON body it verifies pk+uv for that very session
//     (and "password" too when sent). Otherwise it checks "password" (Passwords present, else 400
//     reauth_method_unavailable), then, when "factor" is "totp" or "recovery_code", that second
//     factor. A password alone never refreshes secondAt (C-44): an enrolled subject gets
//     {"state":"mfa_required","factors"} and its session is unchanged.
func (s *Service) Endpoints(issuer Issuer) ([]routes.Endpoint, error) {
	if !present(issuer) {
		return nil, ErrNilIssuer
	}
	h := &handlers{Service: s, issuer: issuer}
	fns := []served{{routes.Reauth, h.reauth}}
	if s.second != nil {
		fns = append(fns, served{routes.MFAChallenge, h.challenge})
	}
	if s.stepUp != nil {
		fns = append(fns, served{routes.MFAPasskeyBegin, h.passkeyBegin}, served{routes.MFAPasskeyFinish, h.passkeyFinish})
	}
	out := make([]routes.Endpoint, 0, len(fns))
	for _, e := range fns {
		ep, err := routes.NewEndpoint(e.path, e.f)
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, nil
}

type served struct {
	path string
	f    httpx.EndpointFunc
}

type handlers struct {
	*Service
	issuer Issuer
}

func unavailable(err error) error {
	return errors.Join(httpx.ErrServiceUnavailable, err)
}
