package issuance

import (
	"context"
	"errors"
	"net/http"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/ceremony"
)

type authenticatedBody struct {
	State    string `json:"state"`
	ReturnTo string `json:"return_to,omitempty"`
}

type mfaRequiredBody struct {
	State   string   `json:"state"`
	Factors []string `json:"factors"`
	Flow    string   `json:"flow,omitempty"`
}

type stateBody struct {
	State string `json:"state"`
}

// Begin starts a login journey for r: the remember-me policy is applied to r's remember field once
// and sealed with the validated return_to and r's transport (T-19). It returns ErrInvalidReturnTo
// for a refused return_to.
func (i *Issuer) Begin(_ context.Context, r *httpx.Request) (core.Pending, error) {
	remember := core.RememberDeclined
	if r.Flag(routes.FieldRemember) {
		remember = core.RememberRequested
	}
	tg, err := i.target(r.Tenant(), r.Field(routes.FieldReturnTo))
	if err != nil {
		return core.Pending{}, err
	}
	p, err := core.NewPending(r.Tenant(), remember, tg, r.Transport(), i.remember, i.clock.Now())
	if err != nil {
		return core.Pending{}, errors.Join(httpx.ErrInternal, err)
	}
	return p, nil
}

// Complete is the only admission (DESIGN §5.1 step 2). It loads the account state and the persisted
// MFA decision itself, adds v to p and calls core.Admit; p must belong to r's tenant.
//
//   - Session: the claims are fetched, Backend.Start writes the credentials on p's sealed transport,
//     SessionIssued and LoginSucceeded are emitted once, and the response is {"state":
//     "authenticated","return_to"} or, for a cookie-transport browser, a 303 to return_to or
//     Pages.AfterLogin.
//   - NeedsFactor: any session cookie of the client is cleared, the Pending is stored as an
//     MFAFlow record scoped to the subject and its handle delivered on the sealed transport (the
//     flow cookie, or "flow" in the body under Bearer); the response is {"state":"mfa_required",
//     "factors"} or a 303 to Pages.MFA, and MFAChallengeRequired is emitted. When no enabled module
//     completes any required factor, MFAModuleMissing is emitted, no flow is stored and no session is
//     ever issued.
//
// Errors: httpx.ErrUnauthenticated for a refused verification or admission (another tenant,
// subject or epoch, an unusable account, an expired journey), ErrAuthUnavailable when the
// enrollment cannot be read, ErrClaimsUnavailable, and a 503 problem for any other outage.
func (i *Issuer) Complete(ctx context.Context, w http.ResponseWriter, r *httpx.Request, p core.Pending, v core.Verified) (httpx.Response, error) {
	sub := v.Subject()
	if p.Tenant() != r.Tenant() || sub.Tenant != r.Tenant() {
		return httpx.Response{}, errors.Join(httpx.ErrUnauthenticated, core.ErrTenantMismatch)
	}
	st, err := i.state(ctx, sub)
	if err != nil {
		return httpx.Response{}, err
	}
	bound, err := p.Add(v, st)
	if err != nil {
		i.refused(ctx, sub, v.Factors())
		return httpx.Response{}, errors.Join(httpx.ErrUnauthenticated, err)
	}
	d, err := i.decision(ctx, sub)
	if err != nil {
		return httpx.Response{}, err
	}
	adm, err := core.Admit(bound, st, d, i.clock.Now())
	if err != nil {
		i.refused(ctx, sub, bound.Factors())
		return httpx.Response{}, errors.Join(httpx.ErrUnauthenticated, err)
	}
	if a, ok := adm.Session(); ok {
		return i.start(ctx, w, a)
	}
	parked, needs, _ := adm.NeedsFactor()
	return i.park(ctx, w, r, parked, needs)
}

func (i *Issuer) start(ctx context.Context, w http.ResponseWriter, a core.SessionAttrs) (httpx.Response, error) {
	sub := a.Subject()
	loc, err := i.landing(sub.Tenant, a.ReturnTo(), i.pages.AfterLogin)
	if err != nil {
		return httpx.Response{}, err
	}
	claims, err := i.claims.FetchClaims(ctx, sub)
	switch {
	case errors.Is(err, core.ErrClaimsSubjectUnknown):
		return httpx.Response{}, errors.Join(httpx.ErrUnauthenticated, err)
	case err != nil:
		return httpx.Response{}, errors.Join(ErrClaimsUnavailable, err)
	}
	if err := i.backend.Start(ctx, w, a, claims); err != nil {
		return httpx.Response{}, startProblem(err)
	}
	scope := scopeOf(sub)
	method := primaryCode(a.Factors())
	_ = i.audit.Emit(ctx, event.SessionIssued, scope, audit.Detail{}, nil,
		audit.A(event.KeyMethod, method), audit.A(event.KeyAMR, a.AMR()), audit.A(event.KeyRememberMe, a.RememberMe()),
		audit.A(event.KeyMustChange, a.MustChangePassword()))
	_ = i.audit.Emit(ctx, event.LoginSucceeded, scope, audit.Detail{}, nil, audit.A(event.KeyMethod, method))
	return httpx.Response{Body: authenticatedBody{State: StateAuthenticated, ReturnTo: a.ReturnTo()}, Location: loc}, nil
}

func startProblem(err error) error {
	switch {
	case errors.Is(err, core.ErrClaimsTooLarge):
		return errors.Join(ErrClaimsUnavailable, err)
	case errors.Is(err, httpx.ErrUnavailable):
		return unavailable(err)
	}
	return errors.Join(httpx.ErrInternal, err)
}

func (i *Issuer) park(ctx context.Context, w http.ResponseWriter, r *httpx.Request, p core.Pending, needs []core.Factor) (httpx.Response, error) {
	sub, _ := p.Subject()
	i.clearSession(w, r, p.Transport())
	offered := i.offered(needs, flowFactors...)
	body := mfaRequiredBody{State: StateMFARequired, Factors: factorNames(offered)}
	method := primaryCode(p.Factors())
	if len(offered) == 0 {
		_ = i.audit.Emit(ctx, event.MFAModuleMissing, scopeOf(sub), audit.Detail{Reason: "no_completing_module"}, nil,
			audit.A(event.KeyMethod, method), audit.A(event.KeyFactors, factorCodes(needs)))
		return httpx.Response{Body: body}, nil
	}
	loc, err := i.landing(sub.Tenant, "", i.pages.MFA)
	if err != nil {
		return httpx.Response{}, err
	}
	handle, err := i.putFlow(ctx, p, sub)
	if err != nil {
		return httpx.Response{}, err
	}
	switch p.Transport() {
	case core.TransportCookies:
		if err := i.cookies.SetFlow(w, handle.Encode(), ceremony.MFAFlow); err != nil {
			return httpx.Response{}, errors.Join(httpx.ErrInternal, err)
		}
	case core.TransportBearer:
		body.Flow = handle.Encode()
	default:
		return httpx.Response{}, errors.Join(httpx.ErrInternal, core.ErrInvalidArgument)
	}
	_ = i.audit.Emit(ctx, event.MFAChallengeRequired, scopeOf(sub), audit.Detail{}, nil,
		audit.A(event.KeyMethod, method), audit.A(event.KeyFactors, factorCodes(offered)))
	return httpx.Response{Body: body, Location: loc}, nil
}

func (i *Issuer) putFlow(ctx context.Context, p core.Pending, sub core.Subject) (ceremonycodec.Handle, error) {
	payload, err := ceremonycodec.MFAFlow().Encode(ceremonycodec.Empty{})
	if err != nil {
		return ceremonycodec.Handle{}, errors.Join(httpx.ErrInternal, err)
	}
	sealed, err := core.SealPending(p)
	if err != nil {
		return ceremonycodec.Handle{}, errors.Join(httpx.ErrInternal, err)
	}
	handle, err := ceremonycodec.NewHandle()
	if err != nil {
		return ceremonycodec.Handle{}, errors.Join(httpx.ErrInternal, err)
	}
	rec, err := ceremony.NewRecord(ceremony.Spec{
		Kind: ceremony.MFAFlow, HandleHash: handle.Hash(), Scope: ceremony.SubjectScope(sub),
		Pending: sealed, Payload: payload, Now: i.clock.Now(),
	}, openPending)
	switch {
	case errors.Is(err, ceremony.ErrExpired):
		return ceremonycodec.Handle{}, errors.Join(httpx.ErrUnauthenticated, err)
	case err != nil:
		return ceremonycodec.Handle{}, errors.Join(httpx.ErrInternal, err)
	}
	if _, err := i.flows.Put(ctx, rec); err != nil {
		return ceremonycodec.Handle{}, unavailable(err)
	}
	return handle, nil
}

func openPending(sealed principal.Sealed) (ceremony.PendingBinding, error) {
	p, err := core.UnsealPending(sealed)
	if err != nil {
		return ceremony.PendingBinding{}, err
	}
	sub, _ := p.Subject()
	return ceremony.PendingBinding{Tenant: p.Tenant(), Subject: sub, ExpiresAt: p.ExpiresAt()}, nil
}

func (i *Issuer) refused(ctx context.Context, sub core.Subject, fs []core.Factor) {
	_ = i.audit.Emit(ctx, event.LoginFailed, scopeOf(sub), audit.Detail{Reason: "admission_refused"}, nil,
		audit.A(event.KeyMethod, primaryCode(fs)))
}

func scopeOf(s core.Subject) audit.Scope {
	return audit.Scope{TenantID: s.Tenant.String(), UserID: s.User.String()}
}
