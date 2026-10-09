package issuance

import (
	"context"
	"errors"
	"net/http"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/store"
)

// BeginReauth returns the Pending of a reauthentication of r's session (core.PendingForReauth):
// bound to its subject, epoch and lineage, it seals a /reauth passkey ceremony so that only this
// session can finish it. It returns httpx.ErrUnauthenticated without a session.
func (i *Issuer) BeginReauth(_ context.Context, r *httpx.Request) (core.Pending, error) {
	res, ok := r.Session()
	if !ok {
		return core.Pending{}, httpx.ErrUnauthenticated
	}
	p := core.PendingForReauth(res.Attrs(), i.clock.Now())
	if _, bound := p.Subject(); !bound {
		return core.Pending{}, httpx.ErrUnauthenticated
	}
	return p, nil
}

// Reauthenticate is ReauthenticateAll with the single verification v, for a ceremony that proves
// both factors at once (a passkey assertion with user verification).
func (i *Issuer) Reauthenticate(ctx context.Context, w http.ResponseWriter, r *httpx.Request, v core.Verified) (httpx.Response, error) {
	return i.ReauthenticateAll(ctx, w, r, []core.Verified{v})
}

// ReauthenticateAll refreshes the freshness of r's session with vs, all verified for its subject
// during this request (DESIGN §5.3): a Pending bound to the session's lineage (PendingForReauth)
// collects vs, core.Reauthenticate keeps the lineage and the factors, refreshes primaryAt and, only
// when vs hold a second factor or a passkey with user verification, secondAt, so a password alone
// never makes a multi-factor session fresh (C-44). Backend.Reissue then replaces the session
// atomically. When the subject is enrolled and vs are not multi-factor nothing changes and the
// response is {"state":"mfa_required","factors"} listing the second factors /reauth accepts ("passkey"
// meaning a passkey reauthentication, which alone suffices), or a 303 to Pages.Reauth for a cookie
// browser.
// Errors: httpx.ErrUnauthenticated without a session or for a refused verification,
// ErrAuthUnavailable, and the errors of Reissue.
func (i *Issuer) ReauthenticateAll(ctx context.Context, w http.ResponseWriter, r *httpx.Request, vs []core.Verified) (httpx.Response, error) {
	res, ok := r.Session()
	if !ok || len(vs) == 0 {
		return httpx.Response{}, httpx.ErrUnauthenticated
	}
	a := res.Attrs()
	sub := a.Subject()
	st, err := i.state(ctx, sub)
	if err != nil {
		return httpx.Response{}, err
	}
	p := core.PendingForReauth(a, i.clock.Now())
	for _, v := range vs {
		if p, err = p.Add(v, st); err != nil {
			return httpx.Response{}, errors.Join(httpx.ErrUnauthenticated, err)
		}
	}
	d, err := i.decision(ctx, sub)
	if err != nil {
		return httpx.Response{}, err
	}
	n, err := core.Reauthenticate(a, p, st, d, i.clock.Now())
	if errors.Is(err, core.ErrFactorRequired) {
		offered := i.offered(d.Factors(), reauthFactors...)
		body := mfaRequiredBody{State: StateMFARequired, Factors: factorNames(offered)}
		if len(offered) == 0 {
			_ = i.audit.Emit(ctx, event.MFAModuleMissing, scopeOf(sub), audit.Detail{Reason: "no_completing_module"}, nil,
				audit.A(event.KeyMethod, primaryCode(p.Factors())), audit.A(event.KeyFactors, factorCodes(d.Factors())))
			return httpx.Response{Body: body}, nil
		}
		loc, err := i.landing(sub.Tenant, "", i.pages.Reauth)
		if err != nil {
			return httpx.Response{}, err
		}
		return httpx.Response{Body: body, Location: loc}, nil
	}
	if err != nil {
		return httpx.Response{}, errors.Join(httpx.ErrUnauthenticated, err)
	}
	if err := i.reissue(ctx, w, r, res, n); err != nil {
		return httpx.Response{}, err
	}
	return httpx.Response{Body: stateBody{State: StateReauthenticated}}, nil
}

// Reissue replaces r's session after the security change c, which the caller has already
// committed with its epoch bump: core.FactorEnrolled (secondAt unchanged, C-45) or
// core.PasswordChanged (pwd added, must-change cleared, every other factor kept, I-19), stamped with
// the new epoch, then Backend.Reissue, atomic against a concurrent revocation (C-33). The session is
// the one the preamble resumed from r's credential, never one named by the request or the context
// (T-09, I-08). On any failure the client's session cookies are cleared: the epoch bump has already
// ended the old session. Errors: httpx.ErrUnauthenticated without a session, for a stale epoch or a
// lost race, httpx.ErrInternal for the zero Change, ErrClaimsUnavailable and 503 problems.
func (i *Issuer) Reissue(ctx context.Context, w http.ResponseWriter, r *httpx.Request, c httpx.Change) error {
	res, ok := r.Session()
	if !ok {
		return httpx.ErrUnauthenticated
	}
	a := res.Attrs()
	st, err := i.state(ctx, a.Subject())
	if err != nil {
		i.clearSession(w, r, a.Transport())
		return err
	}
	var n core.SessionAttrs
	if f, enrolled := c.EnrolledFactor(); enrolled {
		n, err = core.FactorEnrolled(a, f, st)
	} else if c.PasswordChanged() {
		n, err = core.PasswordChanged(a, st, i.clock.Now())
	} else {
		return errors.Join(httpx.ErrInternal, errors.New("issuance: zero change"))
	}
	if err != nil {
		i.clearSession(w, r, a.Transport())
		return errors.Join(httpx.ErrUnauthenticated, err)
	}
	return i.reissue(ctx, w, r, res, n)
}

func (i *Issuer) reissue(ctx context.Context, w http.ResponseWriter, r *httpx.Request, res session.Resumed, n core.SessionAttrs) error {
	err := i.backend.Reissue(ctx, w, res.Handle(), n)
	if err == nil {
		return nil
	}
	i.clearSession(w, r, n.Transport())
	switch {
	case errors.Is(err, store.ErrConflict), errors.Is(err, session.ErrHandleMismatch), errors.Is(err, core.ErrClaimsSubjectUnknown):
		return errors.Join(httpx.ErrUnauthenticated, err)
	case errors.Is(err, core.ErrClaimsTooLarge), errors.Is(err, core.ErrClaimsUnavailable):
		return errors.Join(ErrClaimsUnavailable, err)
	case errors.Is(err, httpx.ErrUnavailable):
		return unavailable(err)
	}
	return errors.Join(httpx.ErrInternal, err)
}
