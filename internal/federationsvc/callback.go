package federationsvc

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/ceremony"
)

const (
	stateLinked           = "linked"
	stateExchangeRequired = "exchange_required"
)

type linkedBody struct {
	State        string `json:"state"`
	SessionEnded bool   `json:"session_ended"`
}

type exchangeBody struct {
	State  string `json:"state"`
	Handle string `json:"handle"`
}

func (h *handlers) callback(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	name := r.HTTP().PathValue(pathProvider)
	q := r.HTTP().URL.Query()
	state := q["state"]
	if len(state) != 1 {
		r.Fail(w, ErrInvalidState)
		return
	}
	opened, err := ceremonycodec.OAuthState().Open(h.sealer, r.Tenant(), state[0])
	switch {
	case errors.Is(err, ceremonycodec.ErrWrongTenant):
		r.Fail(w, errors.Join(httpx.ErrUnauthenticated, err))
		return
	case err != nil:
		r.Fail(w, errors.Join(ErrInvalidState, err))
		return
	case opened.Payload.Provider != name:
		r.Fail(w, ErrInvalidState)
		return
	}
	p := opened.Pending
	if p.Transport() == core.TransportCookies && !h.browserBound(r, p) {
		r.Fail(w, ErrUnboundCeremony)
		return
	}
	rp, err := h.provider(ctx, r.Tenant(), name)
	if err != nil {
		r.Fail(w, err)
		return
	}
	first, err := h.ceremonies.MarkConsumed(ctx, r.Tenant(), ceremony.OAuthState, opened.HandleHash, opened.ExpiresAt)
	switch {
	case err != nil:
		r.Fail(w, unavailable(err))
		return
	case !first:
		r.Fail(w, ErrInvalidState)
		return
	}
	h.clearBind(w, p)
	id, err := h.authorized(r, q, rp, opened.Payload)
	if err != nil {
		r.Fail(w, err)
		return
	}
	if sub, bound := p.Subject(); bound {
		h.finishLink(w, r, p, sub, id)
		return
	}
	sub, err := h.directory.SignIn(ctx, r.Tenant(), id)
	if err != nil {
		r.Fail(w, err)
		return
	}
	if p.Transport() == core.TransportBearer {
		h.park(w, r, p, sub, name)
		return
	}
	h.complete(w, r, p, sub, name)
}

func (h *handlers) authorized(r *httpx.Request, q url.Values, rp resolved, o ceremonycodec.OAuth) (ProviderIdentity, error) {
	if q.Has("error") {
		return ProviderIdentity{}, ErrAccessDenied
	}
	if iss, sent := q["iss"]; sent && oidc(rp.spec) && (len(iss) != 1 || iss[0] != rp.spec.Issuer) {
		return ProviderIdentity{}, ErrIssuerMismatch
	}
	code := r.Field(routes.FieldCode)
	if code == "" {
		return ProviderIdentity{}, ErrInvalidState
	}
	tr, err := redeem(r.Context(), rp.client, rp.spec, code, o)
	if err != nil {
		return ProviderIdentity{}, errors.Join(ErrProviderUnavailable, err)
	}
	prof, err := h.identify(r.Context(), rp, tr, o.Nonce)
	if err != nil {
		return ProviderIdentity{}, err
	}
	return ProviderIdentity{
		Provider:      rp.spec.Name,
		Subject:       prof.subject,
		Authority:     rp.authority,
		Email:         prof.email,
		EmailVerified: rp.spec.Verified(prof.email, prof.emailVerified),
	}, nil
}

func (h *handlers) browserBound(r *httpx.Request, p core.Pending) bool {
	presented, _ := h.cookies.Read(r.HTTP(), cookie.Bind)
	return cookie.VerifyBind(presented, p.BindHash())
}

func (h *handlers) clearBind(w http.ResponseWriter, p core.Pending) {
	if p.Transport() == core.TransportCookies {
		h.cookies.Clear(w, cookie.Bind)
	}
}

func (h *handlers) complete(w http.ResponseWriter, r *httpx.Request, p core.Pending, sub core.Subject, provider string) {
	v, err := factors.Federated(sub, provider, h.clock.Now())
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	resp, err := h.issuer.Complete(r.Context(), w, r, p, v)
	if err != nil {
		r.Fail(w, err)
		return
	}
	r.RespondPending(w, p, resp)
}

func (h *handlers) finishLink(w http.ResponseWriter, r *httpx.Request, p core.Pending, sub core.Subject, id ProviderIdentity) {
	if p.Transport() != core.TransportCookies {
		r.Fail(w, ErrUnsupportedTransport)
		return
	}
	if err := h.directory.Link(r.Context(), sub, p.EpochAtBind(), id); err != nil {
		r.Fail(w, err)
		return
	}
	if to := p.ReturnTo(); to != "" {
		seeOther(w, to)
		return
	}
	r.RespondPending(w, p, httpx.Response{Body: linkedBody{State: stateLinked, SessionEnded: true}})
}

func (h *handlers) park(w http.ResponseWriter, r *httpx.Request, p core.Pending, sub core.Subject, provider string) {
	ctx := r.Context()
	st, err := h.accounts.AccountState(ctx, sub)
	if err != nil {
		r.Fail(w, unavailable(err))
		return
	}
	if p, err = p.Bind(sub, st); err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	handle, err := ceremonycodec.NewHandle()
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	if err := h.putExchange(r, p, sub, exchangeKey(handle, provider)); err != nil {
		r.Fail(w, err)
		return
	}
	wire := handle.Encode() + exchangeSep + provider
	if to := p.ReturnTo(); to != "" {
		sep := "?"
		if strings.Contains(to, "?") {
			sep = "&"
		}
		seeOther(w, to+sep+routes.FieldHandle+"="+url.QueryEscape(wire))
		return
	}
	r.RespondPending(w, p, httpx.Response{Body: exchangeBody{State: stateExchangeRequired, Handle: wire}})
}
