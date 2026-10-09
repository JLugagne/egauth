package federationsvc

import (
	"errors"
	"net/http"

	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/store/ceremony"
)

const (
	pathProvider  = "provider"
	stateRedirect = "redirect"
)

type redirectBody struct {
	State            string `json:"state"`
	AuthorizationURL string `json:"authorization_url"`
	Bind             string `json:"bind,omitempty"`
}

func (h *handlers) begin(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	rp, err := h.provider(ctx, r.Tenant(), r.HTTP().PathValue(pathProvider))
	if err != nil {
		r.Fail(w, err)
		return
	}
	p, err := h.issuer.Begin(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	h.start(w, r, rp, p)
}

func (h *handlers) link(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	res, ok := r.Session()
	if !ok {
		r.Fail(w, httpx.ErrUnauthenticated)
		return
	}
	if res.Attrs().Transport() != core.TransportCookies {
		r.Fail(w, ErrUnsupportedTransport)
		return
	}
	sub := res.Attrs().Subject()
	rp, err := h.provider(ctx, r.Tenant(), r.HTTP().PathValue(pathProvider))
	if err != nil {
		r.Fail(w, err)
		return
	}
	st, err := h.accounts.AccountState(ctx, sub)
	switch {
	case err != nil:
		r.Fail(w, unavailable(err))
		return
	case !st.Usable():
		r.Fail(w, httpx.ErrUnauthenticated)
		return
	case !st.EmailVerified():
		r.Fail(w, ErrEmailUnverified)
		return
	}
	p, err := h.issuer.Begin(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	if p, err = p.Bind(sub, st); err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	h.start(w, r, rp, p)
}

func (h *handlers) start(w http.ResponseWriter, r *httpx.Request, rp resolved, p core.Pending) {
	bind, err := cookie.NewBind()
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	if p, err = p.WithBindHash(bind.Hash()); err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	payload, err := h.statePayload(r, rp)
	if err != nil {
		r.Fail(w, err)
		return
	}
	issued, err := ceremonycodec.OAuthState().Seal(h.sealer, p, payload)
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	authURL, err := authorizationURL(rp.spec, issued.Handle, payload)
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	if p.Transport() == core.TransportBearer {
		r.RespondPending(w, p, httpx.Response{Body: redirectBody{State: stateRedirect, AuthorizationURL: authURL, Bind: bind.Value()}})
		return
	}
	if err := h.cookies.SetBind(w, bind, ceremony.OAuthState); err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	if p.Bound() {
		r.RespondPending(w, p, httpx.Response{Body: redirectBody{State: stateRedirect, AuthorizationURL: authURL}})
		return
	}
	seeOther(w, authURL)
}

func (h *handlers) statePayload(r *httpx.Request, rp resolved) (ceremonycodec.OAuth, error) {
	verifier, err := randomToken()
	if err != nil {
		return ceremonycodec.OAuth{}, errors.Join(httpx.ErrInternal, err)
	}
	var nonce string
	if oidc(rp.spec) {
		if nonce, err = randomToken(); err != nil {
			return ceremonycodec.OAuth{}, errors.Join(httpx.ErrInternal, err)
		}
	}
	uri, err := h.redirectURI(r.Tenant(), rp.spec.Name)
	if err != nil {
		return ceremonycodec.OAuth{}, errors.Join(httpx.ErrInternal, err)
	}
	return ceremonycodec.OAuth{Provider: rp.spec.Name, PKCEVerifier: verifier, Nonce: nonce, RedirectURI: uri}, nil
}

func seeOther(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusSeeOther)
}
