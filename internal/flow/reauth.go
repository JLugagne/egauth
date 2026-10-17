package flow

import (
	"errors"
	"net/http"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/mfasvc"
	"github.com/JLugagne/egauth/internal/passkeysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session"
)

const factorPasskey = "passkey"

func (h *handlers) reauth(w http.ResponseWriter, r *httpx.Request) {
	res, ok := r.Session()
	if !ok {
		r.Fail(w, httpx.ErrUnauthenticated)
		return
	}
	if r.Field(routes.FieldFactor) == factorPasskey {
		h.reauthPasskey(w, r, res)
		return
	}
	ctx := r.Context()
	v, err := h.password(r, res.Attrs().Subject())
	if err != nil {
		r.Fail(w, err)
		return
	}
	vs := []core.Verified{v}
	var second core.Factor
	if r.Has(routes.FieldFactor) {
		if h.second == nil {
			r.Fail(w, mfasvc.ErrInvalidFactor)
			return
		}
		f, err := mfasvc.ParseFactor(r.Field(routes.FieldFactor))
		if err != nil {
			r.Fail(w, err)
			return
		}
		sv, err := h.second.Verify(ctx, res.Attrs().Subject(), f, r.Field(routes.FieldCode))
		if err != nil {
			r.Fail(w, err)
			return
		}
		vs, second = append(vs, sv), f
	}
	resp, err := h.issuer.ReauthenticateAll(ctx, w, r, vs)
	if err != nil {
		r.Fail(w, err)
		return
	}
	if second != (core.Factor{}) {
		h.verified(ctx, res.Attrs().Subject(), second)
	}
	r.Respond(w, resp)
}

func (h *handlers) password(r *httpx.Request, sub core.Subject) (core.Verified, error) {
	if h.passwords == nil {
		return core.Verified{}, ErrReauthUnavailable
	}
	password := r.Field(routes.FieldPassword)
	if password == "" {
		return core.Verified{}, httpx.ErrInvalidRequest
	}
	if err := h.passwords.CheckPassword(r.Context(), sub, password); err != nil {
		return core.Verified{}, err
	}
	v, err := factors.Password(sub, h.clock.Now())
	if err != nil {
		return core.Verified{}, errors.Join(httpx.ErrInternal, err)
	}
	return v, nil
}

func (h *handlers) reauthPasskey(w http.ResponseWriter, r *httpx.Request, res session.Resumed) {
	ctx := r.Context()
	if h.stepUp == nil {
		r.Fail(w, mfasvc.ErrInvalidFactor)
		return
	}
	if !r.Has(routes.FieldHandle) {
		p, err := h.issuer.BeginReauth(ctx, r)
		if err != nil {
			r.Fail(w, err)
			return
		}
		ch, err := h.stepUp.BeginStepUp(ctx, p)
		if err != nil {
			r.Fail(w, err)
			return
		}
		r.Respond(w, httpx.Response{Body: passkeyBody{State: statePasskeyChallenge, Options: ch.Options, Handle: ch.Handle}})
		return
	}
	a := res.Attrs()
	var vs []core.Verified
	if r.Has(routes.FieldPassword) {
		v, err := h.password(r, a.Subject())
		if err != nil {
			r.Fail(w, err)
			return
		}
		vs = append(vs, v)
	}
	p, v, err := h.stepUp.FinishReauth(ctx, r.Tenant(), r.Field(routes.FieldHandle), r.WebAuthnBody())
	if err != nil {
		r.Fail(w, err)
		return
	}
	lineage, reauth := p.ReauthOf()
	if sub, _ := p.Subject(); !reauth || lineage != a.Lineage() || sub != a.Subject() {
		r.Fail(w, errors.Join(passkeysvc.ErrPasskeyRejected, errors.New("flow: passkey reauthentication begun by another session")))
		return
	}
	var resp httpx.Response
	if len(vs) == 0 {
		resp, err = h.issuer.Reauthenticate(ctx, w, r, v)
	} else {
		resp, err = h.issuer.ReauthenticateAll(ctx, w, r, append(vs, v))
	}
	if err != nil {
		r.Fail(w, err)
		return
	}
	r.Respond(w, resp)
}
