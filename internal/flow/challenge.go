package flow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/mfasvc"
	"github.com/JLugagne/egauth/internal/passkeysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
)

const statePasskeyChallenge = "passkey_challenge"

type passkeyBody struct {
	State   string          `json:"state"`
	Options json.RawMessage `json:"options"`
	Handle  string          `json:"handle"`
}

type parked struct {
	handle     ceremonycodec.Handle
	sealed     []byte
	pending    core.Pending
	subject    core.Subject
	fromCookie bool
}

func (h *handlers) presented(r *httpx.Request) (ceremonycodec.Handle, bool, error) {
	raw, fromCookie := r.Field(routes.FieldFlow), false
	if !r.Has(routes.FieldFlow) {
		v, ok := h.cookies.Read(r.HTTP(), cookie.Flow)
		if !ok {
			return ceremonycodec.Handle{}, false, ErrInvalidFlow
		}
		raw, fromCookie = v, true
	}
	handle, err := ceremonycodec.ParseHandle(raw)
	if err != nil {
		return ceremonycodec.Handle{}, fromCookie, errors.Join(ErrInvalidFlow, err)
	}
	return handle, fromCookie, nil
}

func (h *handlers) open(ctx context.Context, w http.ResponseWriter, r *httpx.Request) (parked, error) {
	handle, fromCookie, err := h.presented(r)
	if err != nil {
		h.dropCookie(w, fromCookie)
		return parked{}, err
	}
	rec, err := h.flows.Peek(ctx, r.Tenant(), ceremony.MFAFlow, handle.Hash())
	switch {
	case errors.Is(err, store.ErrNotFound):
		h.dropCookie(w, fromCookie)
		return parked{}, errors.Join(ErrInvalidFlow, err)
	case err != nil:
		return parked{}, unavailable(err)
	}
	p, err := core.UnsealPending(rec.Pending)
	if err != nil {
		return parked{}, errors.Join(ErrInvalidFlow, err)
	}
	sub, bound := p.Subject()
	_, reauth := p.ReauthOf()
	switch {
	case !bound || reauth || p.Tenant() != r.Tenant() || rec.Tenant() != r.Tenant() || !rec.ScopedTo(ceremony.SubjectScope(sub)):
		return parked{}, ErrInvalidFlow
	case (p.Transport() == core.TransportCookies) != fromCookie:
		return parked{}, errors.Join(ErrInvalidFlow, errors.New("flow: handle presented on another transport"))
	}
	return parked{handle: handle, sealed: rec.Pending.Bytes(), pending: p, subject: sub, fromCookie: fromCookie}, nil
}

func (h *handlers) dropCookie(w http.ResponseWriter, fromCookie bool) {
	if fromCookie {
		h.cookies.Clear(w, cookie.Flow)
	}
}

func (h *handlers) charge(ctx context.Context, w http.ResponseWriter, r *httpx.Request, f parked) {
	remaining, err := h.flows.RecordFailure(ctx, r.Tenant(), ceremony.MFAFlow, f.handle.Hash())
	if err == nil && remaining <= 0 {
		h.dropCookie(w, f.fromCookie)
	}
}

func (h *handlers) finish(w http.ResponseWriter, r *httpx.Request, f parked, v core.Verified) (httpx.Response, error) {
	ctx := r.Context()
	rec, err := h.flows.Consume(ctx, r.Tenant(), ceremony.MFAFlow, f.handle.Hash())
	switch {
	case errors.Is(err, store.ErrNotFound):
		h.dropCookie(w, f.fromCookie)
		return httpx.Response{}, errors.Join(ErrInvalidFlow, err)
	case err != nil:
		return httpx.Response{}, unavailable(err)
	}
	h.dropCookie(w, f.fromCookie)
	if !bytes.Equal(rec.Pending.Bytes(), f.sealed) {
		return httpx.Response{}, errors.Join(ErrInvalidFlow, errors.New("flow: record changed between peek and consume"))
	}
	return h.issuer.Complete(ctx, w, r, f.pending, v)
}

func (h *handlers) challenge(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	factor, err := mfasvc.ParseFactor(r.Field(routes.FieldFactor))
	if err != nil {
		r.Fail(w, err)
		return
	}
	f, err := h.open(ctx, w, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	v, err := h.second.Verify(ctx, f.subject, factor, r.Field(routes.FieldCode))
	if err != nil {
		if errors.Is(err, mfasvc.ErrInvalidCode) || errors.Is(err, mfasvc.ErrTooManyAttempts) {
			h.charge(ctx, w, r, f)
		}
		r.Fail(w, err)
		return
	}
	resp, err := h.finish(w, r, f, v)
	if err != nil {
		r.Fail(w, err)
		return
	}
	h.verified(ctx, f.subject, factor)
	r.RespondPending(w, f.pending, resp)
}

func (h *handlers) verified(ctx context.Context, sub core.Subject, f core.Factor) {
	_ = h.audit.Emit(ctx, event.MFAVerified, audit.Scope{TenantID: sub.Tenant.String(), UserID: sub.User.String()},
		audit.Detail{}, nil, audit.A(event.KeyFactor, f.Code()))
}

func (h *handlers) passkeyBegin(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	f, err := h.open(ctx, w, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	ch, err := h.stepUp.BeginStepUp(ctx, f.pending)
	if err != nil {
		r.Fail(w, err)
		return
	}
	r.RespondPending(w, f.pending, httpx.Response{Body: passkeyBody{State: statePasskeyChallenge, Options: ch.Options, Handle: ch.Handle}})
}

func (h *handlers) passkeyFinish(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	f, err := h.open(ctx, w, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	p, v, err := h.stepUp.FinishStepUp(ctx, r.Tenant(), r.Field(routes.FieldHandle), r.WebAuthnBody())
	if err != nil {
		if errors.Is(err, passkeysvc.ErrPasskeyRejected) {
			h.charge(ctx, w, r, f)
		}
		r.Fail(w, err)
		return
	}
	sealed, err := core.SealPending(p)
	if err != nil || !bytes.Equal(sealed.Bytes(), f.sealed) {
		r.Fail(w, errors.Join(ErrInvalidFlow, errors.New("flow: step-up begun from another flow"), err))
		return
	}
	resp, err := h.finish(w, r, f, v)
	if err != nil {
		r.Fail(w, err)
		return
	}
	h.verified(ctx, f.subject, core.FactorPasskeyStepUp)
	r.RespondPending(w, f.pending, resp)
}
