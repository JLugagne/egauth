package codesvc

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

const (
	stateLinkRequested   = "magic_link_requested"
	stateConfirmRequired = "confirm_required"
)

type journeyBody struct {
	State string `json:"state"`
	Bind  string `json:"bind,omitempty"`
}

type confirmBody struct {
	State       string `json:"state"`
	AccountHint string `json:"account_hint"`
}

func (h *handlers) requestLink(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	j, err := h.begin(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	bind, err := h.deliverBind(w, j, ceremony.MagicLink)
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	if id, err := identitysvc.NormalizeAs(identity.IdentifierEmail, r.Field(routes.FieldIdentifier)); err == nil {
		p := j.pending
		h.work.enqueue(ctx, r.Tenant(), func(c context.Context, delivery uuid.UUID) error {
			return h.sendLink(c, delivery, p, id)
		})
	}
	r.RespondPending(w, j.pending, httpx.Response{Status: http.StatusAccepted, Body: journeyBody{State: stateLinkRequested, Bind: bind}})
}

func (s *Service) sendLink(ctx context.Context, delivery uuid.UUID, p core.Pending, id identity.Identifier) error {
	u, st, ok, err := s.eligible(ctx, p.Tenant(), id)
	if err != nil || !ok {
		return err
	}
	p, err = p.Bind(u.Subject, st)
	if err != nil {
		return err
	}
	payload, err := ceremonycodec.MagicLink().Encode(ceremonycodec.Empty{})
	if err != nil {
		return err
	}
	handle, err := ceremonycodec.NewHandle()
	if err != nil {
		return err
	}
	rec, err := s.putRecord(ctx, p, ceremony.MagicLink, handle, id, payload)
	if err != nil {
		return err
	}
	link, err := s.links.Link(ctx, p.Tenant(), ceremony.MagicLink, handle.Encode())
	if err != nil {
		return err
	}
	return s.mailer.MagicLink(ctx, identitysvc.LinkMessage{
		DeliveryID: delivery, Tenant: p.Tenant(), To: id.Value(), Link: link, ExpiresAt: rec.ExpiresAt(),
	})
}

func (h *handlers) consumeLink(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	handle, err := ceremonycodec.ParseHandle(r.Field(routes.FieldToken))
	if err != nil {
		r.Fail(w, errors.Join(ErrInvalidToken, err))
		return
	}
	rec, err := h.ceremonies.Peek(ctx, r.Tenant(), ceremony.MagicLink, handle.Hash())
	if err != nil {
		r.Fail(w, lookupProblem(err, ErrInvalidToken))
		return
	}
	p, sub, err := openBound(rec, r.Tenant(), ErrInvalidToken)
	if err != nil {
		r.Fail(w, err)
		return
	}
	if !h.presentedBind(r, p) && !r.Flag(routes.FieldConfirm) {
		hint, err := h.hint(ctx, p, sub)
		if err != nil {
			r.Fail(w, err)
			return
		}
		r.Respond(w, httpx.Response{Body: confirmBody{State: stateConfirmRequired, AccountHint: hint}})
		return
	}
	if rec, err = h.ceremonies.Consume(ctx, r.Tenant(), ceremony.MagicLink, handle.Hash()); err != nil {
		r.Fail(w, lookupProblem(err, ErrInvalidToken))
		return
	}
	if p, sub, err = openBound(rec, r.Tenant(), ErrInvalidToken); err != nil {
		r.Fail(w, err)
		return
	}
	v, err := factors.EmailLink(sub, h.clock.Now())
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	h.clearBind(w, p)
	resp, err := h.issuer.Complete(ctx, w, r, p, v)
	if err != nil {
		r.Fail(w, err)
		return
	}
	r.RespondPending(w, p, resp)
}

func (s *Service) hint(ctx context.Context, p core.Pending, sub core.Subject) (string, error) {
	u, err := s.identity.GetUser(ctx, sub)
	if err != nil {
		return "", lookupProblem(err, ErrInvalidToken)
	}
	if u.SecurityEpoch != p.EpochAtBind() || !u.DeletedAt.IsZero() {
		return "", ErrInvalidToken
	}
	return accountHint(u.Email), nil
}
