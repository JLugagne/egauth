package identitysvc

import (
	"errors"
	"net/http"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

const (
	stateRecoveryEmailRequested = "recovery_email_requested"
	stateRecoveryEmailConfirmed = "recovery_email_confirmed"
)

func (h *acctHandlers) requestRecoveryEmail(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	c, err := h.currentAccount(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	id, err := NormalizeAs(identity.IdentifierRecoveryEmail, r.Field(routes.FieldEmail))
	if err != nil {
		r.Fail(w, errors.Join(ErrInvalidIdentifier, err))
		return
	}
	if id.Value() == c.user.Email.Value() || (id == c.user.RecoveryEmail && !c.user.RecoveryEmailVerifiedAt.IsZero()) {
		r.Fail(w, ErrIdentifierUnchanged)
		return
	}
	p, err := h.boundPending(ctx, r, c)
	if err != nil {
		r.Fail(w, err)
		return
	}
	payload, err := ceremonycodec.RecoveryEmail().Encode(ceremonycodec.Address{Address: id.Value()})
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	h.sendLink(ctx, p, ceremony.RecoveryEmail, payload, id.Value(), h.mailer.RecoveryEmailLink)
	r.Respond(w, httpx.Response{Status: http.StatusAccepted, Body: journeyBody{State: stateRecoveryEmailRequested}})
}

func (h *acctHandlers) confirmRecoveryEmail(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	c, err := h.consumeBound(ctx, r, ceremony.RecoveryEmail, routes.FieldToken)
	if err != nil {
		r.Fail(w, err)
		return
	}
	addr, err := ceremonycodec.RecoveryEmail().Decode(c.record.Payload())
	if err != nil {
		r.Fail(w, errors.Join(ErrInvalidToken, err))
		return
	}
	id, err := identity.NewIdentifier(identity.IdentifierRecoveryEmail, addr.Address)
	if err != nil {
		r.Fail(w, errors.Join(ErrInvalidToken, err))
		return
	}
	if err := h.applyIdentifier(ctx, identity.SetRecoveryEmail{Subject: c.subject, RecoveryEmail: id}); err != nil {
		r.Fail(w, err)
		return
	}
	_ = h.audit.Emit(ctx, event.RecoveryChannelEnrolled, scopeOf(c.subject), audit.Detail{}, nil,
		audit.A(event.KeyIdentifierKind, identity.IdentifierRecoveryEmail.String()))
	r.RespondPending(w, c.pending, httpx.Response{Body: journeyBody{State: stateRecoveryEmailConfirmed}})
}
