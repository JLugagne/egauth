package identitysvc

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

const (
	stateVerificationRequested = "verification_requested"
	stateEmailVerified         = "email_verified"
	stateEmailChangeRequested  = "email_change_requested"
	stateEmailChanged          = "email_changed"
)

func (h *acctHandlers) requestEmailVerification(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	p, err := h.issuer.Begin(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	if id, err := NormalizeAs(identity.IdentifierEmail, r.Field(routes.FieldIdentifier)); err == nil {
		if err := h.requestVerification(ctx, r.Tenant(), id, p); err != nil {
			r.Fail(w, err)
			return
		}
	}
	r.RespondPending(w, p, httpx.Response{Status: http.StatusAccepted, Body: journeyBody{State: stateVerificationRequested}})
}

func (a *Accounts) requestVerification(ctx context.Context, t core.TenantID, id identity.Identifier, p core.Pending) error {
	u, err := a.identity.FindUser(ctx, t, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return errors.Join(httpx.ErrServiceUnavailable, err)
	}
	st := stateOf(u)
	if !st.Usable() || st.EmailVerified() || u.Email != id {
		return nil
	}
	bound, err := p.Bind(u.Subject, st)
	if err != nil {
		return errors.Join(httpx.ErrInternal, err)
	}
	payload, err := ceremonycodec.EmailVerification().Encode(ceremonycodec.Address{Address: id.Value()})
	if err != nil {
		return errors.Join(httpx.ErrInternal, err)
	}
	a.sendLink(ctx, bound, ceremony.EmailVerification, payload, id.Value(), a.mailer.EmailVerificationLink)
	return nil
}

func (h *acctHandlers) verifyEmail(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	c, err := h.consumeBound(ctx, r, ceremony.EmailVerification, routes.FieldToken)
	if err != nil {
		r.Fail(w, err)
		return
	}
	addr, err := ceremonycodec.EmailVerification().Decode(c.record.Payload())
	if err != nil {
		r.Fail(w, errors.Join(ErrInvalidToken, err))
		return
	}
	if c.user.Email.Value() != addr.Address || !c.user.EmailVerifiedAt.IsZero() {
		r.Fail(w, ErrInvalidToken)
		return
	}
	if _, err := h.VerifyEmailOwnership(ctx, c.subject, identity.PasswordHash{}); err != nil {
		if errors.Is(err, store.ErrConflict) || errors.Is(err, identity.ErrTombstoned) || errors.Is(err, store.ErrNotFound) {
			r.Fail(w, errors.Join(ErrInvalidToken, err))
			return
		}
		r.Fail(w, errors.Join(httpx.ErrServiceUnavailable, err))
		return
	}
	_ = h.audit.Emit(ctx, event.EmailVerified, scopeOf(c.subject), audit.Detail{}, nil)
	r.RespondPending(w, c.pending, httpx.Response{Body: journeyBody{State: stateEmailVerified}})
}

func (h *acctHandlers) requestEmailChange(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	c, err := h.currentAccount(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	id, err := NormalizeAs(identity.IdentifierEmail, r.Field(routes.FieldEmail))
	if err != nil {
		r.Fail(w, errors.Join(ErrInvalidIdentifier, err))
		return
	}
	if c.user.EmailVerifiedAt.IsZero() {
		r.Fail(w, ErrEmailUnverified)
		return
	}
	if id == c.user.Email {
		r.Fail(w, ErrIdentifierUnchanged)
		return
	}
	p, err := h.boundPending(ctx, r, c)
	if err != nil {
		r.Fail(w, err)
		return
	}
	payload, err := ceremonycodec.EmailChange().Encode(ceremonycodec.Address{Address: id.Value()})
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	h.sendEmailChange(ctx, p, id, payload)
	r.Respond(w, httpx.Response{Status: http.StatusAccepted, Body: journeyBody{State: stateEmailChangeRequested}})
}

func (a *Accounts) sendEmailChange(ctx context.Context, p core.Pending, id identity.Identifier, payload []byte) {
	delivery := uuid.New()
	t := p.Tenant()
	a.mail.enqueue(ctx, t, delivery, func(c context.Context) error {
		_, err := a.identity.FindUser(c, t, id)
		switch {
		case err == nil:
			return a.mail.mailer.AccountExistsNotice(c, NoticeMessage{DeliveryID: delivery, Tenant: t, To: id.Value()})
		case !errors.Is(err, store.ErrNotFound):
			return err
		}
		handle, rec, err := a.putSubjectCeremony(c, p, ceremony.EmailChange, payload)
		if err != nil {
			return err
		}
		link, err := a.links.Link(c, t, ceremony.EmailChange, handle.Encode())
		if err != nil {
			return err
		}
		return a.mailer.EmailChangeLink(c, LinkMessage{DeliveryID: delivery, Tenant: t, To: id.Value(), Link: link, ExpiresAt: rec.ExpiresAt()})
	})
}

func (h *acctHandlers) confirmEmailChange(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	c, err := h.consumeBound(ctx, r, ceremony.EmailChange, routes.FieldToken)
	if err != nil {
		r.Fail(w, err)
		return
	}
	addr, err := ceremonycodec.EmailChange().Decode(c.record.Payload())
	if err != nil {
		r.Fail(w, errors.Join(ErrInvalidToken, err))
		return
	}
	id, err := identity.NewIdentifier(identity.IdentifierEmail, addr.Address)
	if err != nil {
		r.Fail(w, errors.Join(ErrInvalidToken, err))
		return
	}
	if c.user.EmailVerifiedAt.IsZero() {
		r.Fail(w, ErrEmailUnverified)
		return
	}
	if _, err := h.changeEmail(ctx, c.user, id, h.Apply); err != nil {
		r.Fail(w, identifierProblem(err))
		return
	}
	_ = h.audit.Emit(ctx, event.EmailChanged, scopeOf(c.subject), audit.Detail{}, nil,
		audit.A(event.KeyIdentifierKind, identity.IdentifierEmail.String()))
	r.RespondPending(w, c.pending, httpx.Response{Body: journeyBody{State: stateEmailChanged}})
}

func (a *Accounts) changeEmail(ctx context.Context, before identity.User, to identity.Identifier, apply func(context.Context, identity.Mutation) (identity.Applied, error)) (identity.Applied, error) {
	ap, err := apply(ctx, identity.ChangeEmail{Subject: before.Subject, Email: to})
	if err != nil {
		return identity.Applied{}, err
	}
	_ = a.recordTenure(ctx, before, ap)
	return ap, nil
}
