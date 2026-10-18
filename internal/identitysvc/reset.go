package identitysvc

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
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

const (
	stateResetRequested = "reset_requested"
	statePasswordReset  = "password_reset"
)

func (h *handlers) forgotPassword(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	p, err := h.issuer.Begin(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	if id, err := NormalizeAs(identity.IdentifierEmail, r.Field(routes.FieldIdentifier)); err == nil {
		if err := h.requestReset(ctx, r.Tenant(), id, p); err != nil {
			r.Fail(w, err)
			return
		}
	}
	r.RespondPending(w, p, httpx.Response{Status: http.StatusAccepted, Body: journeyBody{State: stateResetRequested}})
}

func (s *Service) requestReset(ctx context.Context, t core.TenantID, id identity.Identifier, p core.Pending) error {
	u, err := s.identity.FindUser(ctx, t, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return errors.Join(httpx.ErrServiceUnavailable, err)
	}
	st := stateOf(u)
	if !st.Usable() || !st.EmailVerified() {
		return nil
	}
	s.sendReset(ctx, p, u, st)
	return nil
}

func (s *Service) putReset(ctx context.Context, p core.Pending, u identity.User, st core.AccountState) (LinkMessage, error) {
	bound, err := p.Bind(u.Subject, st)
	if err != nil {
		return LinkMessage{}, err
	}
	payload, err := ceremonycodec.PasswordReset().Encode(ceremonycodec.Empty{})
	if err != nil {
		return LinkMessage{}, err
	}
	handle, rec, err := s.newRecord(bound, ceremony.PasswordReset, ceremony.SubjectScope(u.Subject), payload)
	if err != nil {
		return LinkMessage{}, err
	}
	if _, err := s.ceremonies.Put(ctx, rec); err != nil {
		return LinkMessage{}, err
	}
	link, err := s.links.Link(ctx, u.Subject.Tenant, ceremony.PasswordReset, handle.Encode())
	if err != nil {
		return LinkMessage{}, err
	}
	return LinkMessage{Tenant: u.Subject.Tenant, To: u.Email.Value(), Link: link, ExpiresAt: rec.ExpiresAt()}, nil
}

func (h *handlers) resetPassword(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	handle, err := ceremonycodec.ParseHandle(r.Field(routes.FieldToken))
	if err != nil {
		r.Fail(w, errors.Join(ErrInvalidToken, err))
		return
	}
	rec, err := h.ceremonies.Peek(ctx, r.Tenant(), ceremony.PasswordReset, handle.Hash())
	if err != nil {
		r.Fail(w, ceremonyProblem(err))
		return
	}
	if _, _, err := openReset(rec, r.Tenant()); err != nil {
		r.Fail(w, err)
		return
	}
	phc, err := h.AcceptPassword(ctx, r.Field(routes.FieldNewPassword))
	if err != nil {
		r.Fail(w, err)
		return
	}
	if rec, err = h.ceremonies.Consume(ctx, r.Tenant(), ceremony.PasswordReset, handle.Hash()); err != nil {
		r.Fail(w, ceremonyProblem(err))
		return
	}
	p, sub, err := openReset(rec, r.Tenant())
	if err != nil {
		r.Fail(w, err)
		return
	}
	st, err := h.AccountState(ctx, sub)
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrServiceUnavailable, err))
		return
	}
	if !st.Usable() || st.Epoch() != p.EpochAtBind() {
		r.Fail(w, ErrInvalidToken)
		return
	}
	if _, err := h.Apply(ctx, identity.SetPassword{Subject: sub, PHC: phc, Reason: identity.RotationPasswordReset}); err != nil {
		r.Fail(w, mutationProblem(err))
		return
	}
	_ = h.audit.Emit(ctx, event.PasswordReset, scopeOf(sub), audit.Detail{}, nil)
	r.RespondPending(w, p, httpx.Response{Body: journeyBody{State: statePasswordReset}, Location: h.loginPage})
}

func openReset(rec ceremony.Record, t core.TenantID) (core.Pending, core.Subject, error) {
	p, err := core.UnsealPending(rec.Pending)
	if err != nil {
		return core.Pending{}, core.Subject{}, errors.Join(ErrInvalidToken, err)
	}
	sub, bound := p.Subject()
	if !bound {
		return core.Pending{}, core.Subject{}, ErrInvalidToken
	}
	if p.Tenant() != t || rec.Tenant() != t || sub.Tenant != t {
		return core.Pending{}, core.Subject{}, httpx.ErrUnauthenticated
	}
	return p, sub, nil
}

func mutationProblem(err error) error {
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, identity.ErrTombstoned) {
		return errors.Join(ErrInvalidToken, err)
	}
	if errors.Is(err, identity.ErrIdentifiersHeld) {
		return errors.Join(ErrIdentifierHeld, err)
	}
	return errors.Join(httpx.ErrServiceUnavailable, err)
}
