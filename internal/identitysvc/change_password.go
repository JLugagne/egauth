package identitysvc

import (
	"context"
	"errors"
	"net/http"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

const statePasswordChanged = "password_changed"

func (h *acctHandlers) changePassword(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	c, err := h.currentAccount(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	if err := h.checkCurrentPassword(ctx, c, r.Field(routes.FieldPassword)); err != nil {
		r.Fail(w, err)
		return
	}
	phc, err := h.AcceptPassword(ctx, r.Field(routes.FieldNewPassword))
	if err != nil {
		r.Fail(w, err)
		return
	}
	sub := c.user.Subject
	if _, err := h.Apply(ctx, identity.SetPassword{Subject: sub, PHC: phc, Reason: identity.RotationPasswordChanged, Keep: c.attrs.Lineage()}); err != nil {
		r.Fail(w, mutationProblem(err))
		return
	}
	_ = h.audit.Emit(ctx, event.PasswordChanged, scopeOf(sub), audit.Detail{}, nil)
	if err := h.issuer.Reissue(ctx, w, r, httpx.PasswordChangedChange()); err != nil {
		r.Fail(w, errors.Join(httpx.ErrUnauthenticated, err))
		return
	}
	r.Respond(w, httpx.Response{Body: journeyBody{State: statePasswordChanged}})
}

func (s *Service) checkCurrentPassword(ctx context.Context, c current, password string) error {
	cred, err := s.identity.GetPassword(ctx, c.user.Subject)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return errors.Join(httpx.ErrServiceUnavailable, err)
	}
	ok := s.matches(ctx, cred.PHC.PHC(), password)
	if cred.LockedUntil.After(s.clock.Now()) {
		return ErrInvalidCredentials
	}
	if !ok {
		s.recordFailure(ctx, c.user.Subject)
		return ErrInvalidCredentials
	}
	return nil
}
