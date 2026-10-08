package identitysvc

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

const (
	stateRegistrationRequested = "registration_requested"
	stateConfirmRequired       = "confirm_required"
)

type journeyBody struct {
	State string `json:"state"`
	Bind  string `json:"bind,omitempty"`
}

type confirmBody struct {
	State       string `json:"state"`
	AccountHint string `json:"account_hint"`
}

func (h *handlers) registerAccount(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	id, err := NormalizeAs(identity.IdentifierEmail, r.Field(routes.FieldIdentifier))
	if err != nil {
		r.Fail(w, errors.Join(ErrInvalidIdentifier, err))
		return
	}
	phc, err := h.AcceptPassword(ctx, r.Field(routes.FieldPassword))
	if err != nil {
		r.Fail(w, err)
		return
	}
	p, err := h.issuer.Begin(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	bind, err := cookie.NewBind()
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	if p, err = p.WithBindHash(bind.Hash()); err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	u, err := h.identity.FindUser(ctx, r.Tenant(), id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		r.Fail(w, errors.Join(httpx.ErrServiceUnavailable, err))
		return
	}
	verified := err == nil && !u.EmailVerifiedAt.IsZero()
	if err := h.putRegistration(ctx, p, id, phc, verified); err != nil {
		_ = h.audit.Emit(ctx, event.DeliveryFailed, audit.Scope{TenantID: r.Tenant().String()}, audit.Detail{Reason: "registration"}, err)
	}
	body := journeyBody{State: stateRegistrationRequested}
	if p.Transport() == core.TransportBearer {
		body.Bind = bind.Value()
	} else if err := h.cookies.SetBind(w, bind, ceremony.PendingRegistration); err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	r.RespondPending(w, p, httpx.Response{Status: http.StatusAccepted, Body: body})
}

func (s *Service) putRegistration(ctx context.Context, p core.Pending, id identity.Identifier, phc identity.PasswordHash, verified bool) error {
	payload, err := ceremonycodec.PendingRegistration().Encode(ceremonycodec.Registration{Email: id.Value(), PasswordHash: phc.PHC()})
	if err != nil {
		return err
	}
	scope, err := s.scopes.Scope(id)
	if err != nil {
		return err
	}
	handle, rec, err := s.newRecord(p, ceremony.PendingRegistration, scope, payload)
	if err != nil {
		return err
	}
	if _, err := s.ceremonies.Put(ctx, rec); err != nil {
		return err
	}
	link, err := s.links.Link(ctx, p.Tenant(), ceremony.PendingRegistration, handle.Encode())
	if err != nil {
		return err
	}
	if verified {
		s.sendAccountExists(ctx, NoticeMessage{Tenant: p.Tenant(), To: id.Value()})
		return nil
	}
	s.sendRegistrationLink(ctx, LinkMessage{Tenant: p.Tenant(), To: id.Value(), Link: link, ExpiresAt: rec.ExpiresAt()})
	return nil
}

func (s *Service) newRecord(p core.Pending, k ceremony.Kind, scope ceremony.Scope, payload []byte) (ceremonycodec.Handle, ceremony.Record, error) {
	sealed, err := core.SealPending(p)
	if err != nil {
		return ceremonycodec.Handle{}, ceremony.Record{}, err
	}
	handle, err := ceremonycodec.NewHandle()
	if err != nil {
		return ceremonycodec.Handle{}, ceremony.Record{}, err
	}
	rec, err := ceremony.NewRecord(ceremony.Spec{
		Kind: k, HandleHash: handle.Hash(), Scope: scope, Pending: sealed, Payload: payload, Now: s.clock.Now(),
	}, openPending)
	if err != nil {
		return ceremonycodec.Handle{}, ceremony.Record{}, err
	}
	return handle, rec, nil
}

func openPending(sealed principal.Sealed) (ceremony.PendingBinding, error) {
	p, err := core.UnsealPending(sealed)
	if err != nil {
		return ceremony.PendingBinding{}, err
	}
	sub, _ := p.Subject()
	return ceremony.PendingBinding{Tenant: p.Tenant(), Subject: sub, ExpiresAt: p.ExpiresAt()}, nil
}

func (h *handlers) confirmRegistration(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	handle, err := ceremonycodec.ParseHandle(r.Field(routes.FieldToken))
	if err != nil {
		r.Fail(w, errors.Join(ErrInvalidToken, err))
		return
	}
	rec, err := h.ceremonies.Peek(ctx, r.Tenant(), ceremony.PendingRegistration, handle.Hash())
	if err != nil {
		r.Fail(w, ceremonyProblem(err))
		return
	}
	p, reg, email, err := openRegistration(rec, r.Tenant())
	if err != nil {
		r.Fail(w, err)
		return
	}
	bound := h.presentedBind(r, p)
	if !bound && !r.Flag(routes.FieldConfirm) {
		r.Respond(w, httpx.Response{Body: confirmBody{State: stateConfirmRequired, AccountHint: accountHint(email)}})
		return
	}
	if rec, err = h.ceremonies.Consume(ctx, r.Tenant(), ceremony.PendingRegistration, handle.Hash()); err != nil {
		r.Fail(w, ceremonyProblem(err))
		return
	}
	if p, reg, email, err = openRegistration(rec, r.Tenant()); err != nil {
		r.Fail(w, err)
		return
	}
	var phc identity.PasswordHash
	if bound {
		phc = identity.NewPasswordHash(reg.PasswordHash)
	}
	sub, err := h.createOrVerify(ctx, r.Tenant(), email, phc)
	if err != nil {
		r.Fail(w, err)
		return
	}
	v, err := factors.EmailLink(sub, h.clock.Now())
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	if p.Transport() == core.TransportCookies {
		h.cookies.Clear(w, cookie.Bind)
	}
	resp, err := h.issuer.Complete(ctx, w, r, p, v)
	if err != nil {
		r.Fail(w, err)
		return
	}
	r.RespondPending(w, p, resp)
}

func openRegistration(rec ceremony.Record, t core.TenantID) (core.Pending, ceremonycodec.Registration, identity.Identifier, error) {
	p, err := core.UnsealPending(rec.Pending)
	if err != nil {
		return core.Pending{}, ceremonycodec.Registration{}, identity.Identifier{}, errors.Join(ErrInvalidToken, err)
	}
	if p.Tenant() != t || rec.Tenant() != t {
		return core.Pending{}, ceremonycodec.Registration{}, identity.Identifier{}, httpx.ErrUnauthenticated
	}
	reg, err := ceremonycodec.PendingRegistration().Decode(rec.Payload())
	if err != nil {
		return core.Pending{}, ceremonycodec.Registration{}, identity.Identifier{}, errors.Join(ErrInvalidToken, err)
	}
	email, err := identity.NewIdentifier(identity.IdentifierEmail, reg.Email)
	if err != nil {
		return core.Pending{}, ceremonycodec.Registration{}, identity.Identifier{}, errors.Join(ErrInvalidToken, err)
	}
	return p, reg, email, nil
}

func (s *Service) presentedBind(r *httpx.Request, p core.Pending) bool {
	var presented string
	if p.Transport() == core.TransportBearer {
		presented = r.Field(routes.FieldBind)
	} else {
		presented, _ = s.cookies.Read(r.HTTP(), cookie.Bind)
	}
	return cookie.VerifyBind(presented, p.BindHash())
}

func (s *Service) createOrVerify(ctx context.Context, t core.TenantID, email identity.Identifier, phc identity.PasswordHash) (core.Subject, error) {
	u, err := s.identity.FindUser(ctx, t, email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		a, err := s.Apply(ctx, identity.CreateVerified{Tenant: t, Email: email, PHC: phc})
		if errors.Is(err, identity.ErrIdentifierTaken) {
			return core.Subject{}, errors.Join(ErrAccountExists, err)
		}
		if err != nil {
			return core.Subject{}, errors.Join(httpx.ErrServiceUnavailable, err)
		}
		_ = s.audit.Emit(ctx, event.UserRegistered, scopeOf(a.Subject), audit.Detail{}, nil)
		return a.Subject, nil
	case err != nil:
		return core.Subject{}, errors.Join(httpx.ErrServiceUnavailable, err)
	case !u.EmailVerifiedAt.IsZero():
		return core.Subject{}, ErrAccountExists
	}
	if _, err := s.VerifyEmailOwnership(ctx, u.Subject, phc); err != nil {
		if errors.Is(err, store.ErrConflict) || errors.Is(err, identity.ErrTombstoned) {
			return core.Subject{}, errors.Join(ErrAccountExists, err)
		}
		return core.Subject{}, errors.Join(httpx.ErrServiceUnavailable, err)
	}
	_ = s.audit.Emit(ctx, event.EmailVerified, scopeOf(u.Subject), audit.Detail{}, nil)
	return u.Subject, nil
}

func ceremonyProblem(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return errors.Join(ErrInvalidToken, err)
	}
	return errors.Join(httpx.ErrServiceUnavailable, err)
}

func scopeOf(sub core.Subject) audit.Scope {
	return audit.Scope{TenantID: sub.Tenant.String(), UserID: sub.User.String()}
}

func accountHint(email identity.Identifier) string {
	local, domain, _ := strings.Cut(email.Value(), "@")
	first, _ := utf8.DecodeRuneInString(local)
	return string(first) + "***@" + domain
}
