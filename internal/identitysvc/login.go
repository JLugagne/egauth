package identitysvc

import (
	"context"
	"errors"
	"net/http"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

func (h *handlers) login(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	p, err := h.issuer.Begin(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	sub, err := h.verifyPassword(ctx, r.Tenant(), r.Field(routes.FieldIdentifier), r.Field(routes.FieldPassword))
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			_ = h.audit.Emit(ctx, event.LoginFailed, audit.Scope{TenantID: r.Tenant().String()},
				audit.Detail{Reason: ErrInvalidCredentials.Code()}, nil, audit.A(event.KeyMethod, core.FactorPassword.Code()))
		}
		r.Fail(w, err)
		return
	}
	v, err := factors.Password(sub, h.clock.Now())
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	resp, err := h.issuer.Complete(ctx, w, r, p, v)
	if err != nil {
		r.Fail(w, err)
		return
	}
	r.RespondPending(w, p, resp)
}

func (s *Service) verifyPassword(ctx context.Context, t core.TenantID, rawID, password string) (core.Subject, error) {
	id, err := Normalize(rawID)
	if err != nil {
		if err := s.decoy(ctx, password); err != nil {
			return core.Subject{}, err
		}
		return core.Subject{}, ErrInvalidCredentials
	}
	u, err := s.identity.FindUser(ctx, t, id)
	known := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		_ = s.decoy(ctx, password)
		return core.Subject{}, errors.Join(httpx.ErrServiceUnavailable, err)
	}
	decoySub := core.Subject{Tenant: t, User: s.decoyUser}
	sub := decoySub
	if known {
		sub = u.Subject
	}
	cred, err := s.identity.GetPassword(ctx, sub)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		_ = s.decoy(ctx, password)
		return core.Subject{}, errors.Join(httpx.ErrServiceUnavailable, err)
	}
	if !known || err != nil {
		if err := s.decoy(ctx, password); err != nil {
			return core.Subject{}, err
		}
		s.chargeDecoy(ctx, decoySub)
		return core.Subject{}, ErrInvalidCredentials
	}
	ok, err := s.matches(ctx, cred.PHC.PHC(), password)
	if err != nil {
		return core.Subject{}, err
	}
	if !loginAllowed(u, id) || cred.LockedUntil.After(s.clock.Now()) {
		s.chargeDecoy(ctx, decoySub)
		return core.Subject{}, ErrInvalidCredentials
	}
	if !ok {
		s.recordFailure(ctx, u.Subject)
		return core.Subject{}, ErrInvalidCredentials
	}
	if cred.FailedAttempts > 0 {
		if err := s.identity.ResetPasswordFailures(ctx, u.Subject); err != nil {
			return core.Subject{}, errors.Join(httpx.ErrServiceUnavailable, err)
		}
	}
	return u.Subject, nil
}

var lockoutPolicy = identity.LockoutPolicy{Threshold: LockoutThreshold, Window: LockoutWindow}

func loginAllowed(u identity.User, id identity.Identifier) bool {
	if !u.DisabledAt.IsZero() || !u.DeletedAt.IsZero() || u.EmailVerifiedAt.IsZero() {
		return false
	}
	return id.Kind() != identity.IdentifierPhone || !u.PhoneVerifiedAt.IsZero()
}

func (s *Service) recordFailure(ctx context.Context, sub core.Subject) {
	l, err := s.identity.RecordPasswordFailure(ctx, sub, lockoutPolicy)
	if err != nil || !l.JustLocked {
		return
	}
	_ = s.audit.Emit(ctx, event.AccountLocked, audit.Scope{TenantID: sub.Tenant.String(), UserID: sub.User.String()},
		audit.Detail{Reason: "password_lockout"}, nil, audit.A(event.KeyCount, l.FailedAttempts))
}

func (s *Service) chargeDecoy(ctx context.Context, decoy core.Subject) {
	_, _ = s.identity.RecordPasswordFailure(ctx, decoy, lockoutPolicy)
}
