package codesvc

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

type journey struct {
	pending core.Pending
	bind    cookie.BindSecret
}

func (h *handlers) begin(ctx context.Context, r *httpx.Request) (journey, error) {
	p, err := h.issuer.Begin(ctx, r)
	if err != nil {
		return journey{}, err
	}
	b, err := cookie.NewBind()
	if err != nil {
		return journey{}, errors.Join(httpx.ErrInternal, err)
	}
	if p, err = p.WithBindHash(b.Hash()); err != nil {
		return journey{}, errors.Join(httpx.ErrInternal, err)
	}
	return journey{pending: p, bind: b}, nil
}

func (s *Service) deliverBind(w http.ResponseWriter, b journey, k ceremony.Kind) (string, error) {
	if b.pending.Transport() == core.TransportBearer {
		return b.bind.Value(), nil
	}
	return "", s.cookies.SetBind(w, b.bind, k)
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

func (s *Service) clearBind(w http.ResponseWriter, p core.Pending) {
	if p.Transport() == core.TransportCookies {
		s.cookies.Clear(w, cookie.Bind)
	}
}

func (s *Service) eligible(ctx context.Context, t core.TenantID, id identity.Identifier) (identity.User, core.AccountState, bool, error) {
	u, err := s.identity.FindUser(ctx, t, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return identity.User{}, core.AccountState{}, false, nil
	case err != nil:
		return identity.User{}, core.AccountState{}, false, err
	}
	if u.EmailVerifiedAt.IsZero() || !u.DisabledAt.IsZero() || !u.DeletedAt.IsZero() {
		return identity.User{}, core.AccountState{}, false, nil
	}
	switch id.Kind() {
	case identity.IdentifierEmail:
		if u.Email != id {
			return identity.User{}, core.AccountState{}, false, nil
		}
	case identity.IdentifierPhone:
		if u.Phone != id || u.PhoneVerifiedAt.IsZero() {
			return identity.User{}, core.AccountState{}, false, nil
		}
	default:
		return identity.User{}, core.AccountState{}, false, nil
	}
	st, err := s.accounts.AccountState(ctx, u.Subject)
	if err != nil {
		return identity.User{}, core.AccountState{}, false, err
	}
	if !st.Usable() || !st.EmailVerified() {
		return identity.User{}, core.AccountState{}, false, nil
	}
	return u, st, true, nil
}

func (s *Service) putRecord(ctx context.Context, p core.Pending, k ceremony.Kind, handle ceremonycodec.Handle, id identity.Identifier, payload []byte) (ceremony.Record, error) {
	sealed, err := core.SealPending(p)
	if err != nil {
		return ceremony.Record{}, err
	}
	scope, err := s.scopes.Scope(id)
	if err != nil {
		return ceremony.Record{}, err
	}
	rec, err := ceremony.NewRecord(ceremony.Spec{
		Kind: k, HandleHash: handle.Hash(), Scope: scope, Pending: sealed, Payload: payload, Now: s.clock.Now(),
	}, openPending)
	if err != nil {
		return ceremony.Record{}, err
	}
	if _, err := s.ceremonies.Put(ctx, rec); err != nil {
		return ceremony.Record{}, err
	}
	return rec, nil
}

func openPending(sealed principal.Sealed) (ceremony.PendingBinding, error) {
	p, err := core.UnsealPending(sealed)
	if err != nil {
		return ceremony.PendingBinding{}, err
	}
	sub, _ := p.Subject()
	return ceremony.PendingBinding{Tenant: p.Tenant(), Subject: sub, ExpiresAt: p.ExpiresAt()}, nil
}

func openBound(rec ceremony.Record, t core.TenantID, invalid error) (core.Pending, core.Subject, error) {
	p, err := core.UnsealPending(rec.Pending)
	if err != nil {
		return core.Pending{}, core.Subject{}, errors.Join(invalid, err)
	}
	sub, ok := p.Subject()
	if !ok {
		return core.Pending{}, core.Subject{}, invalid
	}
	if p.Tenant() != t || rec.Tenant() != t || sub.Tenant != t {
		return core.Pending{}, core.Subject{}, httpx.ErrUnauthenticated
	}
	return p, sub, nil
}

func lookupProblem(err error, invalid error) error {
	if errors.Is(err, store.ErrNotFound) {
		return errors.Join(invalid, err)
	}
	return errors.Join(httpx.ErrServiceUnavailable, err)
}

func accountHint(email identity.Identifier) string {
	local, domain, _ := strings.Cut(email.Value(), "@")
	first, _ := utf8.DecodeRuneInString(local)
	return string(first) + "***@" + domain
}
