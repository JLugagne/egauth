package federationsvc

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
)

const (
	exchangeSep  = "."
	exchangeInfo = "egauth/oauth-exchange/v1"
)

var providerName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func exchangeKey(h ceremonycodec.Handle, provider string) []byte {
	sum := sha256.New()
	sum.Write([]byte(exchangeInfo))
	sum.Write([]byte{0})
	sum.Write(h.Hash())
	sum.Write([]byte{0})
	sum.Write([]byte(provider))
	return sum.Sum(nil)
}

func parseExchange(raw string) (ceremonycodec.Handle, string, bool) {
	enc, provider, ok := strings.Cut(raw, exchangeSep)
	if !ok || !providerName.MatchString(provider) {
		return ceremonycodec.Handle{}, "", false
	}
	h, err := ceremonycodec.ParseHandle(enc)
	if err != nil {
		return ceremonycodec.Handle{}, "", false
	}
	return h, provider, true
}

func (h *handlers) putExchange(r *httpx.Request, p core.Pending, sub core.Subject, key []byte) error {
	sealed, err := core.SealPending(p)
	if err != nil {
		return errors.Join(httpx.ErrInternal, err)
	}
	payload, err := ceremonycodec.Exchange().Encode(ceremonycodec.Empty{})
	if err != nil {
		return errors.Join(httpx.ErrInternal, err)
	}
	rec, err := ceremony.NewRecord(ceremony.Spec{
		Kind: ceremony.Exchange, HandleHash: key, Scope: ceremony.SubjectScope(sub), Pending: sealed, Payload: payload, Now: h.clock.Now(),
	}, openPending)
	if err != nil {
		return errors.Join(ErrInvalidState, err)
	}
	if _, err := h.ceremonies.Put(r.Context(), rec); err != nil {
		return unavailable(err)
	}
	return nil
}

func openPending(sealed principal.Sealed) (ceremony.PendingBinding, error) {
	p, err := core.UnsealPending(sealed)
	if err != nil {
		return ceremony.PendingBinding{}, err
	}
	sub, _ := p.Subject()
	return ceremony.PendingBinding{Tenant: p.Tenant(), Subject: sub, ExpiresAt: p.ExpiresAt()}, nil
}

func openExchange(rec ceremony.Record, t core.TenantID) (core.Pending, core.Subject, error) {
	p, err := core.UnsealPending(rec.Pending)
	if err != nil {
		return core.Pending{}, core.Subject{}, errors.Join(ErrInvalidToken, err)
	}
	sub, ok := p.Subject()
	switch {
	case !ok || p.Transport() != core.TransportBearer:
		return core.Pending{}, core.Subject{}, ErrInvalidToken
	case p.Tenant() != t || rec.Tenant() != t || sub.Tenant != t:
		return core.Pending{}, core.Subject{}, httpx.ErrUnauthenticated
	case !rec.ScopedTo(ceremony.SubjectScope(sub)):
		return core.Pending{}, core.Subject{}, ErrInvalidToken
	}
	return p, sub, nil
}

func lookupProblem(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return errors.Join(ErrInvalidToken, err)
	}
	return unavailable(err)
}

func (h *handlers) exchange(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	t := r.Tenant()
	handle, provider, ok := parseExchange(r.Field(routes.FieldHandle))
	if !ok {
		r.Fail(w, ErrInvalidToken)
		return
	}
	key := exchangeKey(handle, provider)
	rec, err := h.ceremonies.Peek(ctx, t, ceremony.Exchange, key)
	if err != nil {
		r.Fail(w, lookupProblem(err))
		return
	}
	p, _, err := openExchange(rec, t)
	if err != nil {
		r.Fail(w, err)
		return
	}
	if !cookie.VerifyBind(r.Field(routes.FieldBind), p.BindHash()) {
		if _, err := h.ceremonies.RecordFailure(ctx, t, ceremony.Exchange, key); err != nil && !errors.Is(err, store.ErrNotFound) {
			r.Fail(w, unavailable(err))
			return
		}
		r.Fail(w, ErrUnboundCeremony)
		return
	}
	if rec, err = h.ceremonies.Consume(ctx, t, ceremony.Exchange, key); err != nil {
		r.Fail(w, lookupProblem(err))
		return
	}
	p, sub, err := openExchange(rec, t)
	if err != nil {
		r.Fail(w, err)
		return
	}
	h.complete(w, r, p, sub, provider)
}
