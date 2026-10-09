package codesvc

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

const (
	codeDigits    = 6
	stateCodeSent = "code_sent"
)

type handleBody struct {
	State  string `json:"state"`
	Handle string `json:"handle"`
	Bind   string `json:"bind,omitempty"`
}

func (s *Service) kindFor(id identity.Identifier) (ceremony.Kind, bool) {
	switch id.Kind() {
	case identity.IdentifierEmail:
		return ceremony.EmailCode, s.emailCodes
	case identity.IdentifierPhone:
		return ceremony.SMSCode, s.smsCodes
	}
	return 0, false
}

func (s *Service) codeKinds() []ceremony.Kind {
	var out []ceremony.Kind
	if s.emailCodes {
		out = append(out, ceremony.EmailCode)
	}
	if s.smsCodes {
		out = append(out, ceremony.SMSCode)
	}
	return out
}

func (h *handlers) requestCode(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	id, err := identitysvc.Normalize(r.Field(routes.FieldIdentifier))
	if err != nil {
		r.Fail(w, errors.Join(ErrInvalidIdentifier, err))
		return
	}
	k, enabled := h.kindFor(id)
	if !enabled {
		r.Fail(w, ErrInvalidIdentifier)
		return
	}
	j, err := h.begin(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	handle, err := ceremonycodec.NewHandle()
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	bind, err := h.deliverBind(w, j, k)
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	p := j.pending
	h.work.enqueue(ctx, r.Tenant(), func(c context.Context, delivery uuid.UUID) error {
		return h.sendCode(c, delivery, p, k, handle, id)
	})
	r.RespondPending(w, p, httpx.Response{Body: handleBody{State: stateCodeSent, Handle: handle.Encode(), Bind: bind}})
}

func (s *Service) sendCode(ctx context.Context, delivery uuid.UUID, p core.Pending, k ceremony.Kind, handle ceremonycodec.Handle, id identity.Identifier) error {
	u, st, ok, err := s.eligible(ctx, p.Tenant(), id)
	if err != nil || !ok {
		return err
	}
	p, err = p.Bind(u.Subject, st)
	if err != nil {
		return err
	}
	code, err := newCode()
	if err != nil {
		return err
	}
	digest, err := ceremonycodec.NewCode(s.sealer, code)
	if err != nil {
		return err
	}
	payload, err := codecOf(k).Encode(digest)
	if err != nil {
		return err
	}
	rec, err := s.putRecord(ctx, p, k, handle, id, payload)
	if err != nil {
		return err
	}
	m := CodeMessage{DeliveryID: delivery, Tenant: p.Tenant(), To: id.Value(), Code: code, ExpiresAt: rec.ExpiresAt()}
	if k == ceremony.SMSCode {
		return s.texter.LoginCode(ctx, m)
	}
	return s.mailer.LoginCode(ctx, m)
}

func codecOf(k ceremony.Kind) ceremonycodec.Codec[ceremonycodec.Code] {
	if k == ceremony.SMSCode {
		return ceremonycodec.SMSCode()
	}
	return ceremonycodec.EmailCode()
}

func newCode() (string, error) {
	limit := big.NewInt(1)
	for range codeDigits {
		limit.Mul(limit, big.NewInt(10))
	}
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return "", err
	}
	s := n.String()
	return strings.Repeat("0", codeDigits-len(s)) + s, nil
}

func wellFormedCode(code string) bool {
	if len(code) != codeDigits {
		return false
	}
	for i := range len(code) {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

func (h *handlers) verifyCode(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	p, sub, k, err := h.checkCode(ctx, r)
	if err != nil {
		if errors.Is(err, ErrInvalidCode) {
			_ = h.audit.Emit(ctx, event.LoginFailed, audit.Scope{TenantID: r.Tenant().String()},
				audit.Detail{Reason: ErrInvalidCode.Code()}, nil, audit.A(event.KeyMethod, "code"))
		}
		r.Fail(w, err)
		return
	}
	var v core.Verified
	if k == ceremony.SMSCode {
		v, err = factors.SMSCode(sub, h.clock.Now())
	} else {
		v, err = factors.EmailCode(sub, h.clock.Now())
	}
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

func (s *Service) checkCode(ctx context.Context, r *httpx.Request) (core.Pending, core.Subject, ceremony.Kind, error) {
	t := r.Tenant()
	handle, err := ceremonycodec.ParseHandle(r.Field(routes.FieldHandle))
	if err != nil {
		return core.Pending{}, core.Subject{}, 0, errors.Join(ErrInvalidCode, err)
	}
	code := strings.TrimSpace(r.Field(routes.FieldCode))
	if !wellFormedCode(code) {
		return core.Pending{}, core.Subject{}, 0, ErrInvalidCode
	}
	rec, k, err := s.find(ctx, t, handle)
	if errors.Is(err, ErrInvalidCode) {
		s.decoyCheck(ctx, t, code)
	}
	if err != nil {
		return core.Pending{}, core.Subject{}, 0, err
	}
	p, sub, err := openBound(rec, t, ErrInvalidCode)
	if err != nil {
		return core.Pending{}, core.Subject{}, 0, err
	}
	if !s.presentedBind(r, p) {
		s.decoyCheck(ctx, t, code)
		return core.Pending{}, core.Subject{}, 0, ErrInvalidCode
	}
	digest, err := codecOf(k).Decode(rec.Payload())
	if err != nil {
		return core.Pending{}, core.Subject{}, 0, errors.Join(ErrInvalidCode, err)
	}
	remaining, err := s.ceremonies.RecordFailure(ctx, t, k, handle.Hash())
	if err != nil {
		return core.Pending{}, core.Subject{}, 0, lookupProblem(err, ErrInvalidCode)
	}
	if !digest.Matches(s.sealer, code) {
		return core.Pending{}, core.Subject{}, 0, ErrInvalidCode
	}
	if remaining == 0 {
		return p, sub, k, nil
	}
	if rec, err = s.ceremonies.Consume(ctx, t, k, handle.Hash()); err != nil {
		return core.Pending{}, core.Subject{}, 0, lookupProblem(err, ErrInvalidCode)
	}
	if p, sub, err = openBound(rec, t, ErrInvalidCode); err != nil {
		return core.Pending{}, core.Subject{}, 0, err
	}
	return p, sub, k, nil
}

func (s *Service) find(ctx context.Context, t core.TenantID, handle ceremonycodec.Handle) (ceremony.Record, ceremony.Kind, error) {
	var (
		found ceremony.Record
		kind  ceremony.Kind
		hit   bool
	)
	for _, k := range s.codeKinds() {
		rec, err := s.ceremonies.Peek(ctx, t, k, handle.Hash())
		switch {
		case err == nil && !hit:
			found, kind, hit = rec, k, true
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return ceremony.Record{}, 0, errors.Join(httpx.ErrServiceUnavailable, err)
		}
	}
	if !hit {
		return ceremony.Record{}, 0, ErrInvalidCode
	}
	return found, kind, nil
}

func (s *Service) decoyCheck(ctx context.Context, t core.TenantID, code string) {
	kinds := s.codeKinds()
	if len(kinds) == 0 {
		return
	}
	_, _ = s.ceremonies.RecordFailure(ctx, t, kinds[0], s.decoy.handle.Hash())
	_ = s.decoy.code.Matches(s.sealer, code)
}
