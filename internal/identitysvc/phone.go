package identitysvc

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
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

const (
	phoneCodeDigits    = 6
	statePhoneCodeSent = "phone_code_sent"
	statePhoneVerified = "phone_verified"
)

type handleBody struct {
	State  string `json:"state"`
	Handle string `json:"handle"`
}

func (h *acctHandlers) requestPhoneVerification(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	c, err := h.currentAccount(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	phone, err := NormalizeAs(identity.IdentifierPhone, r.Field(routes.FieldPhone))
	if err != nil {
		r.Fail(w, errors.Join(ErrInvalidIdentifier, err))
		return
	}
	if phone == c.user.Phone && !c.user.PhoneVerifiedAt.IsZero() {
		r.Fail(w, ErrIdentifierUnchanged)
		return
	}
	p, err := h.boundPending(ctx, r, c)
	if err != nil {
		r.Fail(w, err)
		return
	}
	code, err := newPhoneCode()
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	handle, rec, err := h.putPhoneCode(ctx, p, phone, code)
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrServiceUnavailable, err))
		return
	}
	h.sendPhoneCode(ctx, CodeMessage{Tenant: r.Tenant(), To: phone.Value(), Code: code, ExpiresAt: rec.ExpiresAt()})
	r.Respond(w, httpx.Response{Body: handleBody{State: statePhoneCodeSent, Handle: handle.Encode()}})
}

func (a *Accounts) putPhoneCode(ctx context.Context, p core.Pending, phone identity.Identifier, code string) (ceremonycodec.Handle, ceremony.Record, error) {
	digest, err := ceremonycodec.NewCode(a.sealer, code)
	if err != nil {
		return ceremonycodec.Handle{}, ceremony.Record{}, err
	}
	payload, err := ceremonycodec.PhoneVerification().Encode(ceremonycodec.PhoneCode{Code: digest, Phone: phone.Value()})
	if err != nil {
		return ceremonycodec.Handle{}, ceremony.Record{}, err
	}
	return a.putSubjectCeremony(ctx, p, ceremony.PhoneVerification, payload)
}

func (a *Accounts) sendPhoneCode(ctx context.Context, m CodeMessage) {
	m.DeliveryID = uuid.New()
	a.mail.enqueue(ctx, m.Tenant, m.DeliveryID, func(c context.Context) error {
		return a.texter.PhoneVerificationCode(c, m)
	})
}

func newPhoneCode() (string, error) {
	limit := big.NewInt(1)
	for range phoneCodeDigits {
		limit.Mul(limit, big.NewInt(10))
	}
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return "", err
	}
	s := n.String()
	return strings.Repeat("0", phoneCodeDigits-len(s)) + s, nil
}

func (h *acctHandlers) verifyPhone(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	c, err := h.currentAccount(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	phone, p, err := h.checkPhoneCode(ctx, r, c)
	if err != nil {
		r.Fail(w, err)
		return
	}
	if p.EpochAtBind() != c.state.Epoch() {
		r.Fail(w, ErrInvalidToken)
		return
	}
	if err := h.applyIdentifier(ctx, identity.SetPhone{Subject: c.user.Subject, Phone: phone}); err != nil {
		r.Fail(w, err)
		return
	}
	_ = h.audit.Emit(ctx, event.PhoneVerified, scopeOf(c.user.Subject), audit.Detail{}, nil,
		audit.A(event.KeyIdentifierKind, identity.IdentifierPhone.String()))
	r.Respond(w, httpx.Response{Body: journeyBody{State: statePhoneVerified}})
}

func (a *Accounts) checkPhoneCode(ctx context.Context, r *httpx.Request, c current) (identity.Identifier, core.Pending, error) {
	handle, err := ceremonycodec.ParseHandle(r.Field(routes.FieldHandle))
	if err != nil {
		return identity.Identifier{}, core.Pending{}, errors.Join(ErrInvalidToken, err)
	}
	t, sub := r.Tenant(), c.user.Subject
	rec, err := a.ceremonies.Peek(ctx, t, ceremony.PhoneVerification, handle.Hash())
	if err != nil {
		return identity.Identifier{}, core.Pending{}, ceremonyProblem(err)
	}
	if _, bound, err := openReset(rec, t); err != nil || bound != sub || !rec.ScopedTo(ceremony.SubjectScope(sub)) {
		return identity.Identifier{}, core.Pending{}, errors.Join(ErrInvalidToken, err)
	}
	pc, err := ceremonycodec.PhoneVerification().Decode(rec.Payload())
	if err != nil {
		return identity.Identifier{}, core.Pending{}, errors.Join(ErrInvalidToken, err)
	}
	remaining, err := a.ceremonies.RecordFailure(ctx, t, ceremony.PhoneVerification, handle.Hash())
	if err != nil {
		return identity.Identifier{}, core.Pending{}, ceremonyProblem(err)
	}
	if !pc.Code.Matches(a.sealer, r.Field(routes.FieldCode)) {
		return identity.Identifier{}, core.Pending{}, ErrInvalidCode
	}
	if remaining > 0 {
		if rec, err = a.ceremonies.Consume(ctx, t, ceremony.PhoneVerification, handle.Hash()); err != nil {
			return identity.Identifier{}, core.Pending{}, ceremonyProblem(err)
		}
	}
	p, bound, err := openReset(rec, t)
	if err != nil || bound != sub {
		return identity.Identifier{}, core.Pending{}, errors.Join(ErrInvalidToken, err)
	}
	if pc, err = ceremonycodec.PhoneVerification().Decode(rec.Payload()); err != nil {
		return identity.Identifier{}, core.Pending{}, errors.Join(ErrInvalidToken, err)
	}
	phone, err := identity.NewIdentifier(identity.IdentifierPhone, pc.Phone)
	if err != nil {
		return identity.Identifier{}, core.Pending{}, errors.Join(ErrInvalidToken, err)
	}
	return phone, p, nil
}
