package egauth

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/codesvc"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/externalsvc"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/issuance"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/limiter"
)

var (
	errNoEmailDeliverer = errors.New("egauth: the deployment has no EmailDeliverer")
	errNoSMSDeliverer   = errors.New("egauth: the deployment has no SMSDeliverer")
)

type claimsWire[C any] struct {
	Roles  []string `json:"roles"`
	Groups []string `json:"groups"`
	Scopes []string `json:"scopes"`
	Custom C        `json:"custom"`
}

type claimsAdapter[C any] struct {
	src ClaimsSource[C]
}

func (a claimsAdapter[C]) ClaimsFor(ctx context.Context, s core.Subject) ([]byte, error) {
	c, err := a.src.ClaimsFor(ctx, s)
	if errors.Is(err, ErrUnknownSubject) {
		return nil, errors.Join(session.ErrUnknownSubject, err)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(claimsWire[C]{Roles: nonNil(c.Roles), Groups: nonNil(c.Groups), Scopes: nonNil(c.Scopes), Custom: c.Custom})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type emailAdapter struct {
	d     EmailDeliverer
	audit httpx.Audit
}

func (a emailAdapter) link(m identitysvc.LinkMessage) LinkMessage {
	return LinkMessage{DeliveryID: m.DeliveryID, Tenant: m.Tenant, To: m.To, Link: m.Link, ExpiresAt: m.ExpiresAt}
}

func (a emailAdapter) RegistrationLink(ctx context.Context, m identitysvc.LinkMessage) error {
	if a.d == nil {
		return errNoEmailDeliverer
	}
	return a.d.RegistrationLink(ctx, a.link(m))
}

func (a emailAdapter) AccountExistsNotice(ctx context.Context, m identitysvc.NoticeMessage) error {
	if a.d == nil {
		return errNoEmailDeliverer
	}
	return a.d.AccountExistsNotice(ctx, NoticeMessage{DeliveryID: m.DeliveryID, Tenant: m.Tenant, To: m.To})
}

func (a emailAdapter) PasswordResetLink(ctx context.Context, m identitysvc.LinkMessage) error {
	if a.d == nil {
		return errNoEmailDeliverer
	}
	return a.d.PasswordResetLink(ctx, a.link(m))
}

func (a emailAdapter) MagicLink(ctx context.Context, m identitysvc.LinkMessage) error {
	if a.d == nil {
		return errNoEmailDeliverer
	}
	return a.d.MagicLink(ctx, a.link(m))
}

func (a emailAdapter) LoginCode(ctx context.Context, m codesvc.CodeMessage) error {
	if a.d == nil {
		return errNoEmailDeliverer
	}
	return a.d.LoginCode(ctx, CodeMessage{DeliveryID: m.DeliveryID, Tenant: m.Tenant, To: m.To, Code: m.Code, ExpiresAt: m.ExpiresAt})
}

func (a emailAdapter) EmailVerificationLink(ctx context.Context, m identitysvc.LinkMessage) error {
	if a.d == nil {
		return errNoEmailDeliverer
	}
	return a.d.EmailVerificationLink(ctx, a.link(m))
}

func (a emailAdapter) EmailChangeLink(ctx context.Context, m identitysvc.LinkMessage) error {
	if a.d == nil {
		return errNoEmailDeliverer
	}
	return a.d.EmailChangeLink(ctx, a.link(m))
}

func (a emailAdapter) RecoveryEmailLink(ctx context.Context, m identitysvc.LinkMessage) error {
	if a.d == nil {
		return errNoEmailDeliverer
	}
	return a.d.RecoveryEmailLink(ctx, a.link(m))
}

func (a emailAdapter) SecurityNotice(ctx context.Context, m identitysvc.SecurityNoticeMessage) error {
	if a.d == nil {
		_ = a.audit.Emit(ctx, event.DeliveryFailed, audit.Scope{TenantID: m.Tenant.String()},
			audit.Detail{Reason: "no_email_deliverer"}, errNoEmailDeliverer, audit.A(event.KeyDeliveryID, m.DeliveryID.String()))
		return nil
	}
	return a.d.SecurityNotice(ctx, SecurityNoticeMessage{
		DeliveryID: m.DeliveryID, Tenant: m.Tenant, To: m.To, Event: SecurityEvent(m.Event), Summary: m.Summary,
		RevertLink: m.RevertLink, OccurredAt: m.OccurredAt, Client: ClientInfo{IP: m.Client.IP, UserAgent: m.Client.UserAgent},
	})
}

type smsAdapter struct {
	d SMSDeliverer
}

func (a smsAdapter) PhoneVerificationCode(ctx context.Context, m identitysvc.CodeMessage) error {
	if a.d == nil {
		return errNoSMSDeliverer
	}
	return a.d.PhoneVerificationCode(ctx, CodeMessage{DeliveryID: m.DeliveryID, Tenant: m.Tenant, To: m.To, Code: m.Code, ExpiresAt: m.ExpiresAt})
}

func (a smsAdapter) LoginCode(ctx context.Context, m codesvc.CodeMessage) error {
	if a.d == nil {
		return errNoSMSDeliverer
	}
	return a.d.LoginCode(ctx, CodeMessage{DeliveryID: m.DeliveryID, Tenant: m.Tenant, To: m.To, Code: m.Code, ExpiresAt: m.ExpiresAt})
}

type externalVerifier struct {
	f ExternalFactor
}

func (v externalVerifier) Name() string { return v.f.Name() }

func (v externalVerifier) Verify(ctx context.Context, req externalsvc.Request) (externalsvc.Identity, error) {
	id, err := v.f.Verify(ctx, ExternalRequest{Tenant: req.Tenant, Identifier: req.Identifier, Secret: req.Secret})
	if err != nil {
		return externalsvc.Identity{}, err
	}
	return externalsvc.Identity{ExternalID: id.ExternalID, Email: id.Email, EmailVerified: id.EmailVerified}, nil
}

type identifiers struct{}

func (identifiers) Normalize(raw string) (identity.Identifier, error) {
	return identitysvc.Normalize(raw)
}

type endpointHook struct {
	hook func(ctx context.Context, req EndpointRequest) error
	poke func()
}

func (h endpointHook) BeforeEndpoint(ctx context.Context, c httpx.EndpointCall) error {
	h.poke()
	if h.hook == nil {
		return nil
	}
	return h.hook(ctx, EndpointRequest{
		Endpoint: EndpointID(c.Endpoint), Client: c.Client, Tenant: c.Tenant, CaptchaToken: c.CaptchaToken(),
	})
}

type lateOutbox struct {
	target atomic.Pointer[lifecycle.Dispatcher]
}

func (l *lateOutbox) DispatchOutbox(ctx context.Context, items []identity.OutboxItem) {
	if d := l.target.Load(); d != nil {
		d.DispatchOutbox(ctx, items)
	}
}

type latePendings struct {
	target atomic.Pointer[issuance.Issuer]
}

var errPendingsUnset = errors.New("egauth: the issuer is not wired yet")

func (l *latePendings) Detached(ctx context.Context, t core.TenantID) (core.Pending, error) {
	i := l.target.Load()
	if i == nil {
		return core.Pending{}, errPendingsUnset
	}
	return i.Detached(ctx, t)
}

type scaledLimiter struct {
	inner     limiter.Limiter
	instances atomic.Int32
}

func (s *scaledLimiter) Allow(ctx context.Context, key limiter.Key) (limiter.Decision, error) {
	n := int(s.instances.Load())
	budget := key.Class.Budget().Burst
	tokens := max(1, min(n, budget))
	var last limiter.Decision
	for range tokens {
		d, err := s.inner.Allow(ctx, key)
		if err != nil {
			return limiter.Decision{}, err
		}
		last = d
		if !d.Allowed {
			return d, nil
		}
	}
	return last, nil
}

func (s *scaledLimiter) setInstances(n int) {
	s.instances.Store(int32(max(n, 1)))
}
