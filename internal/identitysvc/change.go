package identitysvc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

// ErrInvalidAccountsConfig is returned by NewAccounts, joined with one error per missing member.
var ErrInvalidAccountsConfig = errors.New("identitysvc: invalid account management configuration")

// The problems the account management endpoints answer besides those of the password endpoints.
var (
	ErrInvalidCode         = httpx.NewProblem(http.StatusBadRequest, "invalid_code")
	ErrEmailUnverified     = httpx.NewProblem(http.StatusForbidden, "email_unverified")
	ErrIdentifierUnchanged = httpx.NewProblem(http.StatusBadRequest, "identifier_unchanged")
)

// SecurityEvent classifies a security notice; its values equal egauth.SecurityEvent's and are
// persisted in the SecurityRevert payload, so a value is never renumbered or reused.
type SecurityEvent uint8

const (
	SecurityCredentialRotated SecurityEvent = 1
	SecurityFactorsChanged    SecurityEvent = 2
	SecurityIdentifierChanged SecurityEvent = 3
)

// CodeMessage is a short code to text. Code is a bearer secret until ExpiresAt: fmt and slog render
// it REDACTED.
type CodeMessage struct {
	DeliveryID uuid.UUID
	Tenant     core.TenantID
	To         string
	Code       string
	ExpiresAt  time.Time
}

func (m CodeMessage) String() string {
	return "identitysvc.CodeMessage{DeliveryID: " + m.DeliveryID.String() + ", Code: " + redacted + "}"
}

func (m CodeMessage) GoString() string { return m.String() }

func (m CodeMessage) LogValue() slog.Value {
	return slog.GroupValue(slog.String("delivery_id", m.DeliveryID.String()), slog.String("code", redacted))
}

// ClientInfo mirrors egauth.ClientInfo: the client behind a security change; either field may be
// empty.
type ClientInfo struct {
	IP        netip.Addr
	UserAgent string
}

// SecurityNoticeMessage tells the owner of To that a security change happened. RevertLink undoes it
// for seven days and is empty when no revert applies: fmt and slog render it REDACTED. DeliveryID is
// derived from the outbox row, so a retried notice keeps it.
type SecurityNoticeMessage struct {
	DeliveryID uuid.UUID
	Tenant     core.TenantID
	To         string
	Event      SecurityEvent
	Summary    string
	RevertLink string
	OccurredAt time.Time
	Client     ClientInfo
}

func (m SecurityNoticeMessage) String() string {
	return "identitysvc.SecurityNoticeMessage{DeliveryID: " + m.DeliveryID.String() + ", Event: " +
		strconv.Itoa(int(m.Event)) + ", RevertLink: " + redacted + "}"
}

func (m SecurityNoticeMessage) GoString() string { return m.String() }

func (m SecurityNoticeMessage) LogValue() slog.Value {
	return slog.GroupValue(slog.String("delivery_id", m.DeliveryID.String()), slog.Int("event", int(m.Event)),
		slog.String("revert_link", redacted))
}

// AccountMailer delivers the account management emails; the composition adapts egauth.EmailDeliverer
// to it. Links run on the service's bounded background dispatcher; SecurityNotice runs on the
// lifecycle outbox, which retries it until it returns nil. A method must be idempotent on DeliveryID.
type AccountMailer interface {
	EmailVerificationLink(ctx context.Context, m LinkMessage) error
	EmailChangeLink(ctx context.Context, m LinkMessage) error
	RecoveryEmailLink(ctx context.Context, m LinkMessage) error
	SecurityNotice(ctx context.Context, m SecurityNoticeMessage) error
}

// Texter delivers the phone verification code; the composition adapts egauth.SMSDeliverer to it. It
// runs on the background dispatcher and must be idempotent on DeliveryID.
type Texter interface {
	PhoneVerificationCode(ctx context.Context, m CodeMessage) error
}

// PendingSource starts the unbound Pending sealed into a ceremony created outside any request: the
// revert link of a security notice. identitysvc may not create a Pending itself (G6), so
// internal/issuance implements it.
type PendingSource interface {
	Detached(ctx context.Context, t core.TenantID) (core.Pending, error)
}

// AccountsConfig is what NewAccounts needs. Mailer and Pendings are always required; Texter and
// Sealer (which keys the texted code) are required with Phone. Email, Phone, RecoveryEmail and
// SelfDelete mount the endpoints of Modules.Verification and Modules.SelfDelete.
type AccountsConfig struct {
	Mailer        AccountMailer
	Texter        Texter
	Sealer        *ceremonycodec.Sealer
	Pendings      PendingSource
	Email         bool
	Phone         bool
	RecoveryEmail bool
	SelfDelete    bool
}

// Accounts serves the account management endpoints of a Service and the security notices of its
// lifecycle outbox. It is safe for concurrent use and shares the Service's delivery workers, so it
// stops sending when the Service is closed.
type Accounts struct {
	*Service
	mailer     AccountMailer
	texter     Texter
	sealer     *ceremonycodec.Sealer
	pendings   PendingSource
	email      bool
	phone      bool
	recovery   bool
	selfDelete bool
}

// NewAccounts validates cfg against s and reports every problem at once as ErrInvalidAccountsConfig
// joined with the member names; a typed nil member counts as missing.
func NewAccounts(s *Service, cfg AccountsConfig) (*Accounts, error) {
	var errs []error
	need := func(ok bool, name string) {
		if !ok {
			errs = append(errs, errors.New(name))
		}
	}
	need(s != nil, "Service")
	need(present(cfg.Mailer), "Mailer")
	need(present(cfg.Pendings), "Pendings")
	need(!cfg.Phone || present(cfg.Texter), "Texter")
	need(!cfg.Phone || cfg.Sealer != nil, "Sealer")
	if len(errs) > 0 {
		return nil, errors.Join(ErrInvalidAccountsConfig, errors.Join(errs...))
	}
	return &Accounts{
		Service:    s,
		mailer:     cfg.Mailer,
		texter:     cfg.Texter,
		sealer:     cfg.Sealer,
		pendings:   cfg.Pendings,
		email:      cfg.Email,
		phone:      cfg.Phone,
		recovery:   cfg.RecoveryEmail,
		selfDelete: cfg.SelfDelete,
	}, nil
}

// Endpoints returns the account management endpoints served through issuer: /password/change and
// /security/revert always, plus those of the enabled channels and of self-deletion. It returns
// ErrNilIssuer or the error of routes.NewEndpoint.
//
// Every authenticated endpoint refuses (401) a session sealed before the account's last security
// change, and every link or code refuses a ceremony bound before it (C-17). A password change keeps
// the current session and ends the others; an email, phone or recovery email change ends them all
// (DESIGN §7.2). A /security/revert link is single-use: it locks the hijacker out, restores the
// notified email, removes the factors and identifiers added since the earliest change still
// revertible from that address and sends a reset link; a refused or failed revert leaves it usable.
// When the notified email now belongs to another account, the account is disabled instead (409).
func (a *Accounts) Endpoints(issuer httpx.Issuer) ([]routes.Endpoint, error) {
	if issuer == nil {
		return nil, ErrNilIssuer
	}
	h := &acctHandlers{Accounts: a, issuer: issuer}
	fns := []route{
		{routes.PasswordChange, h.changePassword},
		{routes.SecurityRevert, h.revert},
	}
	if a.email {
		fns = append(fns,
			route{routes.EmailVerifyRequest, h.requestEmailVerification},
			route{routes.EmailVerify, h.verifyEmail},
			route{routes.EmailChange, h.requestEmailChange},
			route{routes.EmailChangeConfirm, h.confirmEmailChange},
		)
	}
	if a.phone {
		fns = append(fns, route{routes.PhoneVerifyRequest, h.requestPhoneVerification}, route{routes.PhoneVerify, h.verifyPhone})
	}
	if a.recovery {
		fns = append(fns, route{routes.RecoveryEmail, h.requestRecoveryEmail}, route{routes.RecoveryEmailConfirm, h.confirmRecoveryEmail})
	}
	if a.selfDelete {
		fns = append(fns, route{routes.AccountDelete, h.deleteAccount})
	}
	out := make([]routes.Endpoint, 0, len(fns))
	for _, e := range fns {
		ep, err := routes.NewEndpoint(e.path, e.f)
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, nil
}

type acctHandlers struct {
	*Accounts
	issuer httpx.Issuer
}

type current struct {
	attrs core.SessionAttrs
	user  identity.User
	state core.AccountState
}

func (s *Service) currentAccount(ctx context.Context, r *httpx.Request) (current, error) {
	res, ok := r.Session()
	if !ok {
		return current{}, httpx.ErrUnauthenticated
	}
	a := res.Attrs()
	u, err := s.identity.GetUser(ctx, a.Subject())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return current{}, errors.Join(httpx.ErrUnauthenticated, err)
	case err != nil:
		return current{}, errors.Join(httpx.ErrServiceUnavailable, err)
	}
	st := stateOf(u)
	if !st.Usable() || st.Epoch() != a.Epoch() {
		return current{}, httpx.ErrUnauthenticated
	}
	return current{attrs: a, user: u, state: st}, nil
}

func (h *acctHandlers) boundPending(ctx context.Context, r *httpx.Request, c current) (core.Pending, error) {
	p, err := h.issuer.Begin(ctx, r)
	if err != nil {
		return core.Pending{}, err
	}
	p, err = p.Bind(c.user.Subject, c.state)
	if err != nil {
		return core.Pending{}, errors.Join(httpx.ErrInternal, err)
	}
	return p, nil
}

func (s *Service) putSubjectCeremony(ctx context.Context, p core.Pending, k ceremony.Kind, payload []byte) (ceremonycodec.Handle, ceremony.Record, error) {
	sub, _ := p.Subject()
	handle, rec, err := s.newRecord(p, k, ceremony.SubjectScope(sub), payload)
	if err != nil {
		return ceremonycodec.Handle{}, ceremony.Record{}, err
	}
	if _, err := s.ceremonies.Put(ctx, rec); err != nil {
		return ceremonycodec.Handle{}, ceremony.Record{}, err
	}
	return handle, rec, nil
}

func (s *Service) sendLink(ctx context.Context, p core.Pending, k ceremony.Kind, payload []byte, to string, send func(context.Context, LinkMessage) error) {
	id := uuid.New()
	t := p.Tenant()
	s.mail.enqueue(ctx, t, id, func(c context.Context) error {
		handle, rec, err := s.putSubjectCeremony(c, p, k, payload)
		if err != nil {
			return err
		}
		link, err := s.links.Link(c, t, k, handle.Encode())
		if err != nil {
			return err
		}
		return send(c, LinkMessage{DeliveryID: id, Tenant: t, To: to, Link: link, ExpiresAt: rec.ExpiresAt()})
	})
}

type consumed struct {
	pending core.Pending
	subject core.Subject
	record  ceremony.Record
	user    identity.User
	state   core.AccountState
}

func (s *Service) consumeBound(ctx context.Context, r *httpx.Request, k ceremony.Kind, field string) (consumed, error) {
	handle, err := ceremonycodec.ParseHandle(r.Field(field))
	if err != nil {
		return consumed{}, errors.Join(ErrInvalidToken, err)
	}
	rec, err := s.ceremonies.Peek(ctx, r.Tenant(), k, handle.Hash())
	if err != nil {
		return consumed{}, ceremonyProblem(err)
	}
	if _, _, err := openReset(rec, r.Tenant()); err != nil {
		return consumed{}, err
	}
	if rec, err = s.ceremonies.Consume(ctx, r.Tenant(), k, handle.Hash()); err != nil {
		return consumed{}, ceremonyProblem(err)
	}
	p, sub, err := openReset(rec, r.Tenant())
	if err != nil {
		return consumed{}, err
	}
	return s.liveBinding(ctx, p, sub, rec)
}

func (s *Service) liveBinding(ctx context.Context, p core.Pending, sub core.Subject, rec ceremony.Record) (consumed, error) {
	u, err := s.identity.GetUser(ctx, sub)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return consumed{}, errors.Join(ErrInvalidToken, err)
	case err != nil:
		return consumed{}, errors.Join(httpx.ErrServiceUnavailable, err)
	}
	st := stateOf(u)
	if !st.Usable() || st.Epoch() != p.EpochAtBind() {
		return consumed{}, ErrInvalidToken
	}
	return consumed{pending: p, subject: sub, record: rec, user: u, state: st}, nil
}

func (s *Service) applyIdentifier(ctx context.Context, m identity.Mutation) error {
	if _, err := s.Apply(ctx, m); err != nil {
		return identifierProblem(err)
	}
	return nil
}

func identifierProblem(err error) error {
	if errors.Is(err, identity.ErrIdentifierTaken) {
		return errors.Join(ErrAccountExists, err)
	}
	return mutationProblem(err)
}
