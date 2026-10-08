// Package identitysvc owns accounts: the identifier normaliser, the authoritative account state, the
// shared mutation path and the password endpoints (login, verified-email registration, reset). Its
// endpoint bodies are httpx.EndpointFuncs mounted behind the preamble; they reach session issuance
// only through the httpx.Issuer seam.
package identitysvc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"reflect"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/outbound"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/breach"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/passkey"
)

const (
	redacted       = "REDACTED"
	decoyBytes     = 32
	startupTimeout = 30 * time.Second
)

var (
	// ErrInvalidConfig is returned by New, joined with one error per missing or invalid member.
	ErrInvalidConfig = errors.New("identitysvc: invalid service configuration")
	// ErrNilIssuer is returned by Endpoints for a nil issuer.
	ErrNilIssuer = errors.New("identitysvc: nil issuer")
)

// The password lockout charged by /login: LockoutThreshold failures within LockoutWindow lock the
// credential for LockoutWindow. They are constants so that no caller can weaken them.
const (
	LockoutThreshold = 5
	LockoutWindow    = 15 * time.Minute
)

// LinkMessage is a one-time link to deliver. Link is a bearer credential until ExpiresAt: fmt and
// slog render it REDACTED.
type LinkMessage struct {
	DeliveryID uuid.UUID
	Tenant     core.TenantID
	To         string
	Link       string
	ExpiresAt  time.Time
}

func (m LinkMessage) String() string {
	return "identitysvc.LinkMessage{DeliveryID: " + m.DeliveryID.String() + ", Link: " + redacted + "}"
}

func (m LinkMessage) GoString() string { return m.String() }

func (m LinkMessage) LogValue() slog.Value {
	return slog.GroupValue(slog.String("delivery_id", m.DeliveryID.String()), slog.String("link", redacted))
}

// NoticeMessage tells the owner of an address that something happened, without a secret.
type NoticeMessage struct {
	DeliveryID uuid.UUID
	Tenant     core.TenantID
	To         string
}

// Mailer delivers the emails of this package; the composition adapts egauth.EmailDeliverer to it.
// Calls run on the service's bounded background dispatcher, never on the request path, so the
// response time does not depend on whether a message was sent. A method must be idempotent on
// DeliveryID.
type Mailer interface {
	RegistrationLink(ctx context.Context, m LinkMessage) error
	AccountExistsNotice(ctx context.Context, m NoticeMessage) error
	PasswordResetLink(ctx context.Context, m LinkMessage) error
}

// Links builds the absolute link of a stored ceremony handle for tenant t from the public origin,
// BasePath and Pages. An error drops the delivery and is reported as event.DeliveryFailed.
type Links interface {
	Link(ctx context.Context, t core.TenantID, k ceremony.Kind, handle string) (string, error)
}

// OutboxDispatcher runs the lifecycle effects an applied mutation queued, right after commit, as the
// fast path; rows it leaves undone are retried by the reaper, so its errors are not reported here.
type OutboxDispatcher interface {
	DispatchOutbox(ctx context.Context, items []identity.OutboxItem)
}

// Config is what New needs. Every member is required except Breach, Outbound (required only when
// Breach is a breach.Spec or a pointer to one), Dispatcher and LoginPage; the zero Clock reads the
// wall clock.
type Config struct {
	Identity   identity.Store
	Ceremonies ceremony.Store
	MFA        mfa.Store
	Passkeys   passkey.Store
	Hasher     passwords.Hasher
	// Policy runs after the library floor (passwords.Floor) and Breach; it can only tighten them.
	Policy passwords.Policy
	Breach passwords.BreachChecker
	// Outbound is the static-scope client a breach.Spec is fetched through.
	Outbound *outbound.Client
	Mailer   Mailer
	Links    Links
	Cookies  cookie.Policy
	// DataKey is the 32-byte deployment data key; only an HKDF subkey of it is kept.
	DataKey []byte
	// OpenRegistration mounts /register and /register/confirm (RegistrationOpen).
	OpenRegistration bool
	// LoginPage is where a browser form is redirected after a password reset (Pages.Login).
	LoginPage  redirect.Target
	Dispatcher OutboxDispatcher
	Clock      clock.Clock
	Audit      httpx.Audit
}

// Service is the identity service. It is safe for concurrent use; Close stops its delivery workers.
type Service struct {
	identity   identity.Store
	ceremonies ceremony.Store
	mfa        mfa.Store
	passkeys   passkey.Store
	hasher     passwords.Hasher
	policy     passwords.Policy
	breach     passwords.BreachChecker
	links      Links
	cookies    cookie.Policy
	scopes     ScopeKey
	register   bool
	loginPage  redirect.Target
	dispatcher OutboxDispatcher
	clock      clock.Clock
	audit      httpx.Audit
	decoyPHC   string
	decoyUser  uuid.UUID
	mail       *deliveries
}

// New validates cfg, reporting every problem at once as ErrInvalidConfig joined with the member
// names, so no request can later fail as a wrong password because a dependency is missing (I-25); a
// typed nil member counts as missing. It computes the decoy hash that unknown identifiers are
// compared against and starts the delivery workers that Close stops.
func New(cfg Config) (*Service, error) {
	var errs []error
	need := func(ok bool, name string) {
		if !ok {
			errs = append(errs, errors.New(name))
		}
	}
	need(present(cfg.Identity), "Identity")
	need(present(cfg.Ceremonies), "Ceremonies")
	need(present(cfg.MFA), "MFA")
	need(present(cfg.Passkeys), "Passkeys")
	need(present(cfg.Hasher), "Hasher")
	need(present(cfg.Policy), "Policy")
	need(present(cfg.Mailer), "Mailer")
	need(present(cfg.Links), "Links")
	need(present(cfg.Audit), "Audit")
	need(cfg.Dispatcher == nil || present(cfg.Dispatcher), "Dispatcher")
	need(cfg.Cookies != (cookie.Policy{}), "Cookies")
	checker, err := resolveBreach(cfg.Breach, cfg.Outbound)
	if err != nil {
		errs = append(errs, err)
	}
	scopes, err := NewScopeKey(cfg.DataKey)
	if err != nil {
		errs = append(errs, errors.Join(errors.New("DataKey"), err))
	}
	if len(errs) > 0 {
		return nil, errors.Join(ErrInvalidConfig, errors.Join(errs...))
	}
	decoy, err := decoyHash(cfg.Hasher)
	if err != nil {
		return nil, errors.Join(ErrInvalidConfig, errors.New("Hasher"), err)
	}
	s := &Service{
		identity:   cfg.Identity,
		ceremonies: cfg.Ceremonies,
		mfa:        cfg.MFA,
		passkeys:   cfg.Passkeys,
		hasher:     cfg.Hasher,
		policy:     cfg.Policy,
		breach:     checker,
		links:      cfg.Links,
		cookies:    cfg.Cookies,
		scopes:     scopes,
		register:   cfg.OpenRegistration,
		loginPage:  cfg.LoginPage,
		dispatcher: cfg.Dispatcher,
		clock:      cfg.Clock,
		audit:      cfg.Audit,
		decoyPHC:   decoy,
		decoyUser:  uuid.New(),
	}
	s.mail = newDeliveries(cfg.Mailer, cfg.Audit)
	return s, nil
}

func present(v any) bool {
	if v == nil {
		return false
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return !rv.IsNil()
	}
	return true
}

func decoyHash(h passwords.Hasher) (string, error) {
	raw := make([]byte, decoyBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	phc, err := h.Hash(ctx, base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		return "", err
	}
	if phc == "" || len(phc) > identity.MaxPHCLen {
		return "", errors.New("hasher returned an unusable hash of " + strconv.Itoa(len(phc)) + " bytes")
	}
	return phc, nil
}

func resolveBreach(c passwords.BreachChecker, client *outbound.Client) (passwords.BreachChecker, error) {
	var spec breach.Spec
	switch v := c.(type) {
	case breach.Spec:
		spec = v
	case *breach.Spec:
		if v == nil {
			return nil, errors.Join(errors.New("Breach"), breach.ErrUnresolved)
		}
		spec = *v
	case nil:
		return nil, nil
	default:
		if !present(c) {
			return nil, errors.New("Breach: a typed nil checker")
		}
		return c, nil
	}
	if client == nil {
		return nil, errors.New("Outbound: a breach.Spec is fetched through the outbound client")
	}
	if spec.IsZero() {
		return nil, errors.Join(errors.New("Breach"), breach.ErrUnresolved)
	}
	return outboundBreach{spec: spec, client: client}, nil
}

type outboundBreach struct {
	spec   breach.Spec
	client *outbound.Client
}

func (b outboundBreach) IsBreached(ctx context.Context, password string) (bool, error) {
	return b.spec.Lookup(ctx, password, b.client.DoSecretPath)
}

// Close stops the delivery workers after the queued messages are sent. It is idempotent.
func (s *Service) Close() error {
	s.mail.close()
	return nil
}

// Endpoints returns the password endpoints served by s through issuer: /login, /password/forgot and
// /password/reset, plus /register and /register/confirm when registration is open. It returns
// ErrNilIssuer or the error of routes.NewEndpoint.
//
// Their guarantees:
//   - /login answers one 401 invalid_credentials for a wrong password and an unknown, disabled,
//     deleted, unverified or password-less account, always after a full or decoy hash (C-46). An
//     unknown identifier still reads the password store, so an outage of it answers the same 503,
//     and every refusal of a well-formed identifier charges one lockout write: to the account for a
//     wrong password, to a decoy subject otherwise.
//   - /register answers the same 202 and binds the browser whether or not the email has a verified
//     account; it hashes the password, stores one PendingRegistration ceremony and sends exactly one
//     message either way (a link, or AccountExistsNotice; the ceremony of a verified account is never
//     delivered). A ceremony store or Links failure drops the message as event.DeliveryFailed and
//     still answers 202. No account exists before /register/confirm (D5).
//   - /register/confirm without the bind secret answers confirm_required without consuming the link;
//     an explicit confirm then admits the account but drops the password chosen in the other browser.
//     An existing unverified account has its pre-verification credentials wiped (C-39); a verified one
//     is refused with 409.
//   - /password/forgot answers the same 202 for every identifier and sends a link only to the
//     verified email of a usable account. The ceremony is stored and the link built on the delivery
//     workers, so the request does the same work for every identifier. The link is bound to the
//     subject's epoch as read by the request, so any later security change kills it (C-17).
//   - /password/reset checks the new password before consuming the link, never issues a session and
//     applies SetPassword{PasswordReset}, whose epoch bump ends every session; factors survive (C-54,
//     I-09).
func (s *Service) Endpoints(issuer httpx.Issuer) ([]routes.Endpoint, error) {
	if issuer == nil {
		return nil, ErrNilIssuer
	}
	h := &handlers{Service: s, issuer: issuer}
	fns := []route{
		{routes.Login, h.login},
		{routes.PasswordForgot, h.forgotPassword},
		{routes.PasswordReset, h.resetPassword},
	}
	if s.register {
		fns = append(fns, route{routes.Register, h.registerAccount}, route{routes.RegisterConfirm, h.confirmRegistration})
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

type route struct {
	path string
	f    httpx.EndpointFunc
}

type handlers struct {
	*Service
	issuer httpx.Issuer
}
