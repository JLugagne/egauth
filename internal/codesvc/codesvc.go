// Package codesvc owns the passwordless primary factors: the emailed magic link (email_link) and
// the one-time login codes sent by email (email_code) or SMS (sms_code). Every ceremony begun here
// binds the requesting browser, seals remember-me and return_to in its Pending at request time
// (I-14), binds the Pending to the subject and its security epoch, and ends in the single admission
// path, httpx.Issuer.Complete, so the MFA decision always applies (I-04, D-08). A code is never a
// lookup key: records are keyed by a 256-bit handle and the code is compared in constant time
// against its keyed digest (C-30).
package codesvc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

const redacted = "REDACTED"

var (
	// ErrInvalidConfig is returned by New, joined with one error per missing or invalid member.
	ErrInvalidConfig = errors.New("codesvc: invalid service configuration")
	// ErrNilIssuer is returned by Endpoints for a nil issuer.
	ErrNilIssuer = errors.New("codesvc: nil issuer")
)

// The problems the code and magic-link endpoints answer besides those of httpx.
var (
	ErrInvalidIdentifier = httpx.NewProblem(http.StatusBadRequest, "invalid_identifier")
	ErrInvalidToken      = httpx.NewProblem(http.StatusBadRequest, "invalid_token")
	ErrInvalidCode       = httpx.NewProblem(http.StatusUnauthorized, "invalid_code")
)

// CodeMessage is a login code to deliver. Code is a bearer secret until ExpiresAt: fmt and slog
// render it REDACTED.
type CodeMessage struct {
	DeliveryID uuid.UUID
	Tenant     core.TenantID
	To         string
	Code       string
	ExpiresAt  time.Time
}

func (m CodeMessage) String() string {
	return "codesvc.CodeMessage{DeliveryID: " + m.DeliveryID.String() + ", Code: " + redacted + "}"
}

func (m CodeMessage) GoString() string { return m.String() }

func (m CodeMessage) LogValue() slog.Value {
	return slog.GroupValue(slog.String("delivery_id", m.DeliveryID.String()), slog.String("code", redacted))
}

// Mailer delivers the emails of this package; the composition adapts egauth.EmailDeliverer to it.
// Calls run on the service's bounded background workers, never on the request path. A method must
// be idempotent on DeliveryID.
type Mailer interface {
	MagicLink(ctx context.Context, m identitysvc.LinkMessage) error
	LoginCode(ctx context.Context, m CodeMessage) error
}

// Texter delivers SMS login codes; the composition adapts egauth.SMSDeliverer to it. Same rules as
// Mailer.
type Texter interface {
	LoginCode(ctx context.Context, m CodeMessage) error
}

// Accounts answers the authoritative account state; identitysvc.Service satisfies it.
type Accounts interface {
	AccountState(ctx context.Context, sub core.Subject) (core.AccountState, error)
}

// Config is what New needs. Mailer is required when MagicLink or EmailCodes is set, Links when
// MagicLink is, and Texter when SMSCodes is; at least one of the three must be set. The zero Clock
// reads the wall clock.
type Config struct {
	Identity   identity.Store
	Accounts   Accounts
	Ceremonies ceremony.Store
	Mailer     Mailer
	Texter     Texter
	Links      identitysvc.Links
	Cookies    cookie.Policy
	// DataKey is the 32-byte deployment data key; only HKDF subkeys of it are kept.
	DataKey []byte
	// MagicLink mounts /magic-link/request and /magic-link (Modules.MagicLink).
	MagicLink bool
	// EmailCodes and SMSCodes enable the login code channels (Modules.LoginCode); either mounts
	// /code/request and /code/verify.
	EmailCodes bool
	SMSCodes   bool
	Clock      clock.Clock
	Audit      httpx.Audit
}

func (c Config) String() string {
	return "codesvc.Config{MagicLink: " + strconv.FormatBool(c.MagicLink) + ", EmailCodes: " + strconv.FormatBool(c.EmailCodes) +
		", SMSCodes: " + strconv.FormatBool(c.SMSCodes) + ", DataKey: " + redacted + "}"
}

func (c Config) GoString() string { return c.String() }

func (c Config) LogValue() slog.Value {
	return slog.GroupValue(slog.Bool("magic_link", c.MagicLink), slog.Bool("email_codes", c.EmailCodes),
		slog.Bool("sms_codes", c.SMSCodes), slog.String("data_key", redacted))
}

// Service is the passwordless login service. It is safe for concurrent use; Close stops its
// delivery workers.
type Service struct {
	identity   identity.Store
	accounts   Accounts
	ceremonies ceremony.Store
	mailer     Mailer
	texter     Texter
	links      identitysvc.Links
	cookies    cookie.Policy
	scopes     identitysvc.ScopeKey
	sealer     *ceremonycodec.Sealer
	magicLink  bool
	emailCodes bool
	smsCodes   bool
	clock      clock.Clock
	audit      httpx.Audit
	work       *workers
	decoy      decoy
}

type decoy struct {
	handle ceremonycodec.Handle
	code   ceremonycodec.Code
}

func newDecoy(sealer *ceremonycodec.Sealer) (decoy, error) {
	handle, err := ceremonycodec.NewHandle()
	if err != nil {
		return decoy{}, err
	}
	code, err := newCode()
	if err != nil {
		return decoy{}, err
	}
	digest, err := ceremonycodec.NewCode(sealer, code)
	if err != nil {
		return decoy{}, err
	}
	return decoy{handle: handle, code: digest}, nil
}

// New validates cfg, reporting every problem at once as ErrInvalidConfig joined with the member
// names (a typed nil counts as missing), and starts the delivery workers that Close stops.
func New(cfg Config) (*Service, error) {
	var errs []error
	need := func(ok bool, name string) {
		if !ok {
			errs = append(errs, errors.New(name))
		}
	}
	need(cfg.MagicLink || cfg.EmailCodes || cfg.SMSCodes, "MagicLink, EmailCodes or SMSCodes")
	need(present(cfg.Identity), "Identity")
	need(present(cfg.Accounts), "Accounts")
	need(present(cfg.Ceremonies), "Ceremonies")
	need(!(cfg.MagicLink || cfg.EmailCodes) || present(cfg.Mailer), "Mailer")
	need(!cfg.MagicLink || present(cfg.Links), "Links")
	need(!cfg.SMSCodes || present(cfg.Texter), "Texter")
	need(cfg.Cookies != (cookie.Policy{}), "Cookies")
	need(present(cfg.Audit), "Audit")
	scopes, err := identitysvc.NewScopeKey(cfg.DataKey)
	if err != nil {
		errs = append(errs, errors.Join(errors.New("DataKey"), err))
	}
	sealer, err := ceremonycodec.NewSealer(cfg.DataKey, cfg.Clock)
	if err != nil {
		errs = append(errs, errors.Join(errors.New("DataKey"), err))
	}
	if len(errs) > 0 {
		return nil, errors.Join(ErrInvalidConfig, errors.Join(errs...))
	}
	d, err := newDecoy(sealer)
	if err != nil {
		return nil, errors.Join(errors.New("codesvc: decoy"), err)
	}
	return &Service{
		identity:   cfg.Identity,
		accounts:   cfg.Accounts,
		ceremonies: cfg.Ceremonies,
		mailer:     cfg.Mailer,
		texter:     cfg.Texter,
		links:      cfg.Links,
		cookies:    cfg.Cookies,
		scopes:     scopes,
		sealer:     sealer,
		magicLink:  cfg.MagicLink,
		emailCodes: cfg.EmailCodes,
		smsCodes:   cfg.SMSCodes,
		clock:      cfg.Clock,
		audit:      cfg.Audit,
		work:       newWorkers(cfg.Audit),
		decoy:      d,
	}, nil
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

// Close stops the delivery workers after the queued jobs ran. It is idempotent.
func (s *Service) Close() error {
	s.work.close()
	return nil
}

// Endpoints returns the endpoints of the enabled modules, served by s through issuer. It returns
// ErrNilIssuer or the error of routes.NewEndpoint.
//
// Their guarantees:
//   - /magic-link/request and /code/request do the same work and answer the same body for every
//     well-formed identifier (C-46): 202 for a link, 200 with a fresh 256-bit handle for a code. The
//     account is looked up, the ceremony stored and the message sent on the delivery workers, and
//     only for a usable account with a verified email (and, for SMS, a verified phone): an unknown
//     identifier keeps a stateless decoy handle that matches no record. Both bind the browser: the
//     bind cookie, or the bind field under Bearer.
//   - /magic-link without the bind secret answers confirm_required with an account hint and
//     consumes nothing; an explicit confirm completes it.
//   - /code/verify finds the record by its handle only, refuses an unbound request before charging
//     anything with the answer of a wrong code, so a decoy handle cannot be told apart (C-46), then
//     charges one attempt before comparing the code in constant time, so concurrent guesses never
//     exceed Kind.MaxAttempts; the charge that reaches the bound deletes the record.
//   - Both consumers replay the Pending sealed at request time (remember, return_to, transport) and
//     end in Issuer.Complete with email_link, email_code or sms_code; a security change since the
//     request (epoch bump) kills the ceremony there.
func (s *Service) Endpoints(issuer httpx.Issuer) ([]routes.Endpoint, error) {
	if issuer == nil {
		return nil, ErrNilIssuer
	}
	h := &handlers{Service: s, issuer: issuer}
	type route struct {
		path string
		f    httpx.EndpointFunc
	}
	var fns []route
	if s.magicLink {
		fns = append(fns, route{routes.MagicLinkRequest, h.requestLink}, route{routes.MagicLink, h.consumeLink})
	}
	if s.emailCodes || s.smsCodes {
		fns = append(fns, route{routes.CodeRequest, h.requestCode}, route{routes.CodeVerify, h.verifyCode})
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

type handlers struct {
	*Service
	issuer httpx.Issuer
}
