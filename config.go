package egauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/configcheck"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/deployment"
	fedstore "github.com/JLugagne/egauth/store/federation"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/keys"
	"github.com/JLugagne/egauth/store/limiter"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/passkey"
	"github.com/JLugagne/egauth/store/sessions"
	"github.com/JLugagne/egauth/store/tokens"
)

// Config is the whole wiring of an Auth; New is its only consumer. C is the type of the
// application's custom claims. The egauth tags are the validation contract: required fields must
// be set, default= fields take a library default when zero, and module= fields are required
// exactly when one of the named modules (or session backends) is enabled.
type Config[C any] struct {
	PublicOrigin string           `egauth:"required,origin"`
	BasePath     string           `egauth:"default=basepath,path"`
	ExtraOrigins []string         `egauth:"optional,each=origin"`
	Audiences    []string         `egauth:"optional,each=origin"`
	Proxy        ProxyPolicy      `egauth:"required"`
	Tenancy      Tenancy          `egauth:"default=single_tenant"`
	Storage      Storage          `egauth:"required"`
	KEK          kek.KEK          `egauth:"required"`
	Sessions     SessionBackend   `egauth:"required"`
	Transport    Transport        `egauth:"default=cookies"`
	Policy       SessionPolicy    `egauth:"optional"`
	Admin        AdminPolicy      `egauth:"required"`
	Claims       ClaimsSource[C]  `egauth:"default=empty_claims"`
	Events       event.Sink       `egauth:"default=slog_default"`
	Email        EmailDeliverer   `egauth:"module=Password|MagicLink|LoginCode.Email|Verification.Email|Verification.RecoveryEmail"`
	SMS          SMSDeliverer     `egauth:"module=LoginCode.SMS|Verification.Phone"`
	Pages        Pages            `egauth:"optional"`
	Modules      Modules          `egauth:"required,oneof_primary"`
	RateLimit    limiter.Limiter  `egauth:"default=storage_limiter"`
	Outbound     OutboundObserver `egauth:"optional"`
	Hooks        Hooks            `egauth:"optional"`
	Insecure     InsecureOptOuts  `egauth:"optional"`
}

// Storage is every store an Auth reads and writes. pgxstore.New and memstore.New fill every field.
// MFA and Passkeys are always required: the enrollment decision reads them on every primary login,
// whatever the modules. Every security store must report the same Durability.
type Storage struct {
	Identity   identity.Store   `egauth:"required"`
	Ceremonies ceremony.Store   `egauth:"required"`
	Deployment deployment.Store `egauth:"required"`
	Limiter    limiter.Limiter  `egauth:"required"`
	Tokens     tokens.Store     `egauth:"module=Sessions.JWT|APIKeys"`
	Sessions   sessions.Store   `egauth:"module=Sessions.Stateful"`
	MFA        mfa.Store        `egauth:"required"`
	Passkeys   passkey.Store    `egauth:"required"`
	Federation fedstore.Store   `egauth:"module=OAuth|External"`
	Keys       keys.Store       `egauth:"module=Sessions.JWT.TenantKeys"`
}

// SessionPolicy bounds session lifetimes. Defaults: idle 168h, max 720h, recheck 5m, reauth 10m.
// MaxLifetime is at most 2160h (90 days), or 9600h (400 days, the browser cookie cap) with
// Insecure.LongSessions; IdleTimeout is at most MaxLifetime; RecheckEvery is in (0, 15m] and
// ReauthWindow in (0, 1h]. A negative value or a value over its bound fails New.
type SessionPolicy struct {
	IdleTimeout  time.Duration    `egauth:"default=idle_timeout,bound=le:MaxLifetime"`
	MaxLifetime  time.Duration    `egauth:"default=max_lifetime,bound=max:2160h"`
	RecheckEvery time.Duration    `egauth:"default=recheck_every,bound=max:15m"`
	ReauthWindow time.Duration    `egauth:"default=reauth_window,bound=max:1h"`
	Remember     RememberMePolicy `egauth:"default=remember_user_choice"`
}

// RememberMePolicy is applied once per login journey and sealed into the session.
type RememberMePolicy = core.RememberMePolicy

// Remember-me policies.
const (
	RememberUserChoice = core.RememberUserChoice
	RememberAlways     = core.RememberAlways
	RememberNever      = core.RememberNever
)

// ClaimsSource is the single source of application claims, read at admission and on every renewal
// (every SessionPolicy.RecheckEvery). It must be safe for concurrent use. Returning
// ErrUnknownSubject ends the subject's sessions at the next renewal instead of keeping stale claims.
type ClaimsSource[C any] interface {
	ClaimsFor(ctx context.Context, s principal.Subject) (AppClaims[C], error)
}

// ErrUnknownSubject returned by a ClaimsSource ends the subject's session at the next renewal
// instead of keeping stale claims.
var ErrUnknownSubject = errors.New("egauth: claims source does not know the subject")

// AppClaims is the only claims surface an application controls. Its JSON encoding is capped at
// MaxAppClaimsBytes so that an access-token cookie always fits the 4096-byte browser limit.
type AppClaims[C any] struct {
	Roles, Groups, Scopes []string
	Custom                C
}

// MaxAppClaimsBytes caps the JSON encoding of AppClaims, in bytes.
const MaxAppClaimsBytes = 2048

type emptyClaims[C any] struct{}

func (*emptyClaims[C]) ClaimsFor(context.Context, principal.Subject) (AppClaims[C], error) {
	return AppClaims[C]{}, nil
}

// Pages are the application pages the library links or redirects to: relative paths on the public
// origin, or absolute URLs on PublicOrigin or an ExtraOrigins entry. An enabled module that links to
// a page makes that entry required; Login is the 303 target of a completed password reset.
type Pages struct {
	Login               string `egauth:"module=Password"`
	AfterLogin          string `egauth:"module=OAuth"`
	MFA                 string `egauth:"module=OAuth"`
	Reauth              string `egauth:"optional"`
	Error               string `egauth:"module=OAuth"`
	ConfirmRegistration string `egauth:"module=Password"`
	MagicLink           string `egauth:"module=MagicLink"`
	PasswordReset       string `egauth:"module=Password"`
	VerifyEmail         string `egauth:"module=Verification.Email"`
	ConfirmEmailChange  string `egauth:"module=Verification.Email"`
	SecurityRevert      string `egauth:"module=Password|MagicLink|LoginCode.Email|LoginCode.SMS|Verification.Email|Verification.Phone|Verification.RecoveryEmail"`
}

// Hooks lets the application add checks and react to lifecycle events. BeforeEndpoint runs last in
// the preamble of every auth endpoint; a non-nil error refuses the request. AccountDeleted and
// TenantErased run from the lifecycle outbox and are retried until they return nil; the DeliveryID
// is stable across retries. Every hook must be safe for concurrent use.
type Hooks struct {
	BeforeEndpoint func(ctx context.Context, req EndpointRequest) error
	AccountDeleted func(ctx context.Context, deliveryID uuid.UUID, s principal.Subject) error
	TenantErased   func(ctx context.Context, deliveryID uuid.UUID, t principal.TenantID) error
}

// EndpointID names an auth endpoint by its Path* constant, relative to BasePath.
type EndpointID string

// EndpointRequest exposes no request body. fmt, slog and encoding/json render CaptchaToken as
// REDACTED.
type EndpointRequest struct {
	Endpoint     EndpointID
	Client       netip.Addr
	Tenant       principal.TenantID
	CaptchaToken string
}

// String renders r with CaptchaToken redacted.
func (r EndpointRequest) String() string {
	return fmt.Sprintf("EndpointRequest{Endpoint:%s Client:%s Tenant:%s CaptchaToken:%s}",
		r.Endpoint, r.Client, r.Tenant, redactedSecret)
}

// GoString renders r for %#v with CaptchaToken redacted.
func (r EndpointRequest) GoString() string { return r.String() }

// Format renders r like String for every fmt verb, so no verb reaches CaptchaToken.
func (r EndpointRequest) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, r.String()) }

// MarshalJSON encodes r with CaptchaToken redacted.
func (r EndpointRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Endpoint     EndpointID `json:"endpoint"`
		Client       string     `json:"client"`
		Tenant       string     `json:"tenant"`
		CaptchaToken string     `json:"captcha_token"`
	}{r.Endpoint, r.Client.String(), r.Tenant.String(), redactedSecret})
}

// LogValue renders r for slog with CaptchaToken redacted.
func (r EndpointRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("endpoint", string(r.Endpoint)),
		slog.String("client", r.Client.String()),
		slog.String("tenant", r.Tenant.String()),
		slog.String("captcha_token", redactedSecret),
	)
}

const longSessionsMax = 9600 * time.Hour

var primaryModules = []string{"Password", "MagicLink", "LoginCode.Email", "LoginCode.SMS", "Passkey", "OAuth", "External"}

func configOptions[C any](cfg *Config[C]) configcheck.Options {
	b, k := backendOf(cfg.Sessions)
	o := configcheck.Options{
		Defaults: defaults[C](),
		Modules:  "Modules",
		Primary:  slices.Clone(primaryModules),
		Switches: map[string]bool{
			"Sessions.JWT":            b.kind == backendJWT,
			"Sessions.Stateful":       b.kind == backendStateful,
			"Sessions.JWT.TenantKeys": b.kind == backendJWT && k.kind == keysTenant,
		},
		Provider: providerPredicate,
		External: func(any) error { return nil },
	}
	if cfg.Insecure.LongSessions != nil {
		o.Raised = map[string]time.Duration{"Policy.MaxLifetime": longSessionsMax}
	}
	return o
}

func defaults[C any]() configcheck.Defaults {
	return configcheck.Defaults{
		"basepath":             func(*configcheck.Resolved) any { return "/auth" },
		"single_tenant":        func(*configcheck.Resolved) any { return SingleTenant() },
		"cookies":              func(*configcheck.Resolved) any { return Cookies },
		"empty_claims":         func(*configcheck.Resolved) any { return ClaimsSource[C](&emptyClaims[C]{}) },
		"slog_default":         func(*configcheck.Resolved) any { return event.NewSlogSink(nil) },
		"storage_limiter":      storageLimiter,
		"idle_timeout":         func(*configcheck.Resolved) any { return 168 * time.Hour },
		"max_lifetime":         func(*configcheck.Resolved) any { return 720 * time.Hour },
		"recheck_every":        func(*configcheck.Resolved) any { return 5 * time.Minute },
		"reauth_window":        func(*configcheck.Resolved) any { return 10 * time.Minute },
		"remember_user_choice": func(*configcheck.Resolved) any { return RememberUserChoice },
		"password_policy":      func(*configcheck.Resolved) any { return passwords.Policy(policy.NewPassphrasePolicy()) },
		"registration_open":    func(*configcheck.Resolved) any { return RegistrationOpen },
		"attestation_none":     func(*configcheck.Resolved) any { return AttestationNone },
		"totp_issuer":          totpIssuer,
		"api_key_prefix":       func(*configcheck.Resolved) any { return "egk" },
	}
}

func storageLimiter(r *configcheck.Resolved) any {
	l, ok := r.Get("Storage.Limiter")
	if !ok || !present(l) {
		return nil
	}
	return l
}

func totpIssuer(r *configcheck.Resolved) any {
	o, _ := r.Get("PublicOrigin")
	s, _ := o.(string)
	u, err := url.Parse(strings.Replace(s, tenantLabel+".", "", 1))
	if err != nil || u.Hostname() == "" {
		return "egauth"
	}
	return u.Hostname()
}

func snapshot[C any](cfg Config[C]) Config[C] {
	cfg.ExtraOrigins = slices.Clone(cfg.ExtraOrigins)
	cfg.Audiences = slices.Clone(cfg.Audiences)
	m := &cfg.Modules
	m.Password = clonePtr(m.Password)
	m.MagicLink = clonePtr(m.MagicLink)
	m.LoginCode = clonePtr(m.LoginCode)
	m.Passkey = clonePtr(m.Passkey)
	m.MFA = clonePtr(m.MFA)
	m.Verification = clonePtr(m.Verification)
	m.SelfDelete = clonePtr(m.SelfDelete)
	if m.OAuth = clonePtr(m.OAuth); m.OAuth != nil {
		m.OAuth.Providers = slices.Clone(m.OAuth.Providers)
		for i := range m.OAuth.Providers {
			p := &m.OAuth.Providers[i]
			p.Scopes, p.Domains = slices.Clone(p.Scopes), slices.Clone(p.Domains)
		}
	}
	if m.External = clonePtr(m.External); m.External != nil {
		m.External.Verifiers = slices.Clone(m.External.Verifiers)
	}
	if m.APIKeys = clonePtr(m.APIKeys); m.APIKeys != nil {
		m.APIKeys.Kinds = slices.Clone(m.APIKeys.Kinds)
	}
	in := &cfg.Insecure
	in.SharedCookieDomain = clonePtr(in.SharedCookieDomain)
	for _, a := range []**OutboundAllowance{&in.OutboundPrivateNetwork, &in.TenantOutboundPrivateNetwork} {
		if *a = clonePtr(*a); *a != nil {
			(*a).Prefixes = slices.Clone((*a).Prefixes)
		}
	}
	return cfg
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	c := *p
	return &c
}

// String renders the origins and the enabled modules only; stores, keys and deliverers are never
// formatted.
func (c Config[C]) String() string {
	return "egauth.Config{PublicOrigin:" + c.PublicOrigin + " BasePath:" + c.BasePath + " Modules:" + c.Modules.String() + "}"
}

// GoString renders c like String.
func (c Config[C]) GoString() string { return c.String() }

// Format renders c like String for every fmt verb, so no verb reaches the wiring.
func (c Config[C]) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// MarshalJSON encodes the origins and the enabled modules only, like String.
func (c Config[C]) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		PublicOrigin string   `json:"public_origin"`
		BasePath     string   `json:"base_path"`
		Modules      []string `json:"modules"`
	}{c.PublicOrigin, c.BasePath, c.Modules.enabled()})
}

// LogValue renders c for slog like String.
func (c Config[C]) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("public_origin", c.PublicOrigin),
		slog.String("base_path", c.BasePath),
		slog.Any("modules", c.Modules),
	)
}
