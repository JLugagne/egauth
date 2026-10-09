// Package federationsvc owns federated sign-in through OAuth 2.0 and OpenID Connect providers
// (DESIGN §6.9). Every journey begins with a stateless sealed state handle that carries the
// Pending (remember-me, return_to, transport), the PKCE verifier, the OIDC nonce and the redirect
// URI, and binds the browser that began it (O-02, C-38). There is one callback path (O-06): it
// checks the bind, the RFC 9207 issuer against the pinned spec Issuer, then either logs into the
// account already linked to the provider identity or creates a new account, and ends in the single
// admission path, httpx.Issuer.Complete, with the fed factor (O-01). It never attaches a provider
// identity to an existing account (D6): that is the authenticated, sensitive /oauth/{provider}/link.
package federationsvc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/outbound"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/store/ceremony"
	storefed "github.com/JLugagne/egauth/store/federation"
)

var (
	// ErrInvalidConfig is returned by New, joined with one error per missing or invalid member.
	ErrInvalidConfig = errors.New("federationsvc: invalid service configuration")
	// ErrNilIssuer is returned by Endpoints for a nil issuer.
	ErrNilIssuer = errors.New("federationsvc: nil issuer")
)

// The problems the federation endpoints answer besides those of httpx.
var (
	ErrUnknownProvider = httpx.NewProblem(http.StatusNotFound, "unknown_provider")
	ErrInvalidState    = httpx.NewProblem(http.StatusBadRequest, "invalid_state")
	// ErrUnboundCeremony answers a callback or exchange that does not present the browser-binding
	// secret of the begin it completes.
	ErrUnboundCeremony = httpx.NewProblem(http.StatusBadRequest, "unbound_ceremony")
	// ErrIssuerMismatch answers an authorization response whose RFC 9207 iss is not the spec Issuer.
	ErrIssuerMismatch = httpx.NewProblem(http.StatusBadRequest, "issuer_mismatch")
	// ErrAccessDenied answers an authorization response carrying a provider error.
	ErrAccessDenied = httpx.NewProblem(http.StatusBadRequest, "access_denied")
	// ErrInvalidIdentity answers an id_token or userinfo answer that fails verification.
	ErrInvalidIdentity = httpx.NewProblem(http.StatusUnauthorized, "invalid_identity")
	// ErrProviderUnavailable answers a provider that could not be reached or answered malformed data.
	ErrProviderUnavailable = httpx.NewProblem(http.StatusBadGateway, "provider_unavailable")
	// ErrAccountExists answers a sign-in whose provider email belongs to an account not linked to
	// that provider identity: the owner signs in and links it explicitly (D6, §6.11).
	ErrAccountExists = httpx.NewProblem(http.StatusConflict, "account_exists")
	// ErrIdentityLinked answers a link of a provider identity already linked to another account.
	ErrIdentityLinked = httpx.NewProblem(http.StatusConflict, "identity_already_linked")
	// ErrEmailUnverified answers a sign-up without a provider email trusted as verified, and a link
	// to an account whose own email is not verified (§6.9.5).
	ErrEmailUnverified    = httpx.NewProblem(http.StatusForbidden, "email_unverified")
	ErrRegistrationClosed = httpx.NewProblem(http.StatusForbidden, "registration_closed")
	ErrInvalidToken       = httpx.NewProblem(http.StatusBadRequest, "invalid_token")
	// ErrUnsupportedTransport answers /oauth/{provider}/link from a Bearer session: the browser leg
	// of a link cannot be bound to a native client, so linking is a cookie-session action.
	ErrUnsupportedTransport = httpx.NewProblem(http.StatusBadRequest, "unsupported_transport")
)

// PublicOrigins resolves the tenant-expanded PublicOrigin (scheme and host, no path) the redirect
// URI of tenant t is derived from (O-08).
type PublicOrigins interface {
	PublicOrigin(t core.TenantID) (string, error)
}

// Config is what New needs. Providers are the static specs; with PerTenant, a provider not among
// them is read from Federation, its client secret opened with KEK and fetched through the tenant
// scope of Outbound. The zero Clock reads the wall clock.
type Config struct {
	Providers  []federation.Provider
	PerTenant  bool
	Federation storefed.Store
	Users      Users
	Accounts   Accounts
	Ceremonies ceremony.Store
	KEK        kek.KEK
	Outbound   *outbound.Clients
	Origins    PublicOrigins
	// BasePath is Config.BasePath of the deployment; the redirect URI is PublicOrigin, BasePath and
	// the callback path, never configured separately (O-08).
	BasePath string
	Cookies  cookie.Policy
	// DataKey is the 32-byte deployment data key; only HKDF subkeys of it are kept.
	DataKey      []byte
	Registration Registration
	Clock        clock.Clock
	Audit        httpx.Audit
}

func (c Config) String() string {
	names := make([]string, 0, len(c.Providers))
	for _, p := range c.Providers {
		names = append(names, p.Name)
	}
	return "federationsvc.Config{Providers: [" + strings.Join(names, " ") + "], PerTenant: " +
		strconv.FormatBool(c.PerTenant) + ", DataKey: " + redacted + "}"
}

func (c Config) GoString() string { return c.String() }

func (c Config) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("providers", len(c.Providers)), slog.Bool("per_tenant", c.PerTenant),
		slog.String("data_key", redacted))
}

const redacted = "REDACTED"

type doer interface {
	Do(req *http.Request) (*http.Response, error)
}

type httpClients struct {
	static doer
	tenant doer
}

// Service is the federated sign-in service. It is safe for concurrent use.
type Service struct {
	static     map[string]federation.Provider
	perTenant  bool
	federation storefed.Store
	accounts   Accounts
	directory  *Directory
	ceremonies ceremony.Store
	kek        kek.KEK
	http       httpClients
	origins    PublicOrigins
	basePath   string
	cookies    cookie.Policy
	sealer     *ceremonycodec.Sealer
	clock      clock.Clock
	audit      httpx.Audit
	jwks       *jwksCache
}

// New validates cfg, reporting every problem at once as ErrInvalidConfig joined with the member
// names (a typed nil counts as missing), then discovers, through the static outbound scope, every
// static provider that pins an issuer without its endpoints, pinning that issuer. ctx bounds only
// that discovery. A provider that is incomplete after discovery, or two providers sharing a name,
// are configuration errors.
func New(ctx context.Context, cfg Config) (*Service, error) {
	var clients httpClients
	if cfg.Outbound != nil {
		clients = httpClients{static: cfg.Outbound.Static(), tenant: cfg.Outbound.Tenant()}
	}
	return newService(ctx, cfg, clients)
}

func newService(ctx context.Context, cfg Config, clients httpClients) (*Service, error) {
	var errs []error
	need := func(ok bool, name string) {
		if !ok {
			errs = append(errs, errors.New(name))
		}
	}
	need(len(cfg.Providers) > 0 || cfg.PerTenant, "Providers or PerTenant")
	need(present(cfg.Federation), "Federation")
	need(present(cfg.Users), "Users")
	need(present(cfg.Accounts), "Accounts")
	need(present(cfg.Ceremonies), "Ceremonies")
	need(!cfg.PerTenant || present(cfg.KEK), "KEK")
	need(present(clients.static) && present(clients.tenant), "Outbound")
	need(present(cfg.Origins), "Origins")
	need(cfg.Cookies != (cookie.Policy{}), "Cookies")
	need(cfg.Registration.valid(), "Registration")
	need(present(cfg.Audit), "Audit")
	if err := routes.ValidateBasePath(cfg.BasePath); err != nil {
		errs = append(errs, errors.Join(errors.New("BasePath"), err))
	}
	sealer, err := ceremonycodec.NewSealer(cfg.DataKey, cfg.Clock)
	if err != nil {
		errs = append(errs, errors.Join(errors.New("DataKey"), err))
	}
	if len(errs) > 0 {
		return nil, errors.Join(ErrInvalidConfig, errors.Join(errs...))
	}
	static, err := staticProviders(ctx, clients.static, cfg.Providers)
	if err != nil {
		return nil, errors.Join(ErrInvalidConfig, err)
	}
	dir, err := NewDirectory(DirectoryConfig{
		Users: cfg.Users, Links: cfg.Federation, Accounts: cfg.Accounts, Registration: cfg.Registration, Audit: cfg.Audit,
	})
	if err != nil {
		return nil, errors.Join(ErrInvalidConfig, err)
	}
	return &Service{
		static:     static,
		perTenant:  cfg.PerTenant,
		federation: cfg.Federation,
		accounts:   cfg.Accounts,
		directory:  dir,
		ceremonies: cfg.Ceremonies,
		kek:        cfg.KEK,
		http:       clients,
		origins:    cfg.Origins,
		basePath:   cfg.BasePath,
		cookies:    cfg.Cookies,
		sealer:     sealer,
		clock:      cfg.Clock,
		audit:      cfg.Audit,
		jwks:       newJWKSCache(cfg.Clock),
	}, nil
}

func staticProviders(ctx context.Context, d doer, specs []federation.Provider) (map[string]federation.Provider, error) {
	out := make(map[string]federation.Provider, len(specs))
	var errs []error
	for i, p := range specs {
		if p.NeedsDiscovery() {
			found, err := discover(ctx, d, p)
			if err != nil {
				errs = append(errs, errors.Join(errors.New("Providers["+strconv.Itoa(i)+"]"), err))
				continue
			}
			p = found
		}
		if err := p.Complete(); err != nil {
			errs = append(errs, errors.Join(errors.New("Providers["+strconv.Itoa(i)+"]"), err))
			continue
		}
		if _, dup := out[p.Name]; dup {
			errs = append(errs, errors.New("Providers["+strconv.Itoa(i)+"]: duplicate name "+p.Name))
			continue
		}
		out[p.Name] = p
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
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

// Endpoints returns /oauth/{provider}/begin, the single /oauth/{provider}/callback (O-06),
// /oauth/{provider}/link and /exchange, served by s through issuer. It returns ErrNilIssuer or the
// error of routes.NewEndpoint.
//
// Their guarantees:
//   - begin writes no row: it seals the Pending of issuer.Begin, the PKCE verifier, the nonce and
//     the redirect URI into a stateless handle sent as state, and binds the browser (the bind
//     cookie, or the bind field under Bearer).
//   - callback refuses a handle of another kind, tenant (401, unconsumed) or provider, an expired
//     one (O-07) and, under cookie transport, one presented without its bind cookie (400
//     unbound_ceremony, unconsumed); it consumes the handle once, checks the RFC 9207 iss against
//     the spec Issuer, redeems the code with the sealed verifier and redirect URI, verifies the
//     id_token (pinned issuer, audience, nonce, signature) and resolves the account through
//     Directory.SignIn, which never links an existing account (D6). It ends in issuer.Complete
//     with the fed factor; under Bearer it parks the bound Pending in a 60-second Exchange record
//     instead and hands out its handle, followed by "." and the provider name, which is hashed
//     into the record key so that a relabelled provider finds no record.
//   - link is Sensitive and refused from a Bearer session: it seals the session subject and epoch
//     into the state, and its callback attaches the provider identity to that subject only, ending
//     every session of the subject.
//   - /exchange redeems an Exchange record with its bind secret, charging a failed attempt to the
//     record, and ends in issuer.Complete.
func (s *Service) Endpoints(issuer httpx.Issuer) ([]routes.Endpoint, error) {
	if issuer == nil {
		return nil, ErrNilIssuer
	}
	h := &handlers{Service: s, issuer: issuer}
	fns := []struct {
		path string
		f    httpx.EndpointFunc
	}{
		{routes.OAuthBegin, h.begin},
		{routes.OAuthCallback, h.callback},
		{routes.OAuthLink, h.link},
		{routes.Exchange, h.exchange},
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

func unavailable(err error) error {
	return errors.Join(httpx.ErrServiceUnavailable, err)
}
