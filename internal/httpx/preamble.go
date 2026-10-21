package httpx

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/JLugagne/egauth/internal/clientaddr"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/store/limiter"
)

var bearerResponseHeaders = []string{"X-Egauth-Access-Token", "X-Egauth-Refresh-Token", "X-Egauth-Session-Token"}

const (
	maxReauthWindow = time.Hour
	maxLimiterValue = 256
)

// ErrInvalidSettings is returned by NewPreamble for settings it cannot enforce.
var ErrInvalidSettings = errors.New("httpx: invalid preamble settings")

// Transports is the set of credential transports the deployment allows (Config.Transport).
type Transports uint8

const (
	CookiesOnly Transports = iota + 1
	BearerOnly
	CookiesAndBearer
)

func (t Transports) valid() bool { return t >= CookiesOnly && t <= CookiesAndBearer }

// Insecure mirrors the InsecureOptOuts that weaken a preamble gate. The composition sets a field
// only for an acknowledged opt-out.
type Insecure struct {
	// NoOriginCheck skips internal/csrf (step 4).
	NoOriginCheck bool
	// NoRateLimit skips the limiter (step 5); Env.Limiter may then be nil.
	NoRateLimit bool
	// NoReauthWindow skips only the freshness part of the sensitive gate; MultiFactor still holds.
	NoReauthWindow bool
}

// Settings are the deployment values the preamble enforces.
type Settings struct {
	Clients      *clientaddr.Resolver
	Origins      csrf.Origins
	Transports   Transports
	ReauthWindow time.Duration
	Insecure     Insecure
}

// Preamble runs the gates of DESIGN §3.9 in order before every auth endpoint:
//  1. tenant resolution (401, no fallback);
//  2. body cap (Meta.BodyCap);
//  3. a single parse;
//  4. internal/csrf, whose bearer exemption holds only when the request resolves to Bearer
//     transport: X-Egauth-Transport, or a cookieless Authorization Bearer credential on an
//     authenticated or session-ending endpoint, never on a login-type one;
//  5. rate limit on the client key, then on the normalised identifier;
//  6. authentication when Meta.Authenticated, with the tenant cross-check, the refusal (401) of a
//     cookie-transport session presented on the CSRF-exempt bearer channel, and the must-change
//     gate, then the rate limit on the session lineage (Meta.SessionLimit);
//  7. the sensitive gate when Meta.Sensitive;
//  8. the BeforeEndpoint hook.
//
// A Preamble is immutable and safe for concurrent use.
type Preamble struct {
	env Env
	set Settings
}

// NewPreamble validates env and s once, so no request can later find a gate unconfigured. It
// returns ErrIncompleteEnv or ErrInvalidSettings, joined.
func NewPreamble(env Env, s Settings) (*Preamble, error) {
	var errs []error
	if missing := env.preambleMissing(s.Insecure.NoRateLimit); len(missing) > 0 {
		errs = append(errs, errors.Join(ErrIncompleteEnv, errors.Join(missing...)))
	}
	if s.Clients == nil {
		errs = append(errs, errors.Join(ErrInvalidSettings, errors.New("Clients")))
	}
	if !s.Transports.valid() {
		errs = append(errs, errors.Join(ErrInvalidSettings, errors.New("Transports")))
	}
	if s.ReauthWindow <= 0 || s.ReauthWindow > maxReauthWindow {
		errs = append(errs, errors.Join(ErrInvalidSettings, errors.New("ReauthWindow outside (0, 1h]")))
	}
	if s.Origins.IsZero() && !s.Insecure.NoOriginCheck {
		errs = append(errs, errors.Join(ErrInvalidSettings, errors.New("Origins")))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &Preamble{env: env, set: s}, nil
}

// Wrap returns the handler serving f at endpoint behind the preamble. It returns ErrInvalidMeta
// for metadata the preamble cannot enforce, an empty endpoint or a nil f.
func (p *Preamble) Wrap(endpoint string, meta Meta, f EndpointFunc) (http.Handler, error) {
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	if endpoint == "" || f == nil {
		return nil, errors.Join(ErrInvalidMeta, errors.New("empty endpoint or nil func"))
	}
	return &gate{p: p, endpoint: endpoint, meta: meta, f: f}, nil
}

// Tenant runs step 1 alone: the resolver's answer, refused when it errs or when a resolver other
// than SingleTenant returns the zero TenantID.
func (p *Preamble) Tenant(r *http.Request) (core.TenantID, error) {
	t, err := p.env.Tenants.ResolveTenant(r)
	if err != nil {
		return core.TenantID{}, errors.Join(ErrUnauthenticated, err)
	}
	if _, single := p.env.Tenants.(singleTenant); t.IsZero() && !single {
		return core.TenantID{}, errors.Join(ErrUnauthenticated, ErrNoTenant)
	}
	return t, nil
}

type gate struct {
	p        *Preamble
	endpoint string
	meta     Meta
	f        EndpointFunc
}

func (g *gate) ServeHTTP(w http.ResponseWriter, hr *http.Request) {
	secureHeaders(w)
	req, err := g.run(w, hr)
	if err != nil {
		if limited, ok := errors.AsType[*rateLimited](err); ok {
			writeRateLimited(w, limited.retryAfter)
			return
		}
		writeProblem(w, err)
		return
	}
	g.f(w, req)
}

type rateLimited struct{ retryAfter int }

func (e *rateLimited) Error() string { return "httpx: rate limited" }

func (g *gate) run(w http.ResponseWriter, hr *http.Request) (*Request, error) {
	set, env := g.p.set, g.p.env
	tenant, err := g.p.Tenant(hr)
	if err != nil {
		return nil, err
	}
	if hr.Body == nil {
		hr.Body = http.NoBody
	}
	hr.Body = http.MaxBytesReader(w, hr.Body, g.meta.BodyCap)
	fields, isJSON, raw, err := parse(hr, g.meta)
	if err != nil {
		return nil, err
	}
	requested := g.requestedTransport(hr)
	pol := csrf.Policy{
		Origins: set.Origins.For(tenant), SetsCookies: g.meta.SetsCookies, Authenticated: g.meta.Authenticated,
		BearerTransport: requested == core.TransportBearer,
	}
	if err := g.originCheck(hr, pol); err != nil {
		return nil, err
	}
	client, err := set.Clients.Resolve(hr)
	if err != nil {
		return nil, errors.Join(ErrInvalidRequest, err)
	}
	req := &Request{
		http: hr, endpoint: g.endpoint, meta: g.meta, tenant: tenant, client: client,
		fields: fields, jsonBody: isJSON, raw: raw, transport: requested,
	}
	if !set.Insecure.NoRateLimit {
		if err := g.limit(req); err != nil {
			return nil, err
		}
	}
	if g.meta.Authenticated {
		if err := g.authenticate(w, req, pol.BearerTransport && !cookie.Present(hr)); err != nil {
			return nil, err
		}
		if c := g.meta.SessionLimit; c != 0 && !set.Insecure.NoRateLimit {
			if err := g.charge(req, limiter.Key{Class: c, Value: "session:" + req.resumed.Attrs().Lineage().String()}); err != nil {
				return nil, err
			}
		}
	}
	if g.meta.Sensitive {
		if err := g.sensitive(req); err != nil {
			return nil, err
		}
	}
	if g.meta.RecipientLimit != 0 && !set.Insecure.NoRateLimit {
		if err := g.limitRecipient(req); err != nil {
			return nil, err
		}
	}
	if env.BeforeEndpoint != nil {
		call := EndpointCall{Endpoint: g.endpoint, Client: client.Addr(), Tenant: tenant, captchaToken: fields[fieldCaptchaToken]}
		if err := env.BeforeEndpoint.BeforeEndpoint(hr.Context(), call); err != nil {
			return nil, errors.Join(ErrRequestRejected, err)
		}
	}
	return req, nil
}

func (g *gate) originCheck(hr *http.Request, pol csrf.Policy) error {
	if g.p.set.Insecure.NoOriginCheck {
		return nil
	}
	if err := csrf.Check(hr, pol); err != nil {
		return errors.Join(ErrCrossSite, err)
	}
	return nil
}

func (g *gate) requestedTransport(hr *http.Request) core.Transport {
	switch g.p.set.Transports {
	case BearerOnly:
		return core.TransportBearer
	case CookiesAndBearer:
		if csrf.BearerTransportHeader(hr) {
			return core.TransportBearer
		}
		if (g.meta.Authenticated || g.meta.EndsSession) && !cookie.Present(hr) && csrf.BearerAuthorization(hr) {
			return core.TransportBearer
		}
	}
	return core.TransportCookies
}

func (g *gate) limit(req *Request) error {
	if c := g.meta.ClientLimit; c != 0 {
		if err := g.charge(req, limiter.Key{Class: c, Value: req.client.Key()}); err != nil {
			return err
		}
	}
	c := g.meta.IdentifierLimit
	raw := req.fields[fieldIdentifier]
	if c == 0 || raw == "" {
		return nil
	}
	id, err := g.p.env.Identifiers.Normalize(raw)
	if err != nil || id.IsZero() {
		return nil
	}
	return g.charge(req, limiter.Key{Class: c, Tenant: req.tenant, Value: limiterValue(id.Kind().String() + ":" + id.Value())})
}

func limiterValue(v string) string {
	if len(v) <= maxLimiterValue {
		return v
	}
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func (g *gate) charge(req *Request, k limiter.Key) error {
	d, err := g.p.env.Limiter.Allow(req.Context(), k)
	if err != nil {
		return errors.Join(ErrServiceUnavailable, err)
	}
	if !d.Allowed {
		secs := int((d.RetryAfter + time.Second - 1) / time.Second)
		return &rateLimited{retryAfter: secs}
	}
	return nil
}

func (g *gate) authenticate(w http.ResponseWriter, req *Request, bearerChannel bool) error {
	res, err := g.p.env.Authenticator.Resume(req.Context(), w, req.http, req.tenant)
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return errors.Join(ErrServiceUnavailable, err)
		}
		return errors.Join(ErrUnauthenticated, err)
	}
	a := res.Attrs()
	if a.IsZero() || a.Subject().IsZero() || a.Subject().Tenant != req.tenant {
		discardCredentials(w)
		return errors.Join(ErrUnauthenticated, errors.New("session tenant differs from the resolved tenant"))
	}
	if bearerChannel && a.Transport() != core.TransportBearer {
		discardCredentials(w)
		return errors.Join(ErrUnauthenticated, errors.New("cookie-transport session presented on the bearer channel"))
	}
	if a.MustChangePassword() && !g.meta.AcceptsMustChange {
		return ErrPasswordChangeNeeded
	}
	req.resumed, req.hasSess, req.transport = res, true, a.Transport()
	return nil
}

func discardCredentials(w http.ResponseWriter) {
	cookie.Discard(w)
	for _, h := range bearerResponseHeaders {
		w.Header().Del(h)
	}
}

func (g *gate) sensitive(req *Request) error {
	if !req.hasSess {
		return ErrReauthRequired
	}
	a := req.resumed.Attrs()
	required, err := g.p.env.Enrollment.MFARequired(req.Context(), a.Subject())
	if err != nil {
		return errors.Join(ErrServiceUnavailable, err)
	}
	if required && !a.MultiFactor() {
		return ErrReauthRequired
	}
	if !g.p.set.Insecure.NoReauthWindow && !a.FreshWithin(g.p.set.ReauthWindow, g.p.env.Clock.Now()) {
		return ErrReauthRequired
	}
	return nil
}

// limitRecipient charges the per-recipient bucket of an endpoint that sends to a caller-chosen
// address. A value the normaliser refuses is left to the service, which refuses it too.
func (g *gate) limitRecipient(req *Request) error {
	raw := req.fields[g.meta.RecipientField]
	if raw == "" {
		return nil
	}
	id, err := g.p.env.Identifiers.Normalize(raw)
	if err != nil || id.IsZero() {
		return nil
	}
	return g.charge(req, limiter.Key{Class: g.meta.RecipientLimit, Tenant: req.tenant, Value: limiterValue("recipient:" + id.Kind().String() + ":" + id.Value())})
}
