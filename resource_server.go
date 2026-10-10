package egauth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/configcheck"
	"github.com/JLugagne/egauth/internal/outbound"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session/jwt"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
)

const (
	maxDiscoveryBytes   = 64 << 10
	maxJWKSBytes        = 256 << 10
	resourceMaxLifetime = 15 * time.Minute
	reasonLagAccepted   = "revocation_lag_up_to_ttl"
)

// ResourceConfig is the whole wiring of a ResourceServer; NewResourceServer is its only consumer.
// AuthOrigin is the exact origin of the Auth, without {tenant}: a resource server verifies one
// issuer. Audience must be one of the Auth's Config.Audiences. Revocation is FromStorage over the
// Storage the Auth uses, unless Insecure.RevocationLagUpToTTL is set and Revocation is left nil.
//
// Tenant is the one tenant whose tokens the server accepts; empty means the zero tenant of a
// SingleTenant Auth. A token whose tenant differs is refused with 401 and never triggers a JWKS
// fetch. Set it to the tenant behind AuthOrigin for a TenantBySubdomain or TenantFromRequest Auth.
// NewResourceServer compares it with the tenant the Auth's discovery document reports for
// AuthOrigin and returns a ConfigError on a mismatch.
//
// Proxy is validated for parity with Config.Proxy but a resource server derives no client address
// from it. The Auth must be reachable on a public address: there is no outbound private-network
// allowance in ResourceInsecure.
type ResourceConfig struct {
	AuthOrigin string           `egauth:"required,origin"`
	Audience   string           `egauth:"required,origin"`
	Tenant     string           `egauth:"optional"`
	Proxy      ProxyPolicy      `egauth:"required"`
	Revocation RevocationSource `egauth:"required"`
	Events     event.Sink       `egauth:"default=slog_default"`
	Outbound   OutboundObserver `egauth:"optional"`
	Insecure   ResourceInsecure `egauth:"optional"`
}

// ResourceInsecure is the only place where a resource server's default control is weakened.
type ResourceInsecure struct {
	// RevocationLagUpToTTL accepts a resource token until it expires, up to SessionPolicy.RecheckEvery
	// after the session was revoked. It requires ResourceConfig.Revocation to be nil, and
	// NewResourceServer emits one event.InsecureConfiguration.
	RevocationLagUpToTTL *Ack
}

// RevocationSource says where a resource server learns that a session family or a subject's
// security epoch changed. Build it with FromStorage.
type RevocationSource interface {
	revocation() revocationSpec
}

type revocationSpec struct {
	families revoke.FamilySource
	epochs   revoke.EpochSource
	lag      bool
}

func (r revocationSpec) revocation() revocationSpec { return r }

// FromStorage verifies revocation, epochs and families against the same Storage the Auth uses. It
// needs Storage.Tokens and Storage.Identity; NewResourceServer rejects a Storage without them.
func FromStorage(s Storage) RevocationSource {
	var spec revocationSpec
	if present(s.Tokens) {
		spec.families = s.Tokens
	}
	if present(s.Identity) {
		spec.epochs = s.Identity
	}
	return spec
}

// ResourceServer verifies the resource tokens an Auth mints for one audience and serves the routes
// declared on Routes. It holds no signing material: keys come from the Auth's JWKS. It is safe for
// concurrent use.
type ResourceServer[C any] struct {
	cfg       ResourceConfig
	codec     *jwt.Codec
	keys      *jwksSource
	families  *revoke.Families
	epochs    *revoke.Epochs
	clock     clock.Clock
	events    event.Sink
	outbound  *outbound.Clients
	closed    atomic.Bool
	closeOnce sync.Once
}

type rsSeams struct {
	clock   clock.Clock
	rootCAs *x509.CertPool
	private outbound.Allowance
}

// TestResourceSeams replaces what a journey test cannot otherwise drive in a ResourceServer: its
// clock and the roots its outbound client trusts. The zero value keeps the wall clock and the
// system roots.
type TestResourceSeams struct {
	Clock   TestClock
	RootCAs *x509.CertPool
}

// TestHookNewResourceServer is NewResourceServer with seams and a 127.0.0.0/8 outbound allowance, so
// that it can reach an httptest Auth. Like every TestHook it returns an error unless called from
// package egauthtest.
func TestHookNewResourceServer[C any](cfg ResourceConfig, s TestResourceSeams) (*ResourceServer[C], error) {
	if !calledByEgauthtest() {
		return nil, errHookCaller
	}
	allow, err := outbound.NewAllowance([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	if err != nil {
		return nil, err
	}
	return newResourceServer[C](cfg, rsSeams{clock: s.Clock, rootCAs: s.RootCAs, private: allow})
}

// NewResourceServer validates cfg, fetches the Auth's discovery document and JWKS, and starts the
// revocation followers that Close stops. It returns every problem at once as an errors.Join of
// *ConfigError: an AuthOrigin whose issuer is another origin, an Audience the Auth does not
// publish, a claims type C other than the Auth's, a deployment that publishes no JWKS (HS256 or
// stateful sessions), or a discovery or JWKS fetch that fails. It takes no context; its blocking
// calls are bounded by StartupTimeout.
func NewResourceServer[C any](cfg ResourceConfig) (*ResourceServer[C], error) {
	return newResourceServer[C](cfg, rsSeams{})
}

func newResourceServer[C any](cfg ResourceConfig, sm rsSeams) (*ResourceServer[C], error) {
	cfg.Insecure.RevocationLagUpToTTL = clonePtr(cfg.Insecure.RevocationLagUpToTTL)
	v := &problems{}
	checkResourceInsecure(&cfg, v)
	_, errs := configcheck.Validate(&cfg, resourceOptions())
	for _, e := range errs {
		v.add(e.Field, e.Problem)
	}
	if err := v.err(); err != nil {
		return nil, err
	}
	spec, ok := specOf(cfg.Revocation.revocation)
	checkResourceWiring(&cfg, spec, ok, v)
	if err := v.err(); err != nil {
		return nil, err
	}
	rs := &ResourceServer[C]{cfg: cfg, clock: sm.clock, events: cfg.Events}
	oc := outbound.Config{Static: sm.private, RootCAs: sm.rootCAs}
	if present(cfg.Outbound) {
		oc.Observer = cfg.Outbound
	}
	rs.outbound = outbound.New(oc)
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	jwksURI := rs.discover(ctx, claimsFingerprint[C](), v)
	if err := v.err(); err != nil {
		rs.outbound.CloseIdle()
		return nil, err
	}
	if err := rs.bringUp(ctx, jwksURI, spec); err != nil {
		rs.stop()
		return nil, err
	}
	if spec.lag {
		_ = audit.Emit(ctx, rs.events, event.InsecureConfiguration, audit.Scope{}, audit.Detail{Reason: reasonLagAccepted}, nil,
			audit.A(event.KeyPurpose, "ResourceConfig.Insecure.RevocationLagUpToTTL"))
	}
	return rs, nil
}

func resourceOptions() configcheck.Options {
	return configcheck.Options{
		Defaults: configcheck.Defaults{"slog_default": func(*configcheck.Resolved) any { return event.NewSlogSink(nil) }},
	}
}

func checkResourceInsecure(cfg *ResourceConfig, v *problems) {
	lag := cfg.Insecure.RevocationLagUpToTTL
	if lag == nil {
		return
	}
	if !lag.valid() {
		v.add("Insecure.RevocationLagUpToTTL", "needs Acknowledge with a non-empty reason")
	}
	if present(cfg.Revocation) {
		v.add("Insecure.RevocationLagUpToTTL", "contradicts Revocation: leave Revocation nil to accept the lag, or drop the opt-out")
		return
	}
	cfg.Revocation = revocationSpec{lag: true}
}

func checkResourceWiring(cfg *ResourceConfig, spec revocationSpec, ok bool, v *problems) {
	if strings.Contains(cfg.AuthOrigin, tenantLabel) {
		v.add("AuthOrigin", "must not contain "+tenantLabel+": a resource server verifies one issuer")
	}
	if !ok {
		v.add("Revocation", "is not built by FromStorage")
	} else if !spec.lag && (spec.families == nil || spec.epochs == nil) {
		v.add("Revocation", "FromStorage needs Storage.Tokens and Storage.Identity")
	}
	if cfg.Tenant != "" {
		if _, err := principal.ParseTenantID(cfg.Tenant); err != nil {
			v.add("Tenant", "is not a valid tenant identifier")
		}
	}
	proxy := Config[struct{}]{Proxy: cfg.Proxy, Events: cfg.Events}
	buildClients(&proxy, v)
}

type discoveryReply struct {
	Issuer            string   `json:"issuer"`
	JWKSURI           string   `json:"jwks_uri"`
	Audiences         []string `json:"audiences"`
	ClaimsFingerprint string   `json:"claims_fingerprint"`
	Tenant            string   `json:"tenant,omitempty"`
}

func (rs *ResourceServer[C]) discover(ctx context.Context, fingerprint string, v *problems) string {
	var doc discoveryReply
	if err := rs.getJSON(ctx, rs.cfg.AuthOrigin+routes.WellKnown, maxDiscoveryBytes, &doc); err != nil {
		v.errs = append(v.errs, errors.Join(&ConfigError{Field: "AuthOrigin", Problem: "discovery document unavailable"}, err))
		return ""
	}
	if doc.Issuer != rs.cfg.AuthOrigin {
		v.add("AuthOrigin", "the discovery issuer is not AuthOrigin")
	}
	if !slices.Contains(doc.Audiences, rs.cfg.Audience) {
		v.add("Audience", "is not one of the audiences the Auth publishes; set Config.Audiences")
	}
	if doc.ClaimsFingerprint != fingerprint {
		v.add("AuthOrigin", "the Auth was built with another claims type than NewResourceServer's C")
	}
	if doc.Tenant != rs.cfg.Tenant {
		v.add("Tenant", "is not the tenant the Auth serves at AuthOrigin")
	}
	if doc.JWKSURI == "" {
		v.add("AuthOrigin", "the Auth publishes no JWKS: resource servers need asymmetric JWT sessions")
	} else if !strings.HasPrefix(doc.JWKSURI, rs.cfg.AuthOrigin+"/") {
		v.add("AuthOrigin", "the discovery jwks_uri is not on AuthOrigin")
	}
	return doc.JWKSURI
}

func (rs *ResourceServer[C]) getJSON(ctx context.Context, url string, limit int64, into any) error {
	body, err := rs.get(ctx, url, limit)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, into)
}

func (rs *ResourceServer[C]) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := rs.outbound.Static().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("status " + http.StatusText(resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("response larger than the limit")
	}
	return body, nil
}

func (rs *ResourceServer[C]) fetchKeys(ctx context.Context, url string) ([]signing.Verifier, error) {
	body, err := rs.get(ctx, url, maxJWKSBytes)
	if err != nil {
		return nil, err
	}
	var probe struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if json.Unmarshal(body, &probe) == nil && probe.Keys != nil && len(probe.Keys) == 0 {
		return nil, nil
	}
	return signing.ParseJWKS(body)
}

func (rs *ResourceServer[C]) bringUp(ctx context.Context, jwksURI string, spec revocationSpec) error {
	rs.keys = &jwksSource{tenant: rs.cfg.Tenant, fetch: func(ctx context.Context) ([]signing.Verifier, error) { return rs.fetchKeys(ctx, jwksURI) }, clk: rs.clock}
	if err := rs.keys.refresh(ctx, rs.clock.Now()); err != nil {
		return errors.Join(&ConfigError{Field: "AuthOrigin", Problem: "JWKS unavailable"}, err)
	}
	if rs.keys.empty() {
		return &ConfigError{Field: "AuthOrigin", Problem: "JWKS unavailable: the Auth publishes no key"}
	}
	codec, err := jwt.NewCodec(jwt.CodecConfig{
		PublicOrigin: rs.cfg.AuthOrigin, ClaimsFingerprint: claimsFingerprint[C](), RecheckEvery: resourceMaxLifetime, Clock: rs.clock,
	})
	if err != nil {
		return errors.Join(&ConfigError{Field: "AuthOrigin", Problem: "token codec"}, err)
	}
	rs.codec = codec
	if spec.lag {
		return nil
	}
	rc := revoke.Config{Clock: rs.clock, Events: rs.events}
	if rs.families, err = revoke.NewFamilies(spec.families, rc); err != nil {
		return errors.Join(&ConfigError{Field: "Revocation", Problem: "family cache"}, err)
	}
	if rs.epochs, err = revoke.NewEpochs(spec.epochs, rc); err != nil {
		return errors.Join(&ConfigError{Field: "Revocation", Problem: "epoch cache"}, err)
	}
	rs.families.Start()
	rs.epochs.Start()
	return nil
}

func (rs *ResourceServer[C]) stop() {
	if rs.families != nil {
		rs.families.Stop()
	}
	if rs.epochs != nil {
		rs.epochs.Stop()
	}
	rs.outbound.CloseIdle()
}

// Close stops the revocation followers and waits for them. It is idempotent. Requests served after
// Close keep their security properties because every revocation check falls back to the store.
func (rs *ResourceServer[C]) Close() error {
	rs.closeOnce.Do(func() {
		rs.closed.Store(true)
		rs.stop()
	})
	return nil
}
