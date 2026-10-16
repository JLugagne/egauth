package egauth

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/publicsuffix"

	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/configcheck"
	"github.com/JLugagne/egauth/internal/outbound"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/signing"
	"github.com/JLugagne/egauth/store"
)

// StartupTimeout bounds every blocking call New makes.
const StartupTimeout = 30 * time.Second

// Auth is the composition object: the only owner of every policy object, store and background
// worker of a deployment. Build it with New; it is safe for concurrent use.
type Auth[C any] struct {
	cfg        Config[C]
	durability store.Durability
	owned      *owned
	closed     atomic.Bool
	closeOnce  sync.Once
}

// New validates the whole wiring and the deployment it points at, then starts the background work
// that Close stops. It returns every problem at once as an errors.Join of *ConfigError, each naming
// the exact field path. It checks the egauth tags of Config, the origins, the passkey relying party
// id against the origins, the store durabilities, the modules and the InsecureOptOuts
// acknowledgements, then the deployment: the schema of every store, the KEK canary, v0.16 secrets
// left in place, second-factor enrollments whose module is absent, OAuth discovery, the limiter and
// the auth route table. New bounds its own blocking calls with StartupTimeout; it takes no context
// so that no caller deadline can end background work.
func New[C any](cfg Config[C]) (*Auth[C], error) {
	return newWith(cfg, seams{})
}

func newWith[C any](cfg Config[C], sm seams) (*Auth[C], error) {
	cfg = snapshot(cfg)
	v := &problems{}
	res, errs := configcheck.Validate(&cfg, configOptions(&cfg))
	for _, e := range errs {
		v.add(e.Field, e.Problem)
	}
	checkPolicies(&cfg, v)
	checkOrigins(&cfg, v)
	checkPasskey(&cfg, v)
	durability := checkDurability(&cfg, v)
	checkModules(&cfg, v)
	checkInsecure(&cfg, v)
	checkNoticePath(&cfg, v)
	checkRecoveryPage(&cfg, v)
	checkExtraOriginLabels(&cfg, v)
	if err := v.err(); err != nil {
		return nil, err
	}
	pol := buildPolicies(&cfg, v)
	if err := v.err(); err != nil {
		return nil, err
	}
	o := &owned{instance: uuid.New(), sharedLimit: res.Defaulted("RateLimit"), seams: sm}
	if err := bringUp(&cfg, pol, o, durability, v); err != nil {
		_ = o.closeAll()
		return nil, err
	}
	return &Auth[C]{cfg: cfg, durability: durability, owned: o}, nil
}

func bringUp[C any](cfg *Config[C], pol *policies, o *owned, durability store.Durability, v *problems) error {
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	checkSchema(ctx, cfg, o.sharedLimit, v)
	if err := v.err(); err != nil {
		return err
	}
	o.dataKey = openDataKey(ctx, cfg, v)
	checkLegacySecrets(ctx, cfg, v)
	checkEnrollments(ctx, cfg, v)
	if err := v.err(); err != nil {
		return err
	}
	o.scaleLimit = scalesLimiter(cfg, durability)
	assemble(ctx, cfg, pol, o, v)
	if err := v.err(); err != nil {
		return err
	}
	if err := finish(ctx, cfg, o, v); err != nil {
		return err
	}
	startWork(cfg, o)
	return nil
}

// Close stops background work and waits for it, returning the errors of the services it closed.
// Close is idempotent: only the first call stops anything and returns an error. Requests served
// after Close keep their security properties because every revocation check falls back to the
// store.
func (a *Auth[C]) Close() error {
	var err error
	a.closeOnce.Do(func() {
		a.closed.Store(true)
		if a.owned != nil {
			err = a.owned.stop()
		}
	})
	return err
}

func (a *Auth[C]) deployment() routes.Deployment {
	d := routes.Deployment{BasePath: a.cfg.BasePath}
	if m := a.cfg.Modules.APIKeys; m != nil {
		d.APIKeys, d.APIKinds = true, slices.Clone(m.Kinds)
	}
	return d
}

type namedStore struct {
	field string
	base  store.Base
}

func (a *Auth[C]) stores() []namedStore {
	all := presentStores(&a.cfg.Storage, true)
	if a.owned != nil && !a.owned.sharedLimit && present(a.cfg.RateLimit) {
		all = append(all, namedStore{"RateLimit", a.cfg.RateLimit})
	}
	return all
}

func presentStores(s *Storage, withLimiter bool) []namedStore {
	all := []namedStore{
		{"Storage.Identity", s.Identity},
		{"Storage.Ceremonies", s.Ceremonies},
		{"Storage.Deployment", s.Deployment},
		{"Storage.Tokens", s.Tokens},
		{"Storage.Sessions", s.Sessions},
		{"Storage.MFA", s.MFA},
		{"Storage.Passkeys", s.Passkeys},
		{"Storage.Federation", s.Federation},
		{"Storage.Keys", s.Keys},
	}
	if withLimiter {
		all = append(all, namedStore{"Storage.Limiter", s.Limiter})
	}
	return slices.DeleteFunc(all, func(n namedStore) bool { return !present(n.base) })
}

type problems struct {
	errs []error
}

func (p *problems) add(field, problem string) {
	p.errs = append(p.errs, &ConfigError{Field: field, Problem: problem})
}

func (p *problems) err() error {
	return errors.Join(p.errs...)
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

func specOf[T any](f func() T) (spec T, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return f(), true
}

const (
	tenantLabel  = "{tenant}"
	sampleTenant = "tenant"
)

var (
	tokenRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	wellKnownRoot = path.Dir(routes.WellKnown)
)

func checkPolicies[C any](cfg *Config[C], v *problems) {
	if cfg.Proxy != nil {
		p, ok := specOf(cfg.Proxy.proxy)
		switch {
		case !ok || !p.set:
			v.add("Proxy", "must come from DirectClients or TrustedProxies")
		default:
			for i, pfx := range p.trusted {
				if problem := proxyPrefixProblem(pfx); problem != "" {
					v.add("Proxy", "trusted prefix "+strconv.Itoa(i)+" ("+pfx.String()+") "+problem)
				}
			}
		}
	}
	if cfg.Tenancy != nil {
		t, ok := specOf(cfg.Tenancy.tenancy)
		switch {
		case !ok || t.kind < tenancySingle || t.kind > tenancyRequest:
			v.add("Tenancy", "must come from SingleTenant, TenantBySubdomain or TenantFromRequest")
		case t.kind == tenancyRequest && !present(t.resolver):
			v.add("Tenancy", "TenantFromRequest needs a non-nil resolver")
		}
	}
	if cfg.Sessions != nil {
		checkBackend(cfg.Sessions, v)
	}
	if cfg.Admin != nil {
		a, ok := specOf(cfg.Admin.admin)
		switch {
		case !ok || (a.kind != adminRole && a.kind != adminSelfOnly):
			v.add("Admin", "must come from RoleAdmin or SelfServiceOnly")
		case a.kind == adminRole && strings.TrimSpace(a.role) == "":
			v.add("Admin", "RoleAdmin needs a non-blank role")
		}
	}
	if !cfg.Transport.valid() {
		v.add("Transport", "must be Cookies, Bearer or CookiesAndBearer")
	}
	if r := cfg.Policy.Remember; r != RememberUserChoice && r != RememberAlways && r != RememberNever {
		v.add("Policy.Remember", "must be RememberUserChoice, RememberAlways or RememberNever")
	}
}

func proxyPrefixProblem(p netip.Prefix) string {
	switch {
	case !p.IsValid():
		return "is invalid"
	case p.Addr().Zone() != "":
		return "is zoned"
	case p.Addr().Is4In6():
		return "is IPv4-mapped; use the IPv4 form"
	case p.Bits() == 0:
		return "trusts every address"
	case p.Addr().Is4() && p.Bits() < 8:
		return "is shorter than /8"
	case p.Addr().Is6() && p.Bits() < 16:
		return "is shorter than /16"
	}
	for _, r := range ipv4Embeddings {
		if p != r.except && p.Overlaps(r.prefix) && (r.anyOverlap || p.Bits() <= r.prefix.Bits()) {
			return "overlaps " + r.prefix.String() + ", where IPv6 addresses stand for IPv4 hosts; use the IPv4 form"
		}
	}
	return ""
}

var ipv4Embeddings = []struct {
	prefix     netip.Prefix
	anyOverlap bool
	except     netip.Prefix
}{
	{netip.MustParsePrefix("::/96"), true, netip.MustParsePrefix("::1/128")},
	{netip.MustParsePrefix("::ffff:0:0/96"), true, netip.Prefix{}},
	{netip.MustParsePrefix("64:ff9b::/96"), true, netip.Prefix{}},
	{netip.MustParsePrefix("64:ff9b:1::/48"), true, netip.Prefix{}},
	{netip.MustParsePrefix("2002::/16"), true, netip.Prefix{}},
}

func checkBackend(b SessionBackend, v *problems) {
	spec, ok := specOf(b.backend)
	switch {
	case !ok || (spec.kind != backendJWT && spec.kind != backendStateful):
		v.add("Sessions", "must come from JWT or Stateful")
		return
	case spec.kind == backendStateful:
		return
	case spec.keys == nil:
		v.add("Sessions", "JWT needs StaticKeys or TenantKeys")
		return
	}
	k, ok := specOf(spec.keys.keys)
	switch {
	case !ok || (k.kind != keysStatic && k.kind != keysTenant):
		v.add("Sessions", "JWT keys must come from StaticKeys or TenantKeys")
	case k.kind == keysTenant:
	case k.active.IsZero():
		v.add("Sessions", "StaticKeys needs an active signer")
	default:
		all := []signing.Verifier{k.active.Verifier()}
		for i, vo := range k.verifyOnly {
			if vo.IsZero() {
				v.add("Sessions", "StaticKeys verify-only key "+strconv.Itoa(i)+" is zero")
				continue
			}
			all = append(all, vo)
		}
		if err := signing.CheckKeyIDs(all...); err != nil {
			v.add("Sessions", "StaticKeys: "+err.Error())
		}
	}
}

func backendOf(b SessionBackend) (backendSpec, keySpec) {
	if b == nil {
		return backendSpec{}, keySpec{}
	}
	spec, ok := specOf(b.backend)
	if !ok || spec.keys == nil {
		return spec, keySpec{}
	}
	k, _ := specOf(spec.keys.keys)
	return spec, k
}

func tenancyOf(t Tenancy) tenancyKind {
	if t == nil {
		return 0
	}
	spec, _ := specOf(t.tenancy)
	return spec.kind
}

func checkOrigins[C any](cfg *Config[C], v *problems) {
	sub := tenancyOf(cfg.Tenancy) == tenancySubdomain
	hasLabel := strings.Contains(cfg.PublicOrigin, tenantLabel)
	switch {
	case sub && !hasLabel:
		v.add("PublicOrigin", "TenantBySubdomain needs exactly one "+tenantLabel+" host label")
	case !sub && hasLabel:
		v.add("PublicOrigin", "has a "+tenantLabel+" label but Tenancy is not TenantBySubdomain")
	}
	for i, o := range cfg.ExtraOrigins {
		if !sub && strings.Contains(o, tenantLabel) {
			v.add("ExtraOrigins["+strconv.Itoa(i)+"]", "has a "+tenantLabel+" label but Tenancy is not TenantBySubdomain")
		}
	}
	for i, a := range cfg.Audiences {
		field := "Audiences[" + strconv.Itoa(i) + "]"
		switch {
		case strings.Contains(a, tenantLabel):
			v.add(field, "must be a fixed origin, without "+tenantLabel)
		case a != "" && sameOrTenantOf(cfg.PublicOrigin, a):
			v.add(field, "must not equal PublicOrigin or one of its tenant origins: session tokens are never accepted by resource servers")
		case a != "" && slices.ContainsFunc(cfg.ExtraOrigins, func(o string) bool { return sameOrTenantOf(o, a) }):
			v.add(field, "must not equal an ExtraOrigins entry or one of its tenant origins: session tokens are never accepted by resource servers")
		}
	}
	if cfg.BasePath == wellKnownRoot || strings.HasPrefix(cfg.BasePath, wellKnownRoot+"/") {
		v.add("BasePath", "must not be under "+wellKnownRoot+", which holds the discovery document")
	}
	if s := cfg.Insecure.SharedCookieDomain; s != nil {
		checkSharedDomain(cfg, s.Domain, v)
	}
}

func sameOrTenantOf(pattern, origin string) bool {
	if pattern == origin {
		return true
	}
	prefix, suffix, ok := strings.Cut(pattern, tenantLabel)
	if !ok {
		return false
	}
	label, ok := strings.CutPrefix(strings.ToLower(origin), prefix)
	if !ok {
		return false
	}
	label, ok = strings.CutSuffix(label, suffix)
	return ok && label != "" && !strings.ContainsAny(label, "./:@")
}

func checkSharedDomain[C any](cfg *Config[C], domain string, v *problems) {
	const field = "Insecure.SharedCookieDomain.Domain"
	if domain == "" || strings.Contains(domain, tenantLabel) || !registrable(domain) || domain != strings.ToLower(domain) {
		v.add(field, "must be a lower-case registrable domain")
		return
	}
	for _, o := range originHosts(cfg) {
		if o.host != "" && !domainCovers(domain, o.host) {
			v.add(field, "is not a suffix of the host of "+o.field)
		}
	}
}

type originHost struct {
	field string
	host  string
}

func originHosts[C any](cfg *Config[C]) []originHost {
	out := []originHost{{"PublicOrigin", hostOf(cfg.PublicOrigin)}}
	for i, o := range cfg.ExtraOrigins {
		out = append(out, originHost{"ExtraOrigins[" + strconv.Itoa(i) + "]", hostOf(o)})
	}
	return out
}

func hostOf(origin string) string {
	u, err := url.Parse(strings.Replace(origin, tenantLabel, sampleTenant, 1))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

func domainCovers(domain, host string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func registrable(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	_, err := publicsuffix.EffectiveTLDPlusOne(host)
	return err == nil
}

func isLoopbackOrigin(origin string) bool {
	host := hostOf(origin)
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func loopbackOnly[C any](cfg *Config[C]) bool {
	all := append([]string{cfg.PublicOrigin}, cfg.ExtraOrigins...)
	all = append(all, cfg.Audiences...)
	return !slices.ContainsFunc(all, func(o string) bool { return !isLoopbackOrigin(o) })
}

func checkPasskey[C any](cfg *Config[C], v *problems) {
	if cfg.Modules.Passkey == nil {
		return
	}
	rpID := hostOf(cfg.PublicOrigin)
	if rpID == "" {
		return
	}
	if _, err := netip.ParseAddr(rpID); err == nil {
		v.add("PublicOrigin", "passkeys need a domain name as relying party id, not the IP address "+rpID)
		return
	}
	if !registrable(rpID) {
		v.add("PublicOrigin", "passkey relying party id "+rpID+" is a public suffix")
		return
	}
	for _, o := range originHosts(cfg)[1:] {
		if o.host != "" && !domainCovers(rpID, o.host) {
			v.add(o.field, "host "+o.host+" is outside the passkey relying party id "+rpID+", so browsers refuse its ceremonies")
		}
	}
}

func checkDurability[C any](cfg *Config[C], v *problems) store.Durability {
	var common store.Durability
	var first string
	for _, s := range presentStores(&cfg.Storage, false) {
		d, ok := specOf(s.base.Durability)
		if !ok || !d.Valid() {
			v.add(s.field, "reports an invalid durability")
			continue
		}
		switch {
		case common == 0:
			common, first = d, s.field
		case d != common:
			v.add(s.field, "is "+d.String()+" while "+first+" is "+common.String()+"; every security store needs the same durability")
		}
	}
	for _, l := range []namedStore{{"Storage.Limiter", cfg.Storage.Limiter}, {"RateLimit", cfg.RateLimit}} {
		if !present(l.base) {
			continue
		}
		if d, ok := specOf(l.base.Durability); !ok || !d.Valid() {
			v.add(l.field, "reports an invalid durability")
		}
	}
	if common == store.Ephemeral && !loopbackOnly(cfg) && cfg.Insecure.EphemeralState == nil {
		v.add("Storage", "ephemeral stores lose every session on restart and are not shared between instances; "+
			"use shared stores, loopback PublicOrigin, ExtraOrigins and Audiences, or Insecure.EphemeralState")
	}
	return common
}

func checkModules[C any](cfg *Config[C], v *problems) {
	m := &cfg.Modules
	if m.LoginCode != nil && !m.LoginCode.Email && !m.LoginCode.SMS {
		v.add("Modules.LoginCode", "enables neither Email nor SMS")
	}
	if m.Verification != nil && !m.Verification.Email && !m.Verification.Phone && !m.Verification.RecoveryEmail {
		v.add("Modules.Verification", "enables neither Email, Phone nor RecoveryEmail")
	}
	if m.Password != nil && !m.Password.Registration.valid() {
		v.add("Modules.Password.Registration", "must be RegistrationOpen or RegistrationInviteOnly")
	}
	if m.Passkey != nil && !m.Passkey.Attestation.valid() {
		v.add("Modules.Passkey.Attestation", "must be AttestationNone")
	}
	if m.OAuth != nil {
		checkOAuth(m.OAuth, v)
	}
	if m.External != nil {
		checkExternal(m.External, v)
	}
	if m.APIKeys != nil {
		unique("Modules.APIKeys.Kinds", m.APIKeys.Kinds, v)
	}
	checkPages(cfg, v)
	checkAudiences(cfg, v)
}

func unique(field string, values []string, v *problems) {
	seen := map[string]int{}
	for i, s := range values {
		if s == "" {
			continue
		}
		if j, ok := seen[s]; ok {
			v.add(field+"["+strconv.Itoa(i)+"]", "duplicates "+field+"["+strconv.Itoa(j)+"]")
			continue
		}
		seen[s] = i
	}
}

func checkOAuth(m *OAuthModule, v *problems) {
	if len(m.Providers) == 0 && !m.PerTenant {
		v.add("Modules.OAuth", "has no provider and PerTenant is off")
	}
	names := make([]string, len(m.Providers))
	for i, p := range m.Providers {
		names[i] = p.Name
	}
	unique("Modules.OAuth.Providers", names, v)
}

func checkExternal(m *ExternalModule, v *problems) {
	var names []string
	for i, f := range m.Verifiers {
		field := "Modules.External.Verifiers[" + strconv.Itoa(i) + "]"
		if !present(f) {
			names = append(names, "")
			continue
		}
		name, ok := specOf(f.Name)
		if !ok || !tokenRE.MatchString(name) {
			v.add(field, "Name must be a token (1 to 32 of [a-z0-9_-], starting with a letter or digit)")
			name = ""
		}
		names = append(names, name)
	}
	unique("Modules.External.Verifiers", names, v)
}

func checkPages[C any](cfg *Config[C], v *problems) {
	origins, err := sampleOrigins(cfg)
	if err != nil {
		return
	}
	pv := reflect.ValueOf(cfg.Pages)
	for i := range pv.NumField() {
		page := pv.Field(i).String()
		if strings.TrimSpace(page) == "" {
			continue
		}
		if _, err := redirect.Parse(samplePage(page), origins); err != nil {
			v.add("Pages."+pv.Type().Field(i).Name, "must be a relative path or an absolute URL on PublicOrigin or ExtraOrigins")
		}
	}
}

func checkAudiences[C any](cfg *Config[C], v *problems) {
	if len(cfg.Audiences) == 0 || cfg.Sessions == nil {
		return
	}
	b, k := backendOf(cfg.Sessions)
	switch {
	case b.kind == backendStateful:
		v.add("Audiences", "resource servers need the JWT session backend")
	case k.kind == keysStatic && !k.active.IsZero() && k.active.Verifier().Symmetric():
		v.add("Audiences", "resource servers need an asymmetric signing key; HS256 keys are never published")
	}
}

type optOut struct {
	name string
	set  bool
	ack  *Ack
}

func optOuts(in *InsecureOptOuts) []optOut {
	out := []optOut{
		{"NoOriginCheck", in.NoOriginCheck != nil, in.NoOriginCheck},
		{"NoRateLimit", in.NoRateLimit != nil, in.NoRateLimit},
		{"NoReauthWindow", in.NoReauthWindow != nil, in.NoReauthWindow},
		{"LongSessions", in.LongSessions != nil, in.LongSessions},
		{"EphemeralState", in.EphemeralState != nil, in.EphemeralState},
	}
	if s := in.SharedCookieDomain; s != nil {
		out = append(out, optOut{"SharedCookieDomain", true, s.Ack})
	}
	for _, a := range []struct {
		name string
		a    *OutboundAllowance
	}{{"OutboundPrivateNetwork", in.OutboundPrivateNetwork}, {"TenantOutboundPrivateNetwork", in.TenantOutboundPrivateNetwork}} {
		if a.a != nil {
			out = append(out, optOut{a.name, true, a.a.Ack})
		}
	}
	return out
}

func checkInsecure[C any](cfg *Config[C], v *problems) {
	in := &cfg.Insecure
	public := !loopbackOnly(cfg)
	for _, o := range optOuts(in) {
		if !o.set {
			continue
		}
		field := "Insecure." + o.name
		if o.name == "SharedCookieDomain" || strings.HasSuffix(o.name, "PrivateNetwork") {
			field += ".Ack"
		}
		switch {
		case !o.ack.valid():
			v.add(field, "needs Acknowledge with a non-empty reason")
		case o.ack.development && public:
			v.add(field, "carries the egauthtest development acknowledgement, refused once an origin or audience is not loopback; acknowledge it with your own reason")
		}
	}
	for _, a := range []struct {
		field string
		a     *OutboundAllowance
	}{{"Insecure.OutboundPrivateNetwork", in.OutboundPrivateNetwork}, {"Insecure.TenantOutboundPrivateNetwork", in.TenantOutboundPrivateNetwork}} {
		if a.a == nil {
			continue
		}
		if len(a.a.Prefixes) == 0 {
			v.add(a.field+".Prefixes", "is empty")
			continue
		}
		if _, err := outbound.NewAllowance(a.a.Prefixes); err != nil {
			v.add(a.field+".Prefixes", err.Error())
		}
	}
}

func providerPredicate(x any) error {
	p, ok := x.(federation.Provider)
	if !ok {
		return errors.New("is not a federation.Provider")
	}
	return p.Validate()
}
