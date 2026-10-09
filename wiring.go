package egauth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/clientaddr"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/codesvc"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/externalsvc"
	"github.com/JLugagne/egauth/internal/federationsvc"
	"github.com/JLugagne/egauth/internal/flow"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/issuance"
	"github.com/JLugagne/egauth/internal/keys"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/internal/mfasvc"
	"github.com/JLugagne/egauth/internal/outbound"
	"github.com/JLugagne/egauth/internal/passkeysvc"
	"github.com/JLugagne/egauth/internal/reap"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/internal/session/endpoints"
	"github.com/JLugagne/egauth/internal/session/jwt"
	"github.com/JLugagne/egauth/internal/session/stateful"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/policy"
)

var startupTimeout = StartupTimeout

type owned struct {
	seams       seams
	clock       clock.Clock
	events      event.Sink
	audit       httpx.Audit
	dataKey     []byte
	instance    uuid.UUID
	cookies     cookie.Policy
	clients     *clientaddr.Resolver
	trusted     csrf.Origins
	origins     origins
	outbound    *outbound.Clients
	limiter     *scaledLimiter
	epochs      *revoke.Epochs
	families    *revoke.Families
	keys        *keys.Manager
	codec       *jwt.Codec
	renewer     *session.Renewer
	backend     session.Backend
	enrollment  *issuance.Enrollment
	identity    *identitysvc.Service
	accounts    *identitysvc.Accounts
	issuer      *issuance.Issuer
	flow        *flow.Service
	mfa         *mfasvc.Service
	passkeys    *passkeysvc.Service
	codes       *codesvc.Service
	federation  *federationsvc.Service
	external    *externalsvc.Service
	dispatcher  *lifecycle.Dispatcher
	reaper      *reap.Reaper
	preamble    *httpx.Preamble
	table       routes.Table
	env         httpx.Env
	fingerprint string
	instances   atomic.Int32
	beat        *heartbeat
	pollers     []follower
	sharedLimit bool
	scaleLimit  bool
	closers     []func() error
}

type follower interface {
	Start()
	Stop()
	Poll(ctx context.Context) error
	Ready() error
}

type builder[C any] struct {
	ctx      context.Context
	cfg      *Config[C]
	pol      *policies
	o        *owned
	errs     *problems
	outbox   *lateOutbox
	pendings *latePendings
}

func (b *builder[C]) fail(field string, err error) {
	b.errs.add(field, err.Error())
}

func (b *builder[C]) onClose(f func() error) {
	b.o.closers = append(b.o.closers, f)
}

func (o *owned) closeAll() error {
	var errs []error
	for _, f := range slices.Backward(o.closers) {
		errs = append(errs, f())
	}
	o.closers = nil
	return errors.Join(errs...)
}

type authority struct {
	accounts   *identitysvc.Service
	enrollment *issuance.Enrollment
}

func (a authority) AccountState(ctx context.Context, s core.Subject) (core.AccountState, error) {
	return a.accounts.AccountState(ctx, s)
}

func (a authority) MFADecision(ctx context.Context, s core.Subject) (core.MFADecision, error) {
	return a.enrollment.MFADecision(ctx, s)
}

func assemble[C any](ctx context.Context, cfg *Config[C], pol *policies, o *owned, errs *problems) {
	b := &builder[C]{ctx: ctx, cfg: cfg, pol: pol, o: o, errs: errs, outbox: &lateOutbox{}, pendings: &latePendings{}}
	for _, stage := range []func(){b.base, b.sessions, b.services, b.lifecycle, b.routes} {
		stage()
		if len(errs.errs) > 0 {
			return
		}
	}
}

func (b *builder[C]) base() {
	cfg, o := b.cfg, b.o
	o.clock = o.seams.clock
	o.events = cfg.Events
	o.audit = httpx.SinkAudit(cfg.Events)
	o.cookies, o.clients, o.trusted, o.origins = b.pol.cookies, b.pol.clients, b.pol.trusted, b.pol.origins
	oc := b.pol.outbound
	oc.RootCAs = o.seams.rootCAs
	o.outbound = outbound.New(oc)
	o.fingerprint = b.pol.fingerprint
	epochs, err := revoke.NewEpochs(cfg.Storage.Identity, revoke.Config{Clock: o.clock, Events: o.events})
	if err != nil {
		b.fail("Storage.Identity", err)
		return
	}
	o.epochs = epochs
	o.pollers = append(o.pollers, epochs)
	o.limiter = &scaledLimiter{inner: cfg.RateLimit}
	o.limiter.setInstances(1)
	var pwPolicy passwords.Policy = policy.NewPassphrasePolicy()
	var breach passwords.BreachChecker
	open := false
	if pw := cfg.Modules.Password; pw != nil {
		pwPolicy, breach, open = pw.Policy, pw.Breach, pw.Registration == RegistrationOpen
	}
	svc, err := identitysvc.New(identitysvc.Config{
		Identity: cfg.Storage.Identity, Ceremonies: cfg.Storage.Ceremonies, MFA: cfg.Storage.MFA, Passkeys: cfg.Storage.Passkeys,
		Hasher: argon2.NewHasher(), Policy: pwPolicy, Breach: breach, Outbound: o.outbound.Static(),
		Mailer: emailAdapter{d: cfg.Email, audit: o.audit}, Links: links{origins: o.origins, pages: cfg.Pages},
		Cookies: o.cookies, DataKey: o.dataKey, OpenRegistration: open, LoginPage: b.pol.loginPage, NoPasswordReset: cfg.Modules.Password == nil,
		Dispatcher: b.outbox, Clock: o.clock, Audit: o.audit,
	})
	if err != nil {
		b.fail("Modules.Password", err)
		return
	}
	o.identity = svc
	b.onClose(svc.Close)
	if o.enrollment, err = issuance.NewEnrollment(cfg.Storage.MFA, cfg.Storage.Passkeys); err != nil {
		b.fail("Storage.MFA", err)
	}
}

func (b *builder[C]) sessions() {
	cfg, o := b.cfg, b.o
	life := session.Lifetimes{IdleTimeout: cfg.Policy.IdleTimeout, MaxLifetime: cfg.Policy.MaxLifetime, RecheckEvery: cfg.Policy.RecheckEvery}
	renewer, err := session.NewRenewer(session.RenewConfig{
		Authority: authority{accounts: o.identity, enrollment: o.enrollment}, Claims: claimsAdapter[C]{src: cfg.Claims},
		Lifetimes: life, Clock: o.clock, Events: o.events,
	})
	if err != nil {
		b.fail("Policy", err)
		return
	}
	o.renewer = renewer
	spec, ks := backendOf(cfg.Sessions)
	if spec.kind == backendStateful {
		be, err := stateful.New(stateful.Config{
			Sessions: cfg.Storage.Sessions, Epochs: o.epochs, Renewer: renewer, Cookies: o.cookies, Clock: o.clock, Events: o.events,
		})
		if err != nil {
			b.fail("Sessions", err)
			return
		}
		o.backend = be
		return
	}
	mgr, err := b.keyManager(ks)
	if err != nil {
		b.fail("Sessions", err)
		return
	}
	o.keys = mgr
	o.pollers = append(o.pollers, mgr)
	codec, err := jwt.NewCodec(jwt.CodecConfig{
		PublicOrigin: cfg.PublicOrigin, ClaimsFingerprint: o.fingerprint, RecheckEvery: life.RecheckEvery, Clock: o.clock,
	})
	if err != nil {
		b.fail("Sessions", err)
		return
	}
	families, err := revoke.NewFamilies(cfg.Storage.Tokens, revoke.Config{Clock: o.clock, Events: o.events})
	if err != nil {
		b.fail("Storage.Tokens", err)
		return
	}
	o.codec, o.families = codec, families
	o.pollers = append(o.pollers, families)
	be, err := jwt.New(jwt.Config{
		Codec: codec, Keys: mgr, Tokens: cfg.Storage.Tokens, Families: families, Epochs: o.epochs, Renewer: renewer,
		Cookies: o.cookies, Audiences: cfg.Audiences, Clock: o.clock, Events: o.events,
	})
	if err != nil {
		b.fail("Sessions", err)
		return
	}
	o.backend = be
}

func (b *builder[C]) keyManager(ks keySpec) (*keys.Manager, error) {
	if ks.kind == keysStatic {
		return keys.NewStatic(ks.active, ks.verifyOnly...)
	}
	return keys.NewTenant(keys.TenantConfig{Store: b.cfg.Storage.Keys, KEK: b.cfg.KEK, Clock: b.o.clock, Events: b.o.events})
}

func (b *builder[C]) services() {
	b.factorServices()
	if len(b.errs.errs) > 0 {
		return
	}
	b.admission()
	if len(b.errs.errs) > 0 {
		return
	}
	b.accountServices()
	b.primaryServices()
}

func (b *builder[C]) factorServices() {
	cfg, o := b.cfg, b.o
	if m := cfg.Modules.MFA; m != nil {
		svc, err := mfasvc.New(mfasvc.Config{
			MFA: cfg.Storage.MFA, Passkeys: cfg.Storage.Passkeys, Identity: cfg.Storage.Identity, Mutations: o.identity,
			KEK: cfg.KEK, TOTPIssuer: m.TOTPIssuer, Clock: o.clock, Audit: o.audit,
		})
		if err != nil {
			b.fail("Modules.MFA", err)
			return
		}
		o.mfa = svc
	}
	if m := cfg.Modules.Passkey; m != nil {
		svc, err := passkeysvc.New(passkeysvc.Config{
			Passkeys: cfg.Storage.Passkeys, MFA: cfg.Storage.MFA, Identity: cfg.Storage.Identity, Accounts: o.identity,
			Mutations: o.identity, Ceremonies: cfg.Storage.Ceremonies, Origins: o.trusted, Cookies: o.cookies,
			DisplayName: m.DisplayName, DataKey: o.dataKey, Clock: o.clock, Audit: o.audit,
		})
		if err != nil {
			b.fail("Modules.Passkey", err)
			return
		}
		o.passkeys = svc
	}
}

func (b *builder[C]) admission() {
	cfg, o := b.cfg, b.o
	fc := flow.Config{Flows: cfg.Storage.Ceremonies, Cookies: o.cookies, Clock: o.clock, Audit: o.audit}
	if o.mfa != nil {
		fc.SecondFactors = o.mfa
	}
	if o.passkeys != nil {
		fc.StepUp = o.passkeys
	}
	if cfg.Modules.Password != nil {
		fc.Passwords = o.identity
	}
	fl, err := flow.New(fc)
	if err != nil {
		b.fail("Modules", err)
		return
	}
	o.flow = fl
	issuer, err := issuance.New(issuance.Config{
		Accounts: o.identity, Enrollment: o.enrollment, Backend: o.backend, Claims: o.renewer, Flows: cfg.Storage.Ceremonies,
		Completer: fl, Cookies: o.cookies, Origins: o.origins, RememberMe: cfg.Policy.Remember, Pages: b.pol.pages,
		Clock: o.clock, Audit: o.audit,
	})
	if err != nil {
		b.fail("Pages", err)
		return
	}
	o.issuer = issuer
	b.pendings.target.Store(issuer)
}

func (b *builder[C]) accountServices() {
	cfg, o := b.cfg, b.o
	ac := identitysvc.AccountsConfig{Mailer: emailAdapter{d: cfg.Email, audit: o.audit}, Pendings: b.pendings, SelfDelete: cfg.Modules.SelfDelete != nil}
	if v := cfg.Modules.Verification; v != nil {
		ac.Email, ac.Phone, ac.RecoveryEmail = v.Email, v.Phone, v.RecoveryEmail
	}
	if ac.Phone {
		sealer, err := ceremonycodec.NewSealer(o.dataKey, o.clock)
		if err != nil {
			b.fail("Modules.Verification.Phone", err)
			return
		}
		ac.Sealer, ac.Texter = sealer, smsAdapter{d: cfg.SMS}
	}
	accounts, err := identitysvc.NewAccounts(o.identity, ac)
	if err != nil {
		b.fail("Modules.Verification", err)
		return
	}
	o.accounts = accounts
}

func (b *builder[C]) primaryServices() {
	b.codeService()
	if len(b.errs.errs) > 0 {
		return
	}
	b.federationServices()
}

func (b *builder[C]) codeService() {
	cfg, o := b.cfg, b.o
	magic, lc := cfg.Modules.MagicLink != nil, cfg.Modules.LoginCode
	if !magic && lc == nil {
		return
	}
	cc := codesvc.Config{
		Identity: cfg.Storage.Identity, Accounts: o.identity, Ceremonies: cfg.Storage.Ceremonies,
		Links: links{origins: o.origins, pages: cfg.Pages}, Cookies: o.cookies, DataKey: o.dataKey, MagicLink: magic,
		Clock: o.clock, Audit: o.audit,
	}
	if magic || (lc != nil && lc.Email) {
		cc.Mailer = emailAdapter{d: cfg.Email, audit: o.audit}
	}
	if lc != nil {
		cc.EmailCodes = lc.Email
		if cc.SMSCodes = lc.SMS; lc.SMS {
			cc.Texter = smsAdapter{d: cfg.SMS}
		}
	}
	svc, err := codesvc.New(cc)
	if err != nil {
		b.fail("Modules.LoginCode", err)
		return
	}
	o.codes = svc
	b.onClose(svc.Close)
}

func (b *builder[C]) registration() federationsvc.Registration {
	if pw := b.cfg.Modules.Password; pw != nil && pw.Registration == RegistrationInviteOnly {
		return federationsvc.RegistrationInviteOnly
	}
	return federationsvc.RegistrationOpen
}

func (b *builder[C]) federationServices() {
	cfg, o := b.cfg, b.o
	if m := cfg.Modules.OAuth; m != nil {
		svc, err := federationsvc.New(b.ctx, federationsvc.Config{
			Providers: m.Providers, PerTenant: m.PerTenant, Federation: cfg.Storage.Federation, Users: cfg.Storage.Identity,
			Accounts: o.identity, Ceremonies: cfg.Storage.Ceremonies, KEK: cfg.KEK, Outbound: o.outbound, Origins: o.origins,
			BasePath: cfg.BasePath, Cookies: o.cookies, DataKey: o.dataKey, Registration: b.registration(), Clock: o.clock, Audit: o.audit,
		})
		if err != nil {
			b.fail("Modules.OAuth", err)
			return
		}
		o.federation = svc
	}
	if m := cfg.Modules.External; m != nil {
		dir, err := federationsvc.NewDirectory(federationsvc.DirectoryConfig{
			Users: cfg.Storage.Identity, Links: cfg.Storage.Federation, Accounts: o.identity, Registration: b.registration(), Audit: o.audit,
		})
		if err != nil {
			b.fail("Modules.External", err)
			return
		}
		vs := make([]externalsvc.Verifier, 0, len(m.Verifiers))
		for _, f := range m.Verifiers {
			vs = append(vs, externalVerifier{f: f})
		}
		svc, err := externalsvc.New(externalsvc.Config{Verifiers: vs, Directory: dir, Clock: o.clock, Audit: o.audit})
		if err != nil {
			b.fail("Modules.External", err)
			return
		}
		o.external = svc
	}
}

func (b *builder[C]) lifecycle() {
	cfg, o := b.cfg, b.o
	st := &cfg.Storage
	var w lifecycle.Wiring
	var errs []error
	keep := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	var err error
	w.Sessions, err = lifecycle.NewSessions(o.backend)
	keep(err)
	w.APIKeys = lifecycle.AbsentAPIKeys()
	if present(st.Tokens) {
		w.APIKeys, err = lifecycle.NewAPIKeys(st.Tokens)
		keep(err)
	}
	w.Ceremonies, err = lifecycle.NewCeremonies(st.Ceremonies, st.Identity, o.accounts)
	keep(err)
	w.MFA, err = lifecycle.NewMFA(st.MFA)
	keep(err)
	w.Passkeys, err = lifecycle.NewPasskeys(st.Passkeys)
	keep(err)
	w.Federation = lifecycle.AbsentFederation()
	if present(st.Federation) {
		w.Federation, err = lifecycle.NewFederation(st.Federation)
		keep(err)
	}
	w.Notices, err = lifecycle.NewNotices(o.accounts)
	keep(err)
	w.Keys = lifecycle.AbsentKeys()
	if present(st.Keys) {
		w.Keys, err = lifecycle.NewKeys(st.Keys)
		keep(err)
	}
	w.Hooks = lifecycle.NewHooks(lifecycle.AccountDeletedHook(cfg.Hooks.AccountDeleted), lifecycle.TenantErasedHook(cfg.Hooks.TenantErased))
	w.Identity, err = lifecycle.NewIdentity(st.Identity)
	keep(err)
	if len(errs) > 0 {
		b.fail("Storage", errors.Join(errs...))
		return
	}
	d, err := lifecycle.NewDispatcher(lifecycle.Config{Outbox: st.Identity, Wiring: w, Reporter: reap.RetryEvents(o.events), Clock: o.clock})
	if err != nil {
		b.fail("Storage", err)
		return
	}
	o.dispatcher = d
	b.outbox.target.Store(d)
	rp, err := reap.New(reap.Config{Stores: b.reapable(), Outbox: d, Clock: o.clock, Events: o.events})
	if err != nil {
		b.fail("Storage", err)
		return
	}
	o.reaper = rp
}

func (b *builder[C]) reapable() []reap.Store {
	cfg := b.cfg
	st := &cfg.Storage
	out := []reap.Store{{Name: "identity", Reaper: st.Identity}, {Name: "ceremonies", Reaper: st.Ceremonies}, {Name: "deployment", Reaper: st.Deployment}}
	if present(st.Tokens) {
		out = append(out, reap.Store{Name: "tokens", Reaper: st.Tokens})
	}
	if present(st.Sessions) {
		out = append(out, reap.Store{Name: "sessions", Reaper: st.Sessions})
	}
	if present(st.Keys) {
		out = append(out, reap.Store{Name: "keys", Reaper: st.Keys})
	}
	if present(st.Limiter) {
		out = append(out, reap.Store{Name: "limiter", Reaper: st.Limiter})
	}
	if present(cfg.RateLimit) && !b.o.sharedLimit {
		out = append(out, reap.Store{Name: "rate_limit", Reaper: cfg.RateLimit})
	}
	return out
}

func (b *builder[C]) endpoints() ([]routes.Endpoint, error) {
	cfg, o := b.cfg, b.o
	var all []routes.Endpoint
	var errs []error
	add := func(eps []routes.Endpoint, err error) {
		all = append(all, eps...)
		errs = append(errs, err)
	}
	add(endpoints.Endpoints(endpoints.Config{Backend: o.backend, Audit: o.audit}))
	if cfg.Modules.Password != nil {
		add(o.identity.Endpoints(o.issuer))
	}
	add(o.accounts.Endpoints(o.issuer))
	add(o.flow.Endpoints(o.issuer))
	if o.mfa != nil {
		add(o.mfa.Endpoints(o.issuer))
	}
	if o.passkeys != nil {
		add(o.passkeys.Endpoints(o.issuer))
	}
	if o.codes != nil {
		add(o.codes.Endpoints(o.issuer))
	}
	if o.federation != nil {
		add(o.federation.Endpoints(o.issuer))
	}
	if o.external != nil {
		add(o.external.Endpoints(o.issuer))
	}
	return all, errors.Join(errs...)
}

func (b *builder[C]) routes() {
	cfg, o := b.cfg, b.o
	eps, err := b.endpoints()
	if err != nil {
		b.fail("Modules", err)
		return
	}
	table, err := routes.NewTable(eps...)
	if err != nil {
		b.fail("Modules", err)
		return
	}
	env := httpx.Env{
		Tenants: b.pol.tenants, Limiter: o.limiter, Authenticator: o.backend, Issuer: o.issuer, Identifiers: identifiers{},
		Enrollment: o.enrollment, BeforeEndpoint: endpointHook{hook: cfg.Hooks.BeforeEndpoint, poke: o.reaper.Poke},
		Clock: o.clock, Audit: o.audit,
	}
	if err := env.Validate(); err != nil {
		b.fail("Modules", err)
		return
	}
	in := &cfg.Insecure
	pre, err := httpx.NewPreamble(env, httpx.Settings{
		Clients: o.clients, Origins: o.trusted, Transports: b.pol.transports, ReauthWindow: cfg.Policy.ReauthWindow,
		Insecure: httpx.Insecure{NoOriginCheck: in.NoOriginCheck != nil, NoRateLimit: in.NoRateLimit != nil, NoReauthWindow: in.NoReauthWindow != nil},
	})
	if err != nil {
		b.fail("Policy", err)
		return
	}
	if err := mountProbe(http.NewServeMux(), table, cfg.BasePath, pre); err != nil {
		b.fail("BasePath", err)
		return
	}
	o.env, o.preamble, o.table = env, pre, table
}

func mountProbe(mux *http.ServeMux, table routes.Table, basePath string, pre *httpx.Preamble) error {
	return table.Mount(mux, basePath, pre)
}
