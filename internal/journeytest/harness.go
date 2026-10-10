// Package journeytest is the behavioural guard of egauth (DESIGN section 9.4): a fully enabled Auth
// on in-memory storage, an HTTP client with a cookie jar, an event recorder, the G22 probe battery
// and the entry point examples use to run the same probes against their own server.
package journeytest

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/journeytest/testdata"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/memstore"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/keys"
	"github.com/JLugagne/egauth/store/mfa"
)

// Fixed identities and routes of every World.
const (
	TenantName    = "acme"
	OtherTenant   = "globex"
	BaseDomain    = "example.com"
	Password      = "correct horse battery staple"
	AdminRole     = "admin"
	ProviderName  = "idp"
	ExternalName  = "directory"
	APIKeyKind    = "service"
	AudienceOne   = "https://resources.example.test"
	AudienceTwo   = "https://other-resources.example.test"
	ProtectRoute  = "/app/profile"
	OptionalRoute = "/app/home"
	APIRoute      = "/api/report"
	PublicRoute   = "/public/health"
	MFARoute      = "/app/mfa-only"
	FreshRoute    = "/app/fresh"
	AdminRoute    = "/app/admin"
)

// Backend selects the session backend of a World.
type Backend uint8

// Session backends a World can run.
const (
	JWT Backend = iota + 1
	Stateful
)

func (b Backend) String() string {
	if b == Stateful {
		return "stateful"
	}
	return "jwt"
}

// Claims is the custom claims type of every World.
type Claims struct {
	Plan string `json:"plan"`
}

// Settings are the knobs of NewWorld. The zero Settings is the fully enabled golden configuration:
// the JWT backend, CookiesAndBearer and subdomain tenancy. Serve serves the Auth on a loopback TLS
// server under single tenancy and without the Passkey module (a relying party id cannot be an IP
// address), so that a ResourceServer can fetch its discovery document and keys over the network.
type Settings struct {
	Backend   Backend
	Transport egauth.Transport
	Tenancy   Tenancy
	Mutate    func(*egauth.Config[Claims])
	Serve     bool
	// LoopbackIdP lets the Auth reach the fake identity provider, which listens on loopback: the
	// outbound SSRF guard refuses it otherwise and every OAuth callback ends in 502
	// provider_unavailable. It sets Insecure.OutboundPrivateNetwork, so a World with it is not the
	// golden configuration and its Posture lists the opt-out; OAuth journeys that must complete use
	// it. The G22 battery derives such a World only for the probes that need a completed callback,
	// never as the configuration it reports on.
	LoopbackIdP bool
}

// Configure returns s with f chained after the mutations it already carries; it is how a variant is
// expressed, since the zero Settings is the golden configuration.
func (s Settings) Configure(f func(*egauth.Config[Claims])) Settings {
	prev := s.Mutate
	s.Mutate = func(c *egauth.Config[Claims]) {
		if prev != nil {
			prev(c)
		}
		f(c)
	}
	return s
}

// Tenancy selects how a World resolves tenants.
type Tenancy uint8

// Tenancies a World can run.
const (
	Subdomain Tenancy = iota + 1
	Single
	FromRequest
)

// Recorder is the event.Sink of a World; it keeps every event in emission order.
type Recorder struct {
	mu     sync.Mutex
	events []event.Event
}

// EmitEvent records e.
func (r *Recorder) EmitEvent(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// All returns a copy of the recorded events.
func (r *Recorder) All() []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]event.Event(nil), r.events...)
}

// Types returns the recorded event types in order.
func (r *Recorder) Types() []event.Type {
	var out []event.Type
	for _, e := range r.All() {
		out = append(out, e.Type)
	}
	return out
}

// Of returns the recorded events of type t.
func (r *Recorder) Of(t event.Type) []event.Event {
	var out []event.Event
	for _, e := range r.All() {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

// Mark returns the number of events recorded so far, for Since.
func (r *Recorder) Mark() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// Since returns the types recorded after mark.
func (r *Recorder) Since(mark int) []event.Type {
	all := r.Types()
	if mark > len(all) {
		return nil
	}
	return all[mark:]
}

// SMSBox is the SMSDeliverer of a World; it records every text.
type SMSBox struct {
	mu   sync.Mutex
	sent []Text
}

// Text is one captured text message.
type Text struct {
	Kind string
	Code string
}

var _ egauth.SMSDeliverer = (*SMSBox)(nil)

func (s *SMSBox) put(kind string, c egauth.CodeMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, Text{Kind: kind, Code: c.Code})
	return nil
}

func (s *SMSBox) LoginCode(_ context.Context, m egauth.CodeMessage) error {
	return s.put("LoginCode", m)
}

func (s *SMSBox) PhoneVerificationCode(_ context.Context, m egauth.CodeMessage) error {
	return s.put("PhoneVerificationCode", m)
}

func (s *SMSBox) PasswordResetCode(_ context.Context, m egauth.CodeMessage) error {
	return s.put("PasswordResetCode", m)
}

func (s *SMSBox) SecurityNotice(context.Context, egauth.SecurityNoticeMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, Text{Kind: "SecurityNotice"})
	return nil
}

// Messages returns a copy of the captured texts.
func (s *SMSBox) Messages() []Text {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Text(nil), s.sent...)
}

type claimsSource struct {
	mu sync.Mutex
	by map[principal.Subject]egauth.AppClaims[Claims]
}

func (c *claimsSource) ClaimsFor(_ context.Context, s principal.Subject) (egauth.AppClaims[Claims], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.by[s]; ok {
		return v, nil
	}
	return egauth.AppClaims[Claims]{Roles: []string{"user"}, Scopes: []string{"items:read"}, Custom: Claims{Plan: "pro"}}, nil
}

func (c *claimsSource) set(s principal.Subject, v egauth.AppClaims[Claims]) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.by == nil {
		c.by = map[principal.Subject]egauth.AppClaims[Claims]{}
	}
	c.by[s] = v
}

type directory struct{}

func (directory) Name() string { return ExternalName }

func (directory) Verify(_ context.Context, r egauth.ExternalRequest) (egauth.ExternalIdentity, error) {
	if r.Secret != Password {
		return egauth.ExternalIdentity{}, errors.New("journeytest: external secret refused")
	}
	return egauth.ExternalIdentity{ExternalID: "ext-" + r.Identifier, Email: r.Identifier, EmailVerified: true}, nil
}

// Seen records the principals the declared routes of a World served.
type Seen struct {
	mu sync.Mutex
	p  []egauth.Principal[Claims]
}

func (s *Seen) record(p egauth.Principal[Claims]) {
	s.mu.Lock()
	s.p = append(s.p, p)
	s.mu.Unlock()
}

func (s *Seen) handler(w http.ResponseWriter, _ *http.Request, p egauth.Principal[Claims]) {
	s.record(p)
	w.WriteHeader(http.StatusOK)
}

// Count returns how many requests reached a declared handler.
func (s *Seen) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.p)
}

// Last returns the principal of the last request a declared handler served.
func (s *Seen) Last() (egauth.Principal[Claims], bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.p) == 0 {
		return egauth.Principal[Claims]{}, false
	}
	return s.p[len(s.p)-1], true
}

// World is a fully enabled Auth on memstore with its fixtures: the manual clock, the fake provider,
// the captured mail and texts, the recorded events and the handler of every declared route.
type World struct {
	T        testing.TB
	Settings Settings
	Clock    *egauthtest.Clock
	Storage  egauth.Storage
	KEK      kek.KEK
	Mailbox  *egauthtest.Mailbox
	SMS      *SMSBox
	IdP      *egauthtest.IdP
	Events   *Recorder
	Auth     *egauth.Auth[Claims]
	Handler  http.Handler
	Config   egauth.Config[Claims]
	Seen     *Seen
	Server   *httptest.Server
	Tenant   principal.TenantID
	Host     string
	Origin   string
	claims   *claimsSource
	nextAddr uint32
	mem      *memServer
	declared []routeDecl
}

// NewWorld builds a World and fails t when New or Build refuses the configuration.
func NewWorld(t testing.TB, s Settings) *World {
	t.Helper()
	w, err := BuildWorld(t, s)
	if err != nil {
		t.Fatalf("journeytest: building the world: %v", err)
	}
	return w
}

// BuildWorld builds a World and returns the error New or Build reported, so that a variant the
// library rejects can be told from one it accepts. The Auth is closed when t ends.
func BuildWorld(t testing.TB, s Settings) (*World, error) {
	t.Helper()
	if s.Backend == 0 {
		s.Backend = JWT
	}
	if s.Transport == 0 {
		s.Transport = egauth.CookiesAndBearer
	}
	if s.Tenancy == 0 || s.Serve {
		s.Tenancy = Subdomain
		if s.Serve {
			s.Tenancy = Single
		}
	}
	clk := egauthtest.NewClock(time.Time{})
	sum := sha256.Sum256([]byte("journeytest kek, public and worthless"))
	k, err := kek.NewLocal(sum[:])
	if err != nil {
		return nil, errors.Join(errors.New("journeytest: kek"), err)
	}
	w := &World{
		T: t, Settings: s, Clock: clk, KEK: k, Storage: SharedStorage(memstore.NewWithClock(k, clk.Library())),
		Mailbox: &egauthtest.Mailbox{}, SMS: &SMSBox{}, Events: &Recorder{}, Seen: &Seen{}, claims: &claimsSource{},
		IdP: egauthtest.NewIdP(t, clk),
	}
	w.Origin, w.Host = "https://"+BaseDomain, BaseDomain
	var swap *swapHandler
	if s.Serve {
		swap = &swapHandler{}
		w.Server = httptest.NewTLSServer(swap)
		t.Cleanup(w.Server.Close)
		w.Origin, w.Host = w.Server.URL, strings.TrimPrefix(w.Server.URL, "https://")
	}
	switch s.Tenancy {
	case Subdomain:
		w.Origin, w.Host = "https://"+TenantName+"."+BaseDomain, TenantName+"."+BaseDomain
		w.Tenant, _ = principal.ParseTenantID(TenantName)
	case FromRequest:
		w.Tenant, _ = principal.ParseTenantID(TenantName)
	}
	cfg, err := w.config()
	if err != nil {
		return nil, err
	}
	if s.Serve {
		cfg.Modules.Passkey = nil
	}
	if s.LoopbackIdP {
		cfg.Insecure.OutboundPrivateNetwork = &egauth.OutboundAllowance{
			Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
			Ack:      egauth.Acknowledge("journeytest: the fake identity provider listens on loopback"),
		}
	}
	if s.Mutate != nil {
		s.Mutate(&cfg)
	}
	w.Config = cfg
	a, err := egauthtest.New(cfg, clk, w.IdP)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = a.Close() })
	w.Auth = a
	if err := w.provisionTenantKeys(); err != nil {
		return nil, err
	}
	w.declared = w.routeTable()
	rt := w.applyRoutes(a.Routes())
	h, err := rt.Build()
	if err != nil {
		return nil, err
	}
	w.Handler = h
	if swap != nil {
		swap.set(h)
	}
	return w, nil
}

func (w *World) config() (egauth.Config[Claims], error) {
	s := w.Settings
	sum := sha256.Sum256([]byte("journeytest signer"))
	signer, err := signing.EdDSA("jt-1", sum[:])
	if err != nil {
		return egauth.Config[Claims]{}, errors.Join(errors.New("journeytest: signer"), err)
	}
	sessions := egauth.SessionBackend(egauth.Stateful())
	if s.Backend == JWT {
		sessions = egauth.JWT(egauth.StaticKeys(signer))
	}
	tenancy := egauth.SingleTenant()
	origin := w.Origin
	switch s.Tenancy {
	case Subdomain:
		tenancy = egauth.TenantBySubdomain()
		origin = "https://{tenant}." + BaseDomain
	case FromRequest:
		tenancy = egauth.TenantFromRequest(ConstantTenant{Tenant: w.Tenant})
	}
	cfg := testdata.ProdConfig(testdata.Deps[Claims]{
		Origin:    origin,
		Tenancy:   tenancy,
		Sessions:  sessions,
		Transport: s.Transport,
		Audiences: audiences(s),
		Storage:   w.Storage,
		KEK:       w.KEK,
		Claims:    w.claims,
		Events:    w.Events,
		Email:     w.Mailbox,
		SMS:       w.SMS,
		Providers: []federation.Provider{w.IdP.Provider(ProviderName)},
		Verifiers: []egauth.ExternalFactor{directory{}},
		AdminRole: AdminRole,
		APIKinds:  []string{APIKeyKind, "pat"},
		Hooks: egauth.Hooks{
			AccountDeleted: func(context.Context, uuid.UUID, principal.Subject) error { return nil },
			TenantErased:   func(context.Context, uuid.UUID, principal.TenantID) error { return nil },
		},
	})
	return cfg, nil
}

// SeedUser creates a verified password account directly in storage and returns its subject.
func (w *World) SeedUser(email string, mustChange bool) principal.Subject {
	w.T.Helper()
	ctx := context.Background()
	phc, err := argon2.NewHasher().Hash(ctx, Password)
	if err != nil {
		w.T.Fatalf("journeytest: hashing: %v", err)
	}
	id, err := identity.NewIdentifier(identity.IdentifierEmail, email)
	if err != nil {
		w.T.Fatalf("journeytest: identifier: %v", err)
	}
	applied, err := w.Storage.Identity.Apply(ctx, identity.CreateVerified{
		Tenant: w.Tenant, Email: id, PHC: identity.NewPasswordHash(phc), MustChange: mustChange,
	})
	if err != nil {
		w.T.Fatalf("journeytest: creating %s: %v", email, err)
	}
	return applied.Subject
}

// Grant replaces the claims the ClaimsSource answers for s from the next admission or renewal.
func (w *World) Grant(s principal.Subject, roles, scopes []string) {
	w.claims.set(s, egauth.AppClaims[Claims]{Roles: roles, Scopes: scopes, Custom: Claims{Plan: "pro"}})
}

// EnrollTOTP stores a confirmed TOTP enrollment for s without going through the endpoints.
func (w *World) EnrollTOTP(s principal.Subject) {
	w.T.Helper()
	ctx := context.Background()
	now := w.Clock.Now()
	e := mfa.Enrollment{Subject: s, Sealed: []byte("sealed-secret"), AADVersion: mfa.AADVersionCurrent, CreatedAt: now}
	if err := w.Storage.MFA.SaveTOTP(ctx, e); err != nil {
		w.T.Fatalf("journeytest: saving TOTP: %v", err)
	}
	e.ConfirmedAt = &now
	if err := w.Storage.MFA.ConfirmEnrollment(ctx, e, []string{"code-hash"}); err != nil {
		w.T.Fatalf("journeytest: confirming TOTP: %v", err)
	}
}

// SetDisabled disables or re-enables s in storage.
func (w *World) SetDisabled(s principal.Subject, disabled bool) {
	w.T.Helper()
	if _, err := w.Storage.Identity.Apply(context.Background(), identity.SetDisabledState{Subject: s, Disable: disabled}); err != nil {
		w.T.Fatalf("journeytest: setting disabled state: %v", err)
	}
}

// FreshEmail returns an address no earlier call returned.
func (w *World) FreshEmail(local string) string {
	return local + "-" + uuid.NewString()[:8] + "@mail.test"
}

func audiences(s Settings) []string {
	if s.Backend == Stateful {
		return nil
	}
	return []string{AudienceOne, AudienceTwo}
}

// Derive builds another World with this one's settings changed by change, so that a probe needing a different
// deployment shape (a trusted proxy, another transport) still probes the configuration under test.
func (w *World) Derive(change func(*Settings)) (*World, error) {
	s := w.Settings
	change(&s)
	return BuildWorld(w.T, s)
}

type swapHandler struct {
	mu sync.Mutex
	h  http.Handler
}

func (s *swapHandler) set(h http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.h = h
}

func (s *swapHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	h := s.h
	s.mu.Unlock()
	if h == nil {
		http.NotFound(w, r)
		return
	}
	h.ServeHTTP(w, r)
}

// ConstantTenant is the TenantResolver that answers Tenant for every request.
type ConstantTenant struct{ Tenant principal.TenantID }

// ResolveTenant returns the constant tenant.
func (c ConstantTenant) ResolveTenant(*http.Request) (principal.TenantID, error) {
	return c.Tenant, nil
}

// ReauthWindow is the effective SessionPolicy.ReauthWindow of the configuration under test.
func (w *World) ReauthWindow() time.Duration {
	if d := w.Config.Policy.ReauthWindow; d > 0 {
		return d
	}
	return 10 * time.Minute
}

// RecheckEvery is the effective SessionPolicy.RecheckEvery of the configuration under test.
func (w *World) RecheckEvery() time.Duration {
	if d := w.Config.Policy.RecheckEvery; d > 0 {
		return d
	}
	return 5 * time.Minute
}

func (w *World) provisionTenantKeys() error {
	sys, err := w.Auth.System(w.Tenant, "journeytest provisioning")
	if errors.Is(err, egauth.ErrFacadeUnavailable) {
		return nil
	}
	if err != nil {
		return errors.Join(errors.New("journeytest: provisioning the tenant keys"), err)
	}
	err = w.Auth.Tenants().RenewKeys(context.Background(), sys, egauth.RenewKeysRequest{Tenant: w.Tenant, Lifetime: keys.DefaultExpiry(), Overlap: keys.DefaultExpiry()})
	if err == nil || errors.Is(err, egauth.ErrFacadeUnavailable) {
		return nil
	}
	return errors.Join(errors.New("journeytest: provisioning the tenant keys"), err)
}
