package egauth_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/memstore"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/deployment"
	fedstore "github.com/JLugagne/egauth/store/federation"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/keys"
	"github.com/JLugagne/egauth/store/limiter"
	limitermem "github.com/JLugagne/egauth/store/limiter/memory"
	"github.com/JLugagne/egauth/store/mfa"
	mfamem "github.com/JLugagne/egauth/store/mfa/memory"
	"github.com/JLugagne/egauth/store/passkey"
	passkeymem "github.com/JLugagne/egauth/store/passkey/memory"
	"github.com/JLugagne/egauth/store/sessions"
	"github.com/JLugagne/egauth/store/tokens"
	tokensmem "github.com/JLugagne/egauth/store/tokens/memory"
)

type base struct {
	d   store.Durability
	err error
}

type identityStub struct {
	identity.Store
	b *base
}

func (s identityStub) Ping(context.Context) error   { return s.b.err }
func (s identityStub) Durability() store.Durability { return s.b.d }

type ceremonyStub struct {
	ceremony.Store
	b *base
}

func (s ceremonyStub) Ping(context.Context) error   { return s.b.err }
func (s ceremonyStub) Durability() store.Durability { return s.b.d }

type deploymentStub struct {
	deployment.Store
	b *base
}

func (s deploymentStub) Ping(context.Context) error   { return s.b.err }
func (s deploymentStub) Durability() store.Durability { return s.b.d }

type limiterStub struct {
	limiter.Limiter
	b *base
}

func (s limiterStub) Ping(context.Context) error   { return s.b.err }
func (s limiterStub) Durability() store.Durability { return s.b.d }

type tokensStub struct {
	tokens.Store
	b *base
}

func (s tokensStub) Ping(context.Context) error   { return s.b.err }
func (s tokensStub) Durability() store.Durability { return s.b.d }

type sessionsStub struct {
	sessions.Store
	b *base
}

func (s sessionsStub) Ping(context.Context) error   { return s.b.err }
func (s sessionsStub) Durability() store.Durability { return s.b.d }

type mfaStub struct {
	mfa.Store
	b *base
}

func (s mfaStub) Ping(context.Context) error   { return s.b.err }
func (s mfaStub) Durability() store.Durability { return s.b.d }

type passkeyStub struct {
	passkey.Store
	b *base
}

func (s passkeyStub) Ping(context.Context) error   { return s.b.err }
func (s passkeyStub) Durability() store.Durability { return s.b.d }

type federationStub struct {
	fedstore.Store
	b *base
}

func (s federationStub) Ping(context.Context) error   { return s.b.err }
func (s federationStub) Durability() store.Durability { return s.b.d }

type keysStub struct {
	keys.Store
	b *base
}

func (s keysStub) Ping(context.Context) error   { return s.b.err }
func (s keysStub) Durability() store.Durability { return s.b.d }

func storage(d store.Durability) egauth.Storage {
	m := memstore.New(nil)
	return egauth.Storage{
		Identity:   identityStub{Store: m.Identity, b: &base{d: d}},
		Ceremonies: ceremonyStub{Store: m.Ceremonies, b: &base{d: d}},
		Deployment: deploymentStub{Store: m.Deployment, b: &base{d: d}},
		Limiter:    memLimiter(d),
		Tokens:     tokensStub{Store: m.Tokens, b: &base{d: d}},
		Sessions:   sessionsStub{Store: m.Sessions, b: &base{d: d}},
		MFA:        mfaStub{Store: m.MFA, b: &base{d: d}},
		Passkeys:   passkeyStub{Store: m.Passkeys, b: &base{d: d}},
		Federation: federationStub{Store: m.Federation, b: &base{d: d}},
		Keys:       keysStub{Store: m.Keys, b: &base{d: d}},
	}
}

func memLimiter(d store.Durability) limiterStub {
	return limiterStub{Limiter: limitermem.New(), b: &base{d: d}}
}

type emailStub struct{ egauth.EmailDeliverer }

type smsStub struct{ egauth.SMSDeliverer }

type claimsStub struct{}

func (claimsStub) ClaimsFor(context.Context, principal.Subject) (egauth.AppClaims[struct{}], error) {
	return egauth.AppClaims[struct{}]{Roles: []string{"user"}}, nil
}

type factorStub struct{ name string }

func (f factorStub) Name() string { return f.name }

func (factorStub) Verify(context.Context, egauth.ExternalRequest) (egauth.ExternalIdentity, error) {
	return egauth.ExternalIdentity{}, errors.New("stub")
}

type policyStub struct{}

func (policyStub) Verify(context.Context, string) error { return nil }

type breachStub struct{}

func (breachStub) IsBreached(context.Context, string) (bool, error) { return false, nil }

type observerStub struct{}

func (observerStub) OutboundStart(*http.Request) func(*http.Response, error) { return nil }

func testKEK(t testing.TB) kek.KEK {
	t.Helper()
	sum := sha256.Sum256([]byte("egauth config test kek"))
	k, err := kek.NewLocal(sum[:])
	require.NoError(t, err)
	return k
}

func edSigner(t testing.TB, kid string) signing.Signer {
	t.Helper()
	sum := sha256.Sum256([]byte("egauth config test signer " + kid))
	s, err := signing.EdDSA(kid, sum[:])
	require.NoError(t, err)
	return s
}

func hsSigner(t testing.TB, kid string) signing.Signer {
	t.Helper()
	sum := sha256.Sum256([]byte("egauth config test hmac " + kid))
	s, err := signing.HS256(kid, sum[:])
	require.NoError(t, err)
	return s
}

func provider(name string) federation.Provider {
	return federation.Provider{
		Name:              name,
		ClientID:          "client",
		AuthURL:           "https://idp.example.com/authorize",
		TokenURL:          "https://idp.example.com/token",
		UserInfoURL:       "https://idp.example.com/userinfo",
		EmailVerification: federation.Never,
	}
}

func fullModules() egauth.Modules {
	return egauth.Modules{
		Password:     &egauth.PasswordModule{Policy: policyStub{}, Breach: breachStub{}, Registration: egauth.RegistrationOpen},
		MagicLink:    &egauth.MagicLinkModule{},
		LoginCode:    &egauth.LoginCodeModule{Email: true, SMS: true},
		Passkey:      &egauth.PasskeyModule{DisplayName: "Example", Attestation: egauth.AttestationNone},
		OAuth:        &egauth.OAuthModule{Providers: []federation.Provider{provider("corp")}, PerTenant: true},
		External:     &egauth.ExternalModule{Verifiers: []egauth.ExternalFactor{factorStub{name: "ldap"}}},
		MFA:          &egauth.MFAModule{TOTPIssuer: "Example"},
		Verification: &egauth.VerificationModule{Email: true, Phone: true, RecoveryEmail: true},
		SelfDelete:   &egauth.SelfDeleteModule{},
		APIKeys:      &egauth.APIKeyModule{Kinds: []string{"service", "pat"}, Prefix: "exk"},
	}
}

func fullConfig(t testing.TB) egauth.Config[struct{}] {
	t.Helper()
	return egauth.Config[struct{}]{
		PublicOrigin: "https://app.example.com",
		BasePath:     "/auth",
		ExtraOrigins: []string{"https://admin.app.example.com"},
		Audiences:    []string{"https://api.example.com"},
		Proxy:        egauth.DirectClients(),
		Tenancy:      egauth.SingleTenant(),
		Storage:      storage(store.Shared),
		KEK:          testKEK(t),
		Sessions:     egauth.JWT(egauth.TenantKeys()),
		Transport:    egauth.CookiesAndBearer,
		Policy: egauth.SessionPolicy{
			IdleTimeout: 24 * time.Hour, MaxLifetime: 720 * time.Hour, RecheckEvery: 5 * time.Minute,
			ReauthWindow: 10 * time.Minute, Remember: egauth.RememberUserChoice,
		},
		Admin:  egauth.RoleAdmin("admin"),
		Claims: claimsStub{},
		Events: event.Discard,
		Email:  emailStub{},
		SMS:    smsStub{},
		Pages: egauth.Pages{
			Login: "/login", AfterLogin: "/home", MFA: "/mfa", Reauth: "/reauth", Error: "/error",
			ConfirmRegistration: "/register/confirm", MagicLink: "/magic", PasswordReset: "/reset",
			VerifyEmail: "/verify", ConfirmEmailChange: "/email/confirm", SecurityRevert: "/revert",
		},
		Modules:   fullModules(),
		RateLimit: memLimiter(store.Shared),
		Outbound:  observerStub{},
		Hooks:     egauth.Hooks{BeforeEndpoint: func(context.Context, egauth.EndpointRequest) error { return nil }},
	}
}

func configErrors(err error) []*egauth.ConfigError {
	var out []*egauth.ConfigError
	var walk func(error)
	walk = func(e error) {
		if ce, ok := e.(*egauth.ConfigError); ok {
			out = append(out, ce)
			return
		}
		if u, ok := e.(interface{ Unwrap() []error }); ok {
			for _, x := range u.Unwrap() {
				walk(x)
			}
		}
	}
	walk(err)
	return out
}

func fieldsOf(err error) []string {
	var out []string
	for _, ce := range configErrors(err) {
		out = append(out, ce.Field)
	}
	return out
}

func newErr(t *testing.T, cfg egauth.Config[struct{}]) error {
	t.Helper()
	a, err := egauth.New(cfg)
	if err == nil {
		require.NoError(t, a.Close())
	}
	return err
}

func requireField(t *testing.T, err error, field string) {
	t.Helper()
	require.Error(t, err)
	require.Contains(t, fieldsOf(err), field, "errors: %v", err)
}

func requireNoField(t *testing.T, err error, field string) {
	t.Helper()
	require.NotContains(t, fieldsOf(err), field, "errors: %v", err)
}

func TestConfigFullIsValid(t *testing.T) {
	a, err := egauth.New(fullConfig(t))
	require.NoError(t, err)
	require.NoError(t, a.Ready(context.Background()))
	p := a.Posture()
	require.Empty(t, p.OptOuts)
	require.Equal(t, store.Shared, p.Durability)
	require.NoError(t, a.Close())
}

func TestConfigEveryErrorIsAConfigError(t *testing.T) {
	err := newErr(t, egauth.Config[struct{}]{})
	require.Error(t, err)
	var ce *egauth.ConfigError
	require.ErrorAs(t, err, &ce)
	u, ok := err.(interface{ Unwrap() []error })
	require.True(t, ok)
	for _, e := range u.Unwrap() {
		require.IsType(t, &egauth.ConfigError{}, e)
	}
}

func TestConfigZeroValueReportsEveryRequiredField(t *testing.T) {
	err := newErr(t, egauth.Config[struct{}]{})
	for _, f := range []string{"PublicOrigin", "Proxy", "Storage", "Storage.Identity", "Storage.MFA", "Storage.Passkeys", "KEK", "Sessions", "Admin", "Modules"} {
		requireField(t, err, f)
	}
	require.NotContains(t, err.Error(), "misconfigured")
}

func TestConfigSessionBackendIsRequired(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Sessions = nil
	requireField(t, newErr(t, cfg), "Sessions")
}

func TestConfigClaimsSourceDefaultsToEmptyClaims(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Claims = nil
	require.NoError(t, newErr(t, cfg))
	r, errs := egauth.Resolve(cfg)
	require.Empty(t, errs)
	require.True(t, r.Defaulted("Claims"))
	v, ok := r.Get("Claims")
	require.True(t, ok)
	src, ok := v.(egauth.ClaimsSource[struct{}])
	require.True(t, ok)
	claims, err := src.ClaimsFor(context.Background(), principal.Subject{})
	require.NoError(t, err)
	require.Equal(t, egauth.AppClaims[struct{}]{}, claims)
}

func TestConfigJWTKeysAreASealedChoice(t *testing.T) {
	cases := map[string]egauth.SessionBackend{
		"nil keys":            egauth.JWT(nil),
		"zero active signer":  egauth.JWT(egauth.StaticKeys(signing.Signer{})),
		"zero verify-only":    egauth.JWT(egauth.StaticKeys(edSigner(t, "a"), signing.Verifier{})),
		"duplicate key ids":   egauth.JWT(egauth.StaticKeys(edSigner(t, "a"), edSigner(t, "a").Verifier())),
		"embedded nil policy": embeddedBackend{},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := fullConfig(t)
			cfg.Sessions = b
			requireField(t, newErr(t, cfg), "Sessions")
		})
	}
	t.Run("static keys need no key store", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Sessions = egauth.JWT(egauth.StaticKeys(edSigner(t, "a"), edSigner(t, "b").Verifier()))
		cfg.Storage.Keys = nil
		require.NoError(t, newErr(t, cfg))
	})
	t.Run("tenant keys need the key store", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Storage.Keys = nil
		requireField(t, newErr(t, cfg), "Storage.Keys")
	})
}

type embeddedBackend struct{ egauth.SessionBackend }

type embeddedProxy struct{ egauth.ProxyPolicy }

func TestConfigSealedPolicies(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*egauth.Config[struct{}])
		field string
	}{
		{"proxy /0", func(c *egauth.Config[struct{}]) {
			c.Proxy = egauth.TrustedProxies(netip.MustParsePrefix("0.0.0.0/0"))
		}, "Proxy"},
		{"proxy ipv4 /7", func(c *egauth.Config[struct{}]) {
			c.Proxy = egauth.TrustedProxies(netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/7"))
		}, "Proxy"},
		{"proxy ipv6 /15", func(c *egauth.Config[struct{}]) { c.Proxy = egauth.TrustedProxies(netip.MustParsePrefix("fd00::/15")) }, "Proxy"},
		{"proxy invalid prefix", func(c *egauth.Config[struct{}]) { c.Proxy = egauth.TrustedProxies(netip.Prefix{}) }, "Proxy"},
		{"proxy embedded nil", func(c *egauth.Config[struct{}]) { c.Proxy = embeddedProxy{} }, "Proxy"},
		{"proxy ipv6 /16 over the ipv4 embeddings", func(c *egauth.Config[struct{}]) {
			c.Proxy = egauth.TrustedProxies(netip.MustParsePrefix("::/16"))
		}, "Proxy"},
		{"proxy nat64 well-known prefix", func(c *egauth.Config[struct{}]) {
			c.Proxy = egauth.TrustedProxies(netip.MustParsePrefix("64:ff9b::/96"))
		}, "Proxy"},
		{"proxy nat64 host", func(c *egauth.Config[struct{}]) {
			c.Proxy = egauth.TrustedProxies(netip.MustParsePrefix("64:ff9b::a00:1/128"))
		}, "Proxy"},
		{"proxy inside the ipv4-compatible block", func(c *egauth.Config[struct{}]) {
			c.Proxy = egauth.TrustedProxies(netip.MustParsePrefix("::/100"))
		}, "Proxy"},
		{"proxy 6to4 prefix", func(c *egauth.Config[struct{}]) {
			c.Proxy = egauth.TrustedProxies(netip.MustParsePrefix("2002::/16"))
		}, "Proxy"},
		{"proxy 6to4 host", func(c *egauth.Config[struct{}]) {
			c.Proxy = egauth.TrustedProxies(netip.MustParsePrefix("2002:c000:204::/48"))
		}, "Proxy"},
		{"proxy nat64 local-use prefix", func(c *egauth.Config[struct{}]) {
			c.Proxy = egauth.TrustedProxies(netip.MustParsePrefix("64:ff9b:1::/48"))
		}, "Proxy"},
		{"nil tenant resolver", func(c *egauth.Config[struct{}]) { c.Tenancy = egauth.TenantFromRequest(nil) }, "Tenancy"},
		{"blank admin role", func(c *egauth.Config[struct{}]) { c.Admin = egauth.RoleAdmin(" ") }, "Admin"},
		{"unknown transport", func(c *egauth.Config[struct{}]) { c.Transport = egauth.Transport(9) }, "Transport"},
		{"unknown remember policy", func(c *egauth.Config[struct{}]) { c.Policy.Remember = 9 }, "Policy.Remember"},
		{"unknown registration", func(c *egauth.Config[struct{}]) { c.Modules.Password.Registration = 9 }, "Modules.Password.Registration"},
		{"unknown attestation", func(c *egauth.Config[struct{}]) { c.Modules.Passkey.Attestation = 9 }, "Modules.Passkey.Attestation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fullConfig(t)
			tc.mut(&cfg)
			requireField(t, newErr(t, cfg), tc.field)
		})
	}
	t.Run("accepted", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Proxy = egauth.TrustedProxies(netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/16"),
			netip.MustParsePrefix("::1/128"))
		cfg.Admin = egauth.SelfServiceOnly()
		cfg.Transport = egauth.Bearer
		require.NoError(t, newErr(t, cfg))
	})
}

func TestConfigOrigins(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*egauth.Config[struct{}])
		field string
	}{
		{"http off loopback", func(c *egauth.Config[struct{}]) { c.PublicOrigin = "http://app.example.com" }, "PublicOrigin"},
		{"origin with path", func(c *egauth.Config[struct{}]) { c.PublicOrigin = "https://app.example.com/app" }, "PublicOrigin"},
		{"subdomain tenancy without label", func(c *egauth.Config[struct{}]) { c.Tenancy = egauth.TenantBySubdomain() }, "PublicOrigin"},
		{"label without subdomain tenancy", func(c *egauth.Config[struct{}]) { c.PublicOrigin = "https://{tenant}.example.com" }, "PublicOrigin"},
		{"extra label without subdomain tenancy", func(c *egauth.Config[struct{}]) {
			c.ExtraOrigins = []string{"https://{tenant}.app.example.com"}
		}, "ExtraOrigins[0]"},
		{"audience equals public origin", func(c *egauth.Config[struct{}]) { c.Audiences = []string{c.PublicOrigin} }, "Audiences[0]"},
		{"audience with label", func(c *egauth.Config[struct{}]) {
			c.Tenancy = egauth.TenantBySubdomain()
			c.PublicOrigin = "https://{tenant}.example.com"
			c.ExtraOrigins = nil
			c.Audiences = []string{"https://{tenant}.api.example.com"}
		}, "Audiences[0]"},
		{"audience equals extra origin", func(c *egauth.Config[struct{}]) { c.Audiences = []string{c.ExtraOrigins[0]} }, "Audiences[0]"},
		{"audience is a tenant of public origin", func(c *egauth.Config[struct{}]) {
			c.Tenancy = egauth.TenantBySubdomain()
			c.PublicOrigin = "https://{tenant}.example.com"
			c.ExtraOrigins = nil
			c.Audiences = []string{"https://acme.example.com"}
		}, "Audiences[0]"},
		{"audience is a tenant of public origin with port", func(c *egauth.Config[struct{}]) {
			c.Tenancy = egauth.TenantBySubdomain()
			c.PublicOrigin = "https://{tenant}.example.com:8443"
			c.ExtraOrigins = nil
			c.Audiences = []string{"https://api.example.com", "https://acme.example.com:8443"}
		}, "Audiences[1]"},
		{"audience is a tenant of an extra origin", func(c *egauth.Config[struct{}]) {
			c.Tenancy = egauth.TenantBySubdomain()
			c.PublicOrigin = "https://{tenant}.example.com"
			c.ExtraOrigins = []string{"https://{tenant}.example.com:8443"}
			c.Audiences = []string{"https://acme.example.com:8443"}
		}, "Audiences[0]"},
		{"base path trailing slash", func(c *egauth.Config[struct{}]) { c.BasePath = "/auth/" }, "BasePath"},
		{"base path well-known", func(c *egauth.Config[struct{}]) { c.BasePath = "/.well-known" }, "BasePath"},
		{"base path under well-known", func(c *egauth.Config[struct{}]) { c.BasePath = "/.well-known/auth" }, "BasePath"},
		{"page on a foreign origin", func(c *egauth.Config[struct{}]) { c.Pages.AfterLogin = "https://evil.example.net/home" }, "Pages.AfterLogin"},
		{"page absolute with a doubled slash", func(c *egauth.Config[struct{}]) {
			c.Pages.AfterLogin = c.PublicOrigin + "//evil.example.net/x"
		}, "Pages.AfterLogin"},
		{"page scheme relative", func(c *egauth.Config[struct{}]) { c.Pages.Login = "//evil.example.net/login" }, "Pages.Login"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fullConfig(t)
			tc.mut(&cfg)
			requireField(t, newErr(t, cfg), tc.field)
		})
	}
	t.Run("subdomain tenancy", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Tenancy = egauth.TenantBySubdomain()
		cfg.PublicOrigin = "https://{tenant}.example.com"
		cfg.ExtraOrigins = nil
		cfg.Audiences = []string{"https://api.example.net"}
		cfg.Pages.AfterLogin = "https://{tenant}.example.com/home"
		require.NoError(t, newErr(t, cfg))
	})
	t.Run("audience outside every tenant pattern", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Tenancy = egauth.TenantBySubdomain()
		cfg.PublicOrigin = "https://{tenant}.example.com"
		cfg.ExtraOrigins = nil
		cfg.Audiences = []string{"https://api.example.net", "https://a.b.example.com", "https://example.com"}
		require.NoError(t, newErr(t, cfg))
	})
	t.Run("absolute page on an allowed origin", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Pages.AfterLogin = "https://app.example.com/home"
		cfg.Pages.Error = "https://admin.app.example.com/error"
		require.NoError(t, newErr(t, cfg))
	})
}

func TestConfigPasskeyRPIDCoversEveryOrigin(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*egauth.Config[struct{}])
		field string
	}{
		{"extra origin outside the rp id", func(c *egauth.Config[struct{}]) { c.ExtraOrigins = []string{"https://other.example.org"} }, "ExtraOrigins[0]"},
		{"extra origin on the parent domain", func(c *egauth.Config[struct{}]) { c.ExtraOrigins = []string{"https://example.com"} }, "ExtraOrigins[0]"},
		{"ip public origin", func(c *egauth.Config[struct{}]) {
			c.PublicOrigin, c.ExtraOrigins = "https://192.0.2.10", nil
		}, "PublicOrigin"},
		{"public suffix rp id", func(c *egauth.Config[struct{}]) { c.PublicOrigin, c.ExtraOrigins = "https://co.uk", nil }, "PublicOrigin"},
		{"tenant host does not cover the parent", func(c *egauth.Config[struct{}]) {
			c.Tenancy = egauth.TenantBySubdomain()
			c.PublicOrigin = "https://{tenant}.example.com"
			c.ExtraOrigins = []string{"https://example.com"}
		}, "ExtraOrigins[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fullConfig(t)
			tc.mut(&cfg)
			requireField(t, newErr(t, cfg), tc.field)
		})
	}
	t.Run("loopback", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.PublicOrigin = "http://localhost:8080"
		cfg.ExtraOrigins = nil
		require.NoError(t, newErr(t, cfg))
	})
	t.Run("no passkey module", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Modules.Passkey = nil
		cfg.PublicOrigin = "https://192.0.2.10"
		cfg.ExtraOrigins = []string{"https://other.example.org"}
		require.NoError(t, newErr(t, cfg))
	})
}

func TestConfigDurability(t *testing.T) {
	t.Run("mixed", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Storage.Tokens = tokensStub{Store: tokensmem.New(), b: &base{d: store.Ephemeral}}
		requireField(t, newErr(t, cfg), "Storage.Tokens")
	})
	t.Run("invalid", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Storage.MFA = mfaStub{Store: mfamem.New(), b: &base{}}
		requireField(t, newErr(t, cfg), "Storage.MFA")
		cfg = fullConfig(t)
		cfg.RateLimit = memLimiter(7)
		requireField(t, newErr(t, cfg), "RateLimit")
	})
	t.Run("ephemeral off loopback", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Storage = storage(store.Ephemeral)
		requireField(t, newErr(t, cfg), "Storage")
	})
	t.Run("ephemeral on loopback", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Storage = storage(store.Ephemeral)
		cfg.PublicOrigin, cfg.ExtraOrigins, cfg.Audiences = "http://127.0.0.1:8080", nil, nil
		cfg.Modules.Passkey = nil
		require.NoError(t, newErr(t, cfg))
	})
	t.Run("ephemeral on loopback with a public extra origin", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Storage = storage(store.Ephemeral)
		cfg.PublicOrigin = "http://127.0.0.1:8080"
		cfg.ExtraOrigins = []string{"https://admin.example.com"}
		cfg.Modules.Passkey = nil
		requireField(t, newErr(t, cfg), "Storage")
	})
	t.Run("ephemeral on loopback with a public audience", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Storage = storage(store.Ephemeral)
		cfg.PublicOrigin, cfg.ExtraOrigins = "http://127.0.0.1:8080", nil
		cfg.Modules.Passkey = nil
		requireField(t, newErr(t, cfg), "Storage")
	})
	t.Run("ephemeral on loopback everywhere", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Storage = storage(store.Ephemeral)
		cfg.PublicOrigin = "http://127.0.0.1:8080"
		cfg.ExtraOrigins = []string{"http://localhost:3000"}
		cfg.Audiences = []string{"http://localhost:9000"}
		cfg.Modules.Passkey = nil
		require.NoError(t, newErr(t, cfg))
	})
	t.Run("ephemeral acknowledged", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Storage = storage(store.Ephemeral)
		cfg.Insecure.EphemeralState = egauth.Acknowledge("single-node demo")
		a, err := egauth.New(cfg)
		require.NoError(t, err)
		require.Equal(t, store.Ephemeral, a.Posture().Durability)
	})
	t.Run("ephemeral limiter beside shared stores", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Storage.Limiter = memLimiter(store.Ephemeral)
		cfg.RateLimit = nil
		require.NoError(t, newErr(t, cfg))
	})
}

func TestConfigModules(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*egauth.Config[struct{}])
		field string
	}{
		{"no primary module", func(c *egauth.Config[struct{}]) {
			m := c.Modules
			c.Modules = egauth.Modules{MFA: m.MFA, Verification: m.Verification, SelfDelete: m.SelfDelete, APIKeys: m.APIKeys}
		}, "Modules"},
		{"login code without channel", func(c *egauth.Config[struct{}]) { c.Modules.LoginCode = &egauth.LoginCodeModule{} }, "Modules.LoginCode"},
		{"verification without channel", func(c *egauth.Config[struct{}]) { c.Modules.Verification = &egauth.VerificationModule{} }, "Modules.Verification"},
		{"oauth without provider", func(c *egauth.Config[struct{}]) { c.Modules.OAuth = &egauth.OAuthModule{} }, "Modules.OAuth"},
		{"duplicate provider names", func(c *egauth.Config[struct{}]) {
			c.Modules.OAuth.Providers = []federation.Provider{provider("corp"), provider("corp")}
		}, "Modules.OAuth.Providers[1]"},
		{"invalid provider", func(c *egauth.Config[struct{}]) {
			c.Modules.OAuth.Providers = []federation.Provider{{Name: "Bad Name"}}
		}, "Modules.OAuth.Providers[0]"},
		{"duplicate api key kinds", func(c *egauth.Config[struct{}]) { c.Modules.APIKeys.Kinds = []string{"svc", "svc"} }, "Modules.APIKeys.Kinds[1]"},
		{"api key kind not a token", func(c *egauth.Config[struct{}]) { c.Modules.APIKeys.Kinds = []string{"Service Key"} }, "Modules.APIKeys.Kinds[0]"},
		{"external name not a token", func(c *egauth.Config[struct{}]) {
			c.Modules.External.Verifiers = []egauth.ExternalFactor{factorStub{name: "LDAP Login"}}
		}, "Modules.External.Verifiers[0]"},
		{"duplicate external names", func(c *egauth.Config[struct{}]) {
			c.Modules.External.Verifiers = []egauth.ExternalFactor{factorStub{name: "ldap"}, factorStub{name: "ldap"}}
		}, "Modules.External.Verifiers[1]"},
		{"nil external factor", func(c *egauth.Config[struct{}]) {
			c.Modules.External.Verifiers = []egauth.ExternalFactor{nil}
		}, "Modules.External.Verifiers[0]"},
		{"audiences with stateful sessions", func(c *egauth.Config[struct{}]) { c.Sessions = egauth.Stateful() }, "Audiences"},
		{"audiences with hs256", func(c *egauth.Config[struct{}]) {
			c.Sessions = egauth.JWT(egauth.StaticKeys(hsSigner(t, "h")))
		}, "Audiences"},
		{"email deliverer missing", func(c *egauth.Config[struct{}]) { c.Email = nil }, "Email"},
		{"sms deliverer missing", func(c *egauth.Config[struct{}]) { c.SMS = nil }, "SMS"},
		{"oauth page missing", func(c *egauth.Config[struct{}]) { c.Pages.AfterLogin = "" }, "Pages.AfterLogin"},
		{"password reset redirect target missing", func(c *egauth.Config[struct{}]) { c.Pages.Login = "" }, "Pages.Login"},
		{"api key prefix not a token", func(c *egauth.Config[struct{}]) { c.Modules.APIKeys.Prefix = "bad prefix_" }, "Modules.APIKeys.Prefix"},
		{"passkey display name missing", func(c *egauth.Config[struct{}]) { c.Modules.Passkey.DisplayName = "" }, "Modules.Passkey.DisplayName"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fullConfig(t)
			tc.mut(&cfg)
			requireField(t, newErr(t, cfg), tc.field)
		})
	}
	t.Run("hs256 without audiences", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Sessions = egauth.JWT(egauth.StaticKeys(hsSigner(t, "h")))
		cfg.Audiences = nil
		require.NoError(t, newErr(t, cfg))
	})
	t.Run("minimal", func(t *testing.T) {
		cfg := egauth.Config[struct{}]{
			PublicOrigin: "https://app.example.com",
			Proxy:        egauth.DirectClients(),
			Storage:      storage(store.Shared),
			KEK:          testKEK(t),
			Sessions:     egauth.Stateful(),
			Admin:        egauth.SelfServiceOnly(),
			Email:        &egauthtest.Mailbox{},
			Pages:        egauth.Pages{SecurityRevert: "/revert"},
			Modules:      egauth.Modules{Passkey: &egauth.PasskeyModule{DisplayName: "Example"}},
		}
		require.NoError(t, newErr(t, cfg))
	})
}

func TestConfigReportsEveryProblemAtOnce(t *testing.T) {
	cfg := fullConfig(t)
	cfg.PublicOrigin = "http://app.example.com"
	cfg.Admin = nil
	cfg.Modules.APIKeys.Kinds = []string{"svc", "svc"}
	cfg.Insecure.NoRateLimit = egauth.Acknowledge("")
	cfg.Storage.Tokens = tokensStub{Store: tokensmem.New(), b: &base{d: store.Ephemeral}}
	err := newErr(t, cfg)
	for _, f := range []string{"PublicOrigin", "Admin", "Modules.APIKeys.Kinds[1]", "Insecure.NoRateLimit", "Storage.Tokens"} {
		requireField(t, err, f)
	}
}

func TestConfigInsecureOptOutsNeedAReason(t *testing.T) {
	allowance := func(a *egauth.Ack) *egauth.OutboundAllowance {
		return &egauth.OutboundAllowance{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, Ack: a}
	}
	sets := []struct {
		field string
		set   func(*egauth.InsecureOptOuts, *egauth.Ack)
	}{
		{"Insecure.NoOriginCheck", func(in *egauth.InsecureOptOuts, a *egauth.Ack) { in.NoOriginCheck = a }},
		{"Insecure.NoRateLimit", func(in *egauth.InsecureOptOuts, a *egauth.Ack) { in.NoRateLimit = a }},
		{"Insecure.NoReauthWindow", func(in *egauth.InsecureOptOuts, a *egauth.Ack) { in.NoReauthWindow = a }},
		{"Insecure.LongSessions", func(in *egauth.InsecureOptOuts, a *egauth.Ack) { in.LongSessions = a }},
		{"Insecure.EphemeralState", func(in *egauth.InsecureOptOuts, a *egauth.Ack) { in.EphemeralState = a }},
		{"Insecure.SharedCookieDomain.Ack", func(in *egauth.InsecureOptOuts, a *egauth.Ack) {
			in.SharedCookieDomain = &egauth.SharedCookieDomain{Domain: "example.com", Ack: a}
		}},
		{"Insecure.OutboundPrivateNetwork.Ack", func(in *egauth.InsecureOptOuts, a *egauth.Ack) { in.OutboundPrivateNetwork = allowance(a) }},
		{"Insecure.TenantOutboundPrivateNetwork.Ack", func(in *egauth.InsecureOptOuts, a *egauth.Ack) {
			in.TenantOutboundPrivateNetwork = allowance(a)
		}},
	}
	for _, s := range sets {
		t.Run(s.field, func(t *testing.T) {
			for _, bad := range []*egauth.Ack{nil, egauth.Acknowledge(""), egauth.Acknowledge("  \t")} {
				cfg := fullConfig(t)
				s.set(&cfg.Insecure, bad)
				if bad == nil && !strings.HasSuffix(s.field, ".Ack") {
					continue
				}
				requireField(t, newErr(t, cfg), s.field)
			}
			cfg := fullConfig(t)
			s.set(&cfg.Insecure, egauth.Acknowledge("reviewed in SEC-42"))
			a, err := egauth.New(cfg)
			require.NoError(t, err)
			p := a.Posture()
			require.Len(t, p.OptOuts, 1)
			require.Equal(t, "reviewed in SEC-42", p.OptOuts[0].Reason)
			require.Equal(t, strings.TrimSuffix(strings.TrimPrefix(s.field, "Insecure."), ".Ack"), p.OptOuts[0].Name)
		})
	}
}

func TestConfigInsecureValues(t *testing.T) {
	ack := egauth.Acknowledge("reviewed")
	cases := []struct {
		name  string
		in    egauth.InsecureOptOuts
		field string
	}{
		{"shared domain not covering the origin", egauth.InsecureOptOuts{
			SharedCookieDomain: &egauth.SharedCookieDomain{Domain: "example.org", Ack: ack},
		}, "Insecure.SharedCookieDomain.Domain"},
		{"shared domain on a public suffix", egauth.InsecureOptOuts{
			SharedCookieDomain: &egauth.SharedCookieDomain{Domain: "com", Ack: ack},
		}, "Insecure.SharedCookieDomain.Domain"},
		{"shared domain upper case", egauth.InsecureOptOuts{
			SharedCookieDomain: &egauth.SharedCookieDomain{Domain: "Example.com", Ack: ack},
		}, "Insecure.SharedCookieDomain.Domain"},
		{"allowance without prefix", egauth.InsecureOptOuts{
			OutboundPrivateNetwork: &egauth.OutboundAllowance{Ack: ack},
		}, "Insecure.OutboundPrivateNetwork.Prefixes"},
		{"allowance on link-local", egauth.InsecureOptOuts{
			OutboundPrivateNetwork: &egauth.OutboundAllowance{Prefixes: []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}, Ack: ack},
		}, "Insecure.OutboundPrivateNetwork.Prefixes"},
		{"tenant allowance too wide", egauth.InsecureOptOuts{
			TenantOutboundPrivateNetwork: &egauth.OutboundAllowance{Prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/4")}, Ack: ack},
		}, "Insecure.TenantOutboundPrivateNetwork.Prefixes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fullConfig(t)
			cfg.Insecure = tc.in
			requireField(t, newErr(t, cfg), tc.field)
		})
	}
}

func TestConfigLongSessionsRaisesTheBound(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Policy.MaxLifetime = 2160*time.Hour + time.Second
	requireField(t, newErr(t, cfg), "Policy.MaxLifetime")
	cfg.Insecure.LongSessions = egauth.Acknowledge("kiosk devices")
	require.NoError(t, newErr(t, cfg))
	cfg.Policy.MaxLifetime = egauth.LongSessionsMax + time.Second
	requireField(t, newErr(t, cfg), "Policy.MaxLifetime")
}

func TestConfigNewKeepsItsOwnCopy(t *testing.T) {
	cfg := fullConfig(t)
	a, err := egauth.New(cfg)
	require.NoError(t, err)
	cfg.Modules.APIKeys.Kinds[0] = "late"
	_, err = a.Routes().ProtectAPI("GET /x", func(http.ResponseWriter, *http.Request, egauth.Principal[struct{}]) {}, egauth.Kinds("late")).Build()
	require.Error(t, err)
}

func TestConfigNewKeepsItsOwnProviderSlices(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Modules.OAuth.Providers[0].Scopes = []string{"openid", "email"}
	cfg.Modules.OAuth.Providers[0].Domains = []string{"corp.example.com"}
	a, err := egauth.New(cfg)
	require.NoError(t, err)
	cfg.Modules.OAuth.Providers[0].Scopes[1] = "admin"
	cfg.Modules.OAuth.Providers[0].Domains[0] = "evil.example.net"
	got := egauth.ConfigOf(a).Modules.OAuth.Providers[0]
	require.Equal(t, []string{"openid", "email"}, got.Scopes)
	require.Equal(t, []string{"corp.example.com"}, got.Domains)
}

func TestConfigReadyAndClose(t *testing.T) {
	cfg := fullConfig(t)
	failing := errors.New("schema missing")
	b := &base{d: store.Shared}
	cfg.Storage.Passkeys = passkeyStub{Store: passkeymem.New(), b: b}
	a, err := egauth.New(cfg)
	require.NoError(t, err)
	require.NoError(t, a.Ready(context.Background()))
	b.err = failing
	err = a.Ready(context.Background())
	require.ErrorIs(t, err, failing)
	require.Contains(t, err.Error(), "Storage.Passkeys")
	require.NoError(t, a.Close())
	require.NoError(t, a.Close())
	require.ErrorIs(t, a.Ready(context.Background()), egauth.ErrClosed)
	require.Equal(t, 30*time.Second, egauth.StartupTimeout)
}

func TestConfigRequestValuesRedactSecrets(t *testing.T) {
	const captcha, secret = "captcha-token-value", "external-secret-value"
	values := []any{
		egauth.EndpointRequest{Endpoint: egauth.PathLogin, Client: netip.MustParseAddr("192.0.2.1"), CaptchaToken: captcha},
		egauth.ExternalRequest{Identifier: "alice", Secret: secret},
	}
	for _, v := range values {
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "v", v)
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		ptr := reflect.New(reflect.TypeOf(v))
		ptr.Elem().Set(reflect.ValueOf(v))
		p := ptr.Interface()
		out := buf.String() + string(raw) + fmt.Sprintf("%v %+v %#v %s %q %x %X %d %t %v %+v %#v %d",
			v, v, v, v, v, v, v, v, v, p, p, p, p)
		require.NotContains(t, out, captcha)
		require.NotContains(t, out, secret)
		require.NotContains(t, out, hex.EncodeToString([]byte(secret)))
		require.NotContains(t, out, hex.EncodeToString([]byte(captcha)))
		require.Contains(t, out, "REDACTED")
	}
}

func TestConfigFormattingOmitsWiringForEveryVerb(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Hooks.BeforeEndpoint = nil
	cfg.Modules.APIKeys.Kinds = []string{"leaky-kind"}
	out := fmt.Sprintf("%d %x %t %d %d", cfg, cfg, cfg, &cfg, cfg.Modules)
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	out += string(raw)
	require.Contains(t, out, "https://app.example.com")
	for _, leak := range []string{"leaky-kind", "identityStub", "admin", hex.EncodeToString([]byte("leaky-kind"))} {
		require.NotContains(t, out, leak)
	}
}

func TestConfigFormattingOmitsWiring(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Modules.OAuth.Providers[0].ClientSecret = federation.NewSecret("client-secret-value")
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "cfg", cfg, "modules", cfg.Modules)
	out := buf.String() + fmt.Sprintf("%v %+v %#v %s", cfg, cfg, cfg, cfg.Modules)
	require.Contains(t, out, "https://app.example.com")
	require.Contains(t, out, "Password MagicLink LoginCode Passkey OAuth External MFA Verification SelfDelete APIKeys")
	for _, leak := range []string{"client-secret-value", "identityStub", "kek.Local", "admin"} {
		require.NotContains(t, out, leak)
	}
}
