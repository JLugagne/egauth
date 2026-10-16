package configcheck_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/configcheck"
)

func TestValidConfigPassesAndDefaultsAreApplied(t *testing.T) {
	c := validConfig()
	r, errs := validate(t, &c, options())
	require.Empty(t, errs)
	require.NotNil(t, r)

	require.Equal(t, "/auth", c.BasePath)
	require.Equal(t, 168*time.Hour, c.Policy.IdleTimeout)
	require.Equal(t, 720*time.Hour, c.Policy.MaxLifetime)
	require.Equal(t, 5*time.Minute, c.Policy.RecheckEvery)
	require.Equal(t, "open", c.Modules.Password.Registration)
	require.Equal(t, "app.example.com", c.Issuer, "a default may read fields resolved before it")

	v, ok := r.Get("Policy.MaxLifetime")
	require.True(t, ok)
	require.Equal(t, 720*time.Hour, v)
	require.True(t, r.Defaulted("Policy.MaxLifetime"))
	require.True(t, r.Defaulted("Modules.Password.Registration"))
	require.False(t, r.Defaulted("PublicOrigin"))
	require.Equal(t, []string{
		"BasePath", "Issuer", "Modules.Password.Registration",
		"Policy.IdleTimeout", "Policy.MaxLifetime", "Policy.RecheckEvery",
	}, r.Applied())
}

func TestExplicitValuesAreKept(t *testing.T) {
	c := validConfig()
	c.BasePath = "/login"
	c.Policy.MaxLifetime = 24 * time.Hour
	c.Policy.IdleTimeout = time.Hour
	r, errs := validate(t, &c, options())
	require.Empty(t, errs)
	require.Equal(t, "/login", c.BasePath)
	require.Equal(t, 24*time.Hour, c.Policy.MaxLifetime)
	require.False(t, r.Defaulted("BasePath"))
	require.False(t, r.Defaulted("Policy.MaxLifetime"))
}

func TestResolvedGetNavigatesSlicesAndPointers(t *testing.T) {
	c := validConfig()
	c.ExtraOrigins = []string{"https://a.example.com", "https://b.example.com"}
	r, errs := validate(t, &c, options())
	require.Empty(t, errs)
	v, ok := r.Get("ExtraOrigins[1]")
	require.True(t, ok)
	require.Equal(t, "https://b.example.com", v)
	_, ok = r.Get("ExtraOrigins[2]")
	require.False(t, ok)
	_, ok = r.Get("Modules.Passkey.DisplayName")
	require.False(t, ok, "a nil module pointer has no fields")
	_, ok = r.Get("Nope")
	require.False(t, ok)
	_, ok = r.Get("ExtraOrigins[x]")
	require.False(t, ok)
}

func TestRequiredFieldsReportTheirExactPath(t *testing.T) {
	c := validConfig()
	c.PublicOrigin = ""
	_, errs := validate(t, &c, options())
	_ = requireOnly(t, errs, "PublicOrigin")

	c = validConfig()
	c.Storage.Identity = nil
	c.Storage.Tokens = &memStore{}
	_, errs = validate(t, &c, options())
	_ = requireOnly(t, errs, "Storage.Identity")
}

func TestTypedNilInInterfaceIsZero(t *testing.T) {
	c := validConfig()
	var nilStore *memStore
	c.Storage.Identity = nilStore
	c.Storage.Tokens = &memStore{}
	_, errs := validate(t, &c, options())
	_ = requireOnly(t, errs, "Storage.Identity")
}

func TestZeroRequiredStructReportsItselfAndItsFields(t *testing.T) {
	c := validConfig()
	c.Storage = storage{}
	_, errs := validate(t, &c, options())
	require.ElementsMatch(t, []string{"Storage", "Storage.Identity"}, problemFields(errs))
}

func TestWhitespaceStringsAreRejected(t *testing.T) {
	c := validConfig()
	c.BasePath = "   "
	_, errs := validate(t, &c, options())
	_ = requireOnly(t, errs, "BasePath")

	c = validConfig()
	c.PublicOrigin = " \t"
	_, errs = validate(t, &c, options())
	_ = requireOnly(t, errs, "PublicOrigin")
}

func TestEmptyNonNilSliceIsRejectedEvenWhenOptional(t *testing.T) {
	c := validConfig()
	c.ExtraOrigins = []string{}
	_, errs := validate(t, &c, options())
	_ = requireOnly(t, errs, "ExtraOrigins")
}

func TestZeroSliceElementIsRejected(t *testing.T) {
	c := validConfig()
	c.ExtraOrigins = []string{"https://a.example.com", ""}
	_, errs := validate(t, &c, options())
	_ = requireOnly(t, errs, "ExtraOrigins[1]")

	c = validConfig()
	c.ExtraOrigins = []string{" "}
	_, errs = validate(t, &c, options())
	_ = requireOnly(t, errs, "ExtraOrigins[0]")
}

func TestZeroNestedSpecInSliceIsRejected(t *testing.T) {
	c := validConfig()
	c.Modules.External = &externalModule{Factors: []externalFactor{{Name: "corp"}, {}}}
	c.Storage.Federation = &memStore{}
	_, errs := validate(t, &c, options())
	_ = requireOnly(t, errs, "Modules.External.Factors[1]")
}

func TestEachPredicateReportsTheElementPath(t *testing.T) {
	c := validConfig()
	c.ExtraOrigins = []string{"https://a.example.com", "ftp://b.example.com"}
	_, errs := validate(t, &c, options())
	_ = requireOnly(t, errs, "ExtraOrigins[1]")
}

func TestProviderAndExternalPredicatesCallTheirValidators(t *testing.T) {
	c := validConfig()
	c.Storage.Federation = &memStore{}
	c.Modules.OAuth = &oauthModule{Providers: []provider{{Name: "g", Issuer: "https://g"}, {Name: "x"}}}
	_, errs := validate(t, &c, options())
	e := requireOnly(t, errs, "Modules.OAuth.Providers[1]")
	require.Contains(t, e.Problem, errBadProvider.Error())

	c = validConfig()
	c.Storage.Federation = &memStore{}
	c.Modules.External = &externalModule{Factors: []externalFactor{{Name: " "}}}
	_, errs = validate(t, &c, options())
	_ = requireOnly(t, errs, "Modules.External.Factors[0]")
}

func TestNonEmptyPredicate(t *testing.T) {
	c := validConfig()
	c.Modules.Passkey = &passkeyModule{DisplayName: "\t"}
	_, errs := validate(t, &c, options())
	_ = requireOnly(t, errs, "Modules.Passkey.DisplayName")

	c = validConfig()
	c.Modules.Passkey = &passkeyModule{}
	_, errs = validate(t, &c, options())
	_ = requireOnly(t, errs, "Modules.Passkey.DisplayName")

	c = validConfig()
	c.Storage.Tokens = &memStore{}
	c.Modules.APIKeys = &apiKeyModule{Kinds: []string{}}
	_, errs = validate(t, &c, options())
	_ = requireOnly(t, errs, "Modules.APIKeys.Kinds")

	c = validConfig()
	c.Storage.Tokens = &memStore{}
	c.Modules.APIKeys = &apiKeyModule{}
	_, errs = validate(t, &c, options())
	_ = requireOnly(t, errs, "Modules.APIKeys.Kinds")
}

func TestTokenPredicate(t *testing.T) {
	good := []string{"ci", "deploy", "read-only", "svc_2", "a", "0abc"}
	bad := []string{"CI", "-x", "_x", "with space", "über", "a.b", "abcdefghijabcdefghijabcdefghijabc", "a/b"}
	for _, k := range good {
		c := validConfig()
		c.Storage.Tokens = &memStore{}
		c.Modules.APIKeys = &apiKeyModule{Kinds: []string{k}}
		_, errs := validate(t, &c, options())
		require.Empty(t, errs, k)
	}
	for _, k := range bad {
		c := validConfig()
		c.Storage.Tokens = &memStore{}
		c.Modules.APIKeys = &apiKeyModule{Kinds: []string{"ok", k}}
		_, errs := validate(t, &c, options())
		_ = requireOnly(t, errs, "Modules.APIKeys.Kinds[1]")
	}
}

func TestOriginPredicate(t *testing.T) {
	good := []string{
		"https://app.example.com",
		"https://app.example.com:8443",
		"http://localhost:8080",
		"http://127.0.0.1:3000",
		"http://[::1]:3000",
		"http://dev.localhost",
		"https://{tenant}.example.com",
		"http://{tenant}.localhost:8080",
		"https://xn--bcher-kva.example",
	}
	bad := []string{
		"app.example.com",
		"http://app.example.com",
		"https://app.example.com/",
		"https://app.example.com/auth",
		"https://app.example.com?x=1",
		"https://app.example.com#f",
		"https://user@app.example.com",
		"https://App.Example.com",
		"HTTPS://app.example.com",
		"https://app.example.com:443",
		"http://localhost:80",
		"https://app.example.com:0",
		"https://app.example.com:65536",
		"https://app.example.com:0443",
		"https://",
		"ftp://app.example.com",
		"https://{tenant}.{tenant}.example.com",
		"https://x{tenant}.example.com",
		"https://{other}.example.com",
		"https://app .example.com",
		`https://app.example.com\`,
		"https://app%2eexample.com",
		"https://-app.example.com",
		"https://app..example.com",
		"https://[fe80::1%25eth0]",
		"javascript:alert(1)",
	}
	for _, o := range good {
		c := validConfig()
		c.PublicOrigin = o
		_, errs := validate(t, &c, options())
		require.Empty(t, errs, o)
	}
	for _, o := range bad {
		c := validConfig()
		c.PublicOrigin = o
		_, errs := validate(t, &c, options())
		_ = requireOnly(t, errs, "PublicOrigin")
	}
}

func TestPathPredicate(t *testing.T) {
	good := []string{"/auth", "/a/b", "/api-v1/auth_x", "/a.b", "/~u"}
	bad := []string{"auth", "/", "/auth/", "//auth", "/a//b", "/a/./b", "/a/../b", "/..", "/a b", "/a%2fb", "/a?b", "/a#b", `/a\b`, "/a\x00"}
	for _, p := range good {
		c := validConfig()
		c.BasePath = p
		_, errs := validate(t, &c, options())
		require.Empty(t, errs, p)
	}
	for _, p := range bad {
		c := validConfig()
		c.BasePath = p
		_, errs := validate(t, &c, options())
		_ = requireOnly(t, errs, "BasePath")
	}
}

func TestBoundMax(t *testing.T) {
	c := validConfig()
	c.Policy.RecheckEvery = 16 * time.Minute
	_, errs := validate(t, &c, options())
	_ = requireOnly(t, errs, "Policy.RecheckEvery")

	c = validConfig()
	c.Policy.RecheckEvery = 15 * time.Minute
	_, errs = validate(t, &c, options())
	require.Empty(t, errs)

	c = validConfig()
	c.Policy.MaxLifetime = 2161 * time.Hour
	_, errs = validate(t, &c, options())
	_ = requireField(t, errs, "Policy.MaxLifetime")
}

func TestNegativeDurationIsRejected(t *testing.T) {
	c := validConfig()
	c.Policy.RecheckEvery = -time.Second
	_, errs := validate(t, &c, options())
	_ = requireOnly(t, errs, "Policy.RecheckEvery")
}

func TestRaisedBoundOnlyRaises(t *testing.T) {
	o := options()
	o.Raised = map[string]time.Duration{"Policy.MaxLifetime": 9600 * time.Hour}
	c := validConfig()
	c.Policy.MaxLifetime = 3000 * time.Hour
	_, errs := validate(t, &c, o)
	require.Empty(t, errs)

	c.Policy.MaxLifetime = 9601 * time.Hour
	_, errs = validate(t, &c, o)
	_ = requireField(t, errs, "Policy.MaxLifetime")

	o.Raised = map[string]time.Duration{"Policy.MaxLifetime": time.Hour}
	c = validConfig()
	_, errs = validate(t, &c, o)
	require.Empty(t, errs, "a raised bound lower than the tag never tightens the default")
}

func TestBoundLE(t *testing.T) {
	c := validConfig()
	c.Policy.IdleTimeout = 721 * time.Hour
	_, errs := validate(t, &c, options())
	_ = requireOnly(t, errs, "Policy.IdleTimeout")

	c = validConfig()
	c.Policy.IdleTimeout = 2 * time.Hour
	c.Policy.MaxLifetime = time.Hour
	_, errs = validate(t, &c, options())
	_ = requireOnly(t, errs, "Policy.IdleTimeout")
}

func TestModuleDependencyRequiresOnlyWhenEnabled(t *testing.T) {
	c := validConfig()
	c.Email = nil
	_, errs := validate(t, &c, options())
	e := requireOnly(t, errs, "Email")
	require.Contains(t, e.Problem, "Password")

	c = validConfig()
	c.Email = nil
	c.Modules = modules{Passkey: &passkeyModule{DisplayName: "App"}, LoginCode: &loginCodeModule{SMS: true}}
	_, errs = validate(t, &c, options())
	require.Empty(t, errs, "LoginCode without Email does not need a mailer")

	c.Modules.LoginCode.Email = true
	_, errs = validate(t, &c, options())
	e = requireOnly(t, errs, "Email")
	require.Contains(t, e.Problem, "LoginCode.Email")

	c = validConfig()
	c.Email = nil
	c.Modules.Password = nil
	c.Modules.Passkey = &passkeyModule{DisplayName: "App"}
	c.Modules.Verification = &verificationModule{Email: true}
	_, errs = validate(t, &c, options())
	_ = requireOnly(t, errs, "Email")
}

func TestModuleDependencyThroughSwitches(t *testing.T) {
	o := options()
	c := validConfig()
	_, errs := validate(t, &c, o)
	require.Empty(t, errs, "Sessions.JWT is off and APIKeys is nil")

	o.Switches["Sessions.JWT"] = true
	_, errs = validate(t, &c, o)
	e := requireOnly(t, errs, "Storage.Tokens")
	require.Contains(t, e.Problem, "Sessions.JWT")

	o.Switches["Sessions.JWT"] = false
	c.Modules.APIKeys = &apiKeyModule{Kinds: []string{"ci"}}
	_, errs = validate(t, &c, o)
	_ = requireOnly(t, errs, "Storage.Tokens")
}

func TestOneOfPrimary(t *testing.T) {
	c := validConfig()
	c.Modules = modules{Verification: &verificationModule{Email: true}}
	_, errs := validate(t, &c, options())
	_ = requireOnly(t, errs, "Modules")

	c.Modules.LoginCode = &loginCodeModule{}
	_, errs = validate(t, &c, options())
	_ = requireOnly(t, errs, "Modules")

	c.Modules.LoginCode.SMS = true
	_, errs = validate(t, &c, options())
	require.Empty(t, errs)
}

func TestEveryProblemIsReported(t *testing.T) {
	c := config{
		BasePath:     "x",
		ExtraOrigins: []string{""},
		Policy:       sessionPolicy{RecheckEvery: time.Hour},
		Modules:      modules{Password: &passwordModule{}},
	}
	_, errs := validate(t, &c, options())
	require.ElementsMatch(t, []string{"PublicOrigin", "BasePath", "ExtraOrigins[0]", "Storage", "Storage.Identity", "Email", "Policy.RecheckEvery"}, problemFields(errs))
	for _, e := range errs {
		require.NotEmpty(t, e.Problem)
		require.Contains(t, e.Error(), e.Field)
	}
}

func TestValidateNeedsAPointerToAStruct(t *testing.T) {
	_, errs := configcheck.Validate(validConfig(), options())
	require.Len(t, errs, 1)
	_, errs = configcheck.Validate(nil, options())
	require.Len(t, errs, 1)
	var nilCfg *config
	_, errs = configcheck.Validate(nilCfg, options())
	require.Len(t, errs, 1)
	s := "x"
	_, errs = configcheck.Validate(&s, options())
	require.Len(t, errs, 1)
}

func TestDefaultMustMatchTheFieldType(t *testing.T) {
	o := options()
	o.Defaults["basepath"] = func(*configcheck.Resolved) any { return 42 }
	c := validConfig()
	_, errs := validate(t, &c, o)
	_ = requireOnly(t, errs, "BasePath")

	o.Defaults["basepath"] = func(*configcheck.Resolved) any { return nil }
	c = validConfig()
	_, errs = validate(t, &c, o)
	_ = requireOnly(t, errs, "BasePath")

	o.Defaults["basepath"] = func(*configcheck.Resolved) any { return "" }
	c = validConfig()
	_, errs = validate(t, &c, o)
	_ = requireOnly(t, errs, "BasePath")
}

func TestDefaultedValueStillPassesPredicates(t *testing.T) {
	o := options()
	o.Defaults["basepath"] = func(*configcheck.Resolved) any { return "auth/" }
	c := validConfig()
	_, errs := validate(t, &c, o)
	_ = requireOnly(t, errs, "BasePath")
}
