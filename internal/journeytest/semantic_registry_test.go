package journeytest_test

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/journeytest"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/limiter"
)

type leaf struct {
	path string
	typ  reflect.Type
	tag  reflect.StructTag
}

var (
	ackType         = reflect.TypeFor[*egauth.Ack]()
	insecureType    = reflect.TypeFor[egauth.InsecureOptOuts]()
	durationType    = reflect.TypeFor[time.Duration]()
	tenancyType     = reflect.TypeFor[egauth.Tenancy]()
	backendType     = reflect.TypeFor[egauth.SessionBackend]()
	proxyType       = reflect.TypeFor[egauth.ProxyPolicy]()
	adminType       = reflect.TypeFor[egauth.AdminPolicy]()
	claimsType      = reflect.TypeFor[egauth.ClaimsSource[journeytest.Claims]]()
	limiterType     = reflect.TypeFor[limiter.Limiter]()
	policyType      = reflect.TypeFor[passwords.Policy]()
	breachType      = reflect.TypeFor[passwords.BreachChecker]()
	externalsType   = reflect.TypeFor[[]egauth.ExternalFactor]()
	extraOrigins    = reflect.TypeFor[[]string]()
	configType      = reflect.TypeFor[egauth.Config[journeytest.Claims]]()
	exportedPackage = "egauth"
)

func leavesOf(t reflect.Type, prefix string) []leaf {
	var out []leaf
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		path := f.Name
		if prefix != "" {
			path = prefix + "." + f.Name
		}
		ft := f.Type
		switch {
		case ft == insecureType:
			out = append(out, leaf{path: path, typ: ft, tag: f.Tag})
		case ft.Kind() == reflect.Struct && ft != reflect.TypeFor[time.Time]() && ft.PkgPath() != "":
			if isOpaqueStruct(ft) {
				out = append(out, leaf{path: path, typ: ft, tag: f.Tag})
				continue
			}
			out = append(out, leavesOf(ft, path)...)
		case ft.Kind() == reflect.Pointer && ft.Elem().Kind() == reflect.Struct && ft != ackType:
			out = append(out, leavesOf(ft.Elem(), path)...)
		case ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct && ft.Elem().PkgPath() != "" && !isOpaqueStruct(ft.Elem()):
			out = append(out, leavesOf(ft.Elem(), path+"[]")...)
		default:
			out = append(out, leaf{path: path, typ: ft, tag: f.Tag})
		}
	}
	return out
}

func isOpaqueStruct(t reflect.Type) bool {
	for i := range t.NumField() {
		if t.Field(i).IsExported() {
			return false
		}
	}
	return true
}

func fieldByPath(root reflect.Value, path string) reflect.Value {
	v := root
	for _, seg := range strings.Split(path, ".") {
		for v.Kind() == reflect.Pointer {
			if v.IsNil() {
				v.Set(reflect.New(v.Type().Elem()))
			}
			v = v.Elem()
		}
		name, element := strings.CutSuffix(seg, "[]")
		v = v.FieldByName(name)
		if element {
			if v.Len() == 0 {
				v.Set(reflect.MakeSlice(v.Type(), 1, 1))
			}
			v = v.Index(0)
		}
	}
	return v
}

type class uint8

const (
	classWiring class = iota + 1
	classText
	classOrigin
)

var classified = map[string]class{
	"PublicOrigin": classOrigin, "BasePath": classText, "Audiences": classOrigin,
	"KEK": classWiring, "Events": classWiring, "Email": classWiring, "SMS": classWiring, "Outbound": classWiring,
	"Storage.Identity": classWiring, "Storage.Ceremonies": classWiring, "Storage.Deployment": classWiring,
	"Storage.Tokens": classWiring, "Storage.Sessions": classWiring, "Storage.MFA": classWiring,
	"Storage.Passkeys": classWiring, "Storage.Federation": classWiring, "Storage.Keys": classWiring,
	"Pages.Login": classText, "Pages.AfterLogin": classText, "Pages.MFA": classText, "Pages.Reauth": classText,
	"Pages.Error": classText, "Pages.ConfirmRegistration": classText, "Pages.MagicLink": classText,
	"Pages.PasswordReset": classText, "Pages.VerifyEmail": classText, "Pages.ConfirmEmailChange": classText,
	"Pages.SecurityRevert":        classText,
	"Modules.Passkey.DisplayName": classText, "Modules.MFA.TOTPIssuer": classText,
	"Modules.APIKeys.Kinds": classText, "Modules.APIKeys.Prefix": classText,
	"Modules.OAuth.Providers[].Name": classWiring, "Modules.OAuth.Providers[].ClientID": classWiring,
	"Modules.OAuth.Providers[].ClientSecret": classWiring, "Modules.OAuth.Providers[].AuthURL": classWiring,
	"Modules.OAuth.Providers[].TokenURL": classWiring, "Modules.OAuth.Providers[].UserInfoURL": classWiring,
	"Modules.OAuth.Providers[].Issuer": classWiring, "Modules.OAuth.Providers[].JWKSURL": classWiring,
	"Modules.OAuth.Providers[].Scopes": classText, "Modules.OAuth.Providers[].Domains": classText,
	"Hooks.BeforeEndpoint": classWiring, "Hooks.AccountDeleted": classWiring, "Hooks.TenantErased": classWiring,
}

type variantKind string

const (
	vBool    variantKind = "bool"
	vEnum    variantKind = "enum"
	vFlag    variantKind = "opt-out"
	vNumeric variantKind = "numeric"
	vTime    variantKind = "duration"
	vPolicy  variantKind = "policy"
	vOrigins variantKind = "origins"
)

type variant struct {
	key    string
	kind   variantKind
	golden bool
	opts   []change
}

func (v variant) short() bool {
	return v.kind == vBool || v.kind == vEnum || v.kind == vFlag
}

type change = func(*journeytest.Settings)

func configOpt(f func(*egauth.Config[journeytest.Claims])) change {
	return func(s *journeytest.Settings) { *s = s.Configure(f) }
}

func tenancy(t journeytest.Tenancy) change {
	return func(s *journeytest.Settings) { s.Tenancy = t }
}

func backend(b journeytest.Backend) change {
	return func(s *journeytest.Settings) { s.Backend = b }
}

func settingsOf(changes []change) journeytest.Settings {
	var s journeytest.Settings
	for _, c := range changes {
		c(&s)
	}
	return s
}

func setter(path string, val reflect.Value) change {
	return configOpt(func(c *egauth.Config[journeytest.Claims]) {
		fieldByPath(reflect.ValueOf(c).Elem(), path).Set(val)
	})
}

type allowAll struct{ limiter.Limiter }

func (allowAll) Allow(context.Context, limiter.Key) (limiter.Decision, error) {
	return limiter.Decision{Allowed: true}, nil
}

type acceptAll struct{}

func (acceptAll) Verify(context.Context, string) error { return nil }

type alwaysClean struct{}

func (alwaysClean) IsBreached(context.Context, string) (bool, error) { return false, nil }

type allRoles struct{}

func (allRoles) ClaimsFor(context.Context, principal.Subject) (egauth.AppClaims[journeytest.Claims], error) {
	return egauth.AppClaims[journeytest.Claims]{Roles: []string{journeytest.AdminRole, "user"}, Scopes: []string{"items:read", "items:write"}}, nil
}

type acceptEveryone struct{}

func (acceptEveryone) Name() string { return journeytest.ExternalName }

func (acceptEveryone) Verify(_ context.Context, r egauth.ExternalRequest) (egauth.ExternalIdentity, error) {
	return egauth.ExternalIdentity{ExternalID: "any-" + r.Identifier, Email: r.Identifier, EmailVerified: true}, nil
}

type namedValue struct {
	name   string
	value  any
	golden bool
}

var enumRegistry = map[reflect.Type][]namedValue{
	reflect.TypeFor[egauth.RegistrationMode]():      {{"Open", egauth.RegistrationOpen, true}, {"InviteOnly", egauth.RegistrationInviteOnly, false}},
	reflect.TypeFor[egauth.AttestationPolicy]():     {{"None", egauth.AttestationNone, true}},
	reflect.TypeFor[egauth.Transport]():             {{"Cookies", egauth.Cookies, false}, {"Bearer", egauth.Bearer, false}, {"CookiesAndBearer", egauth.CookiesAndBearer, true}},
	reflect.TypeFor[federation.EmailVerification](): {{"Never", federation.Never, false}, {"ClaimBased", federation.ClaimBased, false}, {"Always", federation.Always, true}},
	reflect.TypeOf(egauth.RememberUserChoice):       {{"UserChoice", egauth.RememberUserChoice, true}, {"Always", egauth.RememberAlways, false}, {"Never", egauth.RememberNever, false}},
}

func constructorVariants(l leaf) ([]variant, bool) {
	key := func(name string) string { return l.path + "=" + name }
	switch l.typ {
	case proxyType:
		return []variant{
			{key: key("DirectClients"), kind: vEnum, golden: true},
			{key: key("TrustedProxies"), kind: vEnum, opts: []change{setter(l.path, reflect.ValueOf(egauth.TrustedProxies(netip.MustParsePrefix("198.51.0.0/16"))))}},
		}, true
	case tenancyType:
		return []variant{
			{key: key("TenantBySubdomain"), kind: vEnum, golden: true},
			{key: key("SingleTenant"), kind: vEnum, opts: []change{tenancy(journeytest.Single)}},
			{key: key("TenantFromRequest"), kind: vEnum, opts: []change{tenancy(journeytest.FromRequest)}},
		}, true
	case backendType:
		return []variant{
			{key: key("JWT"), kind: vEnum, golden: true},
			{key: key("Stateful"), kind: vEnum, opts: []change{backend(journeytest.Stateful)}},
			{key: key("JWTTenantKeys"), kind: vEnum, opts: []change{setter(l.path, reflect.ValueOf(egauth.JWT(egauth.TenantKeys())))}},
		}, true
	case adminType:
		return []variant{
			{key: key("RoleAdmin"), kind: vEnum, golden: true},
			{key: key("RoleAdminOther"), kind: vEnum, opts: []change{setter(l.path, reflect.ValueOf(egauth.RoleAdmin("ops")))}},
			{key: key("SelfServiceOnly"), kind: vEnum, opts: []change{setter(l.path, reflect.ValueOf(egauth.SelfServiceOnly()))}},
		}, true
	}
	return nil, false
}

func policyVariants(l leaf) ([]variant, bool) {
	key := func(name string) string { return l.path + "=" + name }
	switch l.typ {
	case claimsType:
		return []variant{{key: key("AllRoles"), kind: vPolicy, opts: []change{setter(l.path, reflect.ValueOf(egauth.ClaimsSource[journeytest.Claims](allRoles{})))}}}, true
	case limiterType:
		return []variant{{key: key("AllowAll"), kind: vPolicy, opts: []change{configOpt(func(c *egauth.Config[journeytest.Claims]) {
			stub := allowAll{c.Storage.Limiter}
			if l.path == "Storage.Limiter" {
				c.Storage.Limiter = stub
				return
			}
			c.RateLimit = stub
		})}}}, true
	case policyType:
		return []variant{{key: key("AcceptAll"), kind: vPolicy, opts: []change{setter(l.path, reflect.ValueOf(passwords.Policy(acceptAll{})))}}}, true
	case breachType:
		return []variant{{key: key("AlwaysClean"), kind: vPolicy, opts: []change{setter(l.path, reflect.ValueOf(passwords.BreachChecker(alwaysClean{})))}}}, true
	case externalsType:
		return []variant{{key: key("AcceptEveryone"), kind: vPolicy, opts: []change{setter(l.path, reflect.ValueOf([]egauth.ExternalFactor{acceptEveryone{}}))}}}, true
	case extraOrigins:
		if l.path == "ExtraOrigins" {
			return []variant{{key: key("EvilOrigin"), kind: vOrigins, opts: []change{setter(l.path, reflect.ValueOf([]string{evil}))}}}, true
		}
	}
	return nil, false
}

func durationBound(tag reflect.StructTag, current map[string]time.Duration) (time.Duration, bool) {
	for _, part := range strings.Split(tag.Get("egauth"), ",") {
		spec, ok := strings.CutPrefix(part, "bound=")
		if !ok {
			continue
		}
		op, arg, _ := strings.Cut(spec, ":")
		switch op {
		case "max":
			d, err := time.ParseDuration(arg)
			return d, err == nil
		case "le":
			d, ok := current[arg]
			return d, ok
		}
	}
	return 0, false
}

var defaultDurations = map[string]time.Duration{"MaxLifetime": 720 * time.Hour}

func durationVariants(l leaf) []variant {
	bound, ok := durationBound(l.tag, defaultDurations)
	if !ok {
		return nil
	}
	set := func(d time.Duration) change { return setter(l.path, reflect.ValueOf(d)) }
	return []variant{
		{key: l.path + "=0", kind: vTime, golden: true, opts: []change{set(0)}},
		{key: l.path + "=bound", kind: vTime, opts: []change{set(bound)}},
		{key: l.path + "=bound+1", kind: vTime, opts: []change{set(bound + 1)}},
	}
}

func numericVariants(l leaf) []variant {
	var lo, hi reflect.Value
	switch l.typ.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		bits := l.typ.Bits()
		hiv := int64(1)<<(bits-1) - 1
		lo, hi = reflect.New(l.typ).Elem(), reflect.New(l.typ).Elem()
		lo.SetInt(-hiv - 1)
		hi.SetInt(hiv)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		lo, hi = reflect.New(l.typ).Elem(), reflect.New(l.typ).Elem()
		hi.SetUint(^uint64(0) >> (64 - l.typ.Bits()))
	default:
		return nil
	}
	return []variant{
		{key: l.path + "=min", kind: vNumeric, opts: []change{setter(l.path, lo)}},
		{key: l.path + "=max", kind: vNumeric, opts: []change{setter(l.path, hi)}},
	}
}

func boolVariant(l leaf) variant {
	return variant{key: l.path + "=flipped", kind: vBool, opts: []change{configOpt(func(c *egauth.Config[journeytest.Claims]) {
		f := fieldByPath(reflect.ValueOf(c).Elem(), l.path)
		f.SetBool(!f.Bool())
	})}}
}

func enumVariants(l leaf) ([]variant, bool) {
	vals, ok := enumRegistry[l.typ]
	if !ok {
		return nil, false
	}
	var out []variant
	for _, nv := range vals {
		out = append(out, variant{key: l.path + "=" + nv.name, kind: vEnum, golden: nv.golden, opts: []change{setter(l.path, reflect.ValueOf(nv.value))}})
	}
	return out, true
}

func optOutVariants() []variant {
	var out []variant
	t := insecureType
	for i := range t.NumField() {
		f := t.Field(i)
		name := f.Name
		ack := egauth.Acknowledge("g7b semantic opt-out guard")
		var val reflect.Value
		var extra change
		switch f.Type {
		case ackType:
			val = reflect.ValueOf(ack)
		case reflect.TypeFor[*egauth.SharedCookieDomain]():
			val = reflect.ValueOf(&egauth.SharedCookieDomain{Domain: journeytest.BaseDomain, Ack: ack})
			extra = tenancy(journeytest.FromRequest)
		case reflect.TypeFor[*egauth.OutboundAllowance]():
			val = reflect.ValueOf(&egauth.OutboundAllowance{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Ack: ack})
		default:
			out = append(out, variant{key: "Insecure." + name + "=unclassified", kind: vFlag})
			continue
		}
		opts := []change{setter("Insecure."+name, val)}
		if extra != nil {
			opts = append([]change{extra}, opts...)
		}
		out = append(out, variant{key: "Insecure." + name + "=set", kind: vFlag, opts: opts})
	}
	return out
}

func variantsOf(l leaf) ([]variant, bool) {
	if l.typ == insecureType {
		return optOutVariants(), true
	}
	if vs, ok := constructorVariants(l); ok {
		return vs, true
	}
	if vs, ok := policyVariants(l); ok {
		return vs, true
	}
	if vs, ok := enumVariants(l); ok {
		return vs, true
	}
	switch {
	case l.typ == durationType:
		vs := durationVariants(l)
		return vs, len(vs) > 0
	case l.typ.Kind() == reflect.Bool:
		return []variant{boolVariant(l)}, true
	}
	if l.typ.PkgPath() != "" {
		return nil, false
	}
	if vs := numericVariants(l); vs != nil {
		return vs, true
	}
	return nil, false
}
