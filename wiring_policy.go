package egauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/JLugagne/egauth/internal/clientaddr"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/issuance"
	"github.com/JLugagne/egauth/internal/outbound"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/ceremony"
)

const (
	maxTenantLabel   = 63
	claimsWireDomain = "egauth/claims/v1"
)

type policies struct {
	cookies     cookie.Policy
	clients     *clientaddr.Resolver
	trusted     csrf.Origins
	origins     origins
	outbound    outbound.Config
	transports  httpx.Transports
	tenants     httpx.TenantResolver
	pages       issuance.Pages
	loginPage   redirect.Target
	fingerprint string
}

func buildPolicies[C any](cfg *Config[C], v *problems) *policies {
	p := &policies{fingerprint: claimsFingerprint[C]()}
	p.origins = origins{public: cfg.PublicOrigin, extra: cfg.ExtraOrigins}
	var err error
	if p.cookies, err = cookie.NewPolicy(cookie.Options{PublicOrigin: cfg.PublicOrigin, SharedDomain: sharedDomain(cfg)}); err != nil {
		v.add("PublicOrigin", err.Error())
	}
	p.clients = buildClients(cfg, v)
	if p.trusted, err = csrf.NewOrigins(cfg.PublicOrigin, cfg.ExtraOrigins); err != nil {
		v.add("ExtraOrigins", err.Error())
	}
	p.outbound = buildOutbound(cfg, v)
	p.transports = transportsOf(cfg.Transport)
	p.tenants = buildTenants(cfg, v)
	p.pages, p.loginPage = buildPages(cfg, v)
	return p
}

func sharedDomain[C any](cfg *Config[C]) string {
	if s := cfg.Insecure.SharedCookieDomain; s != nil {
		return s.Domain
	}
	return ""
}

func buildClients[C any](cfg *Config[C], v *problems) *clientaddr.Resolver {
	var pol clientaddr.Policy
	spec, ok := specOf(cfg.Proxy.proxy)
	if !ok || !spec.set {
		return nil
	}
	if len(spec.trusted) == 0 {
		pol = clientaddr.Direct()
	} else {
		var err error
		if pol, err = clientaddr.Trusted(spec.trusted[0], spec.trusted[1:]...); err != nil {
			v.add("Proxy", err.Error())
			return nil
		}
	}
	r, err := clientaddr.New(pol, cfg.Events)
	if err != nil {
		v.add("Proxy", err.Error())
		return nil
	}
	return r
}

func buildOutbound[C any](cfg *Config[C], v *problems) outbound.Config {
	var out outbound.Config
	for _, a := range []struct {
		field string
		in    *OutboundAllowance
		dst   *outbound.Allowance
	}{
		{"Insecure.OutboundPrivateNetwork", cfg.Insecure.OutboundPrivateNetwork, &out.Static},
		{"Insecure.TenantOutboundPrivateNetwork", cfg.Insecure.TenantOutboundPrivateNetwork, &out.Tenant},
	} {
		if a.in == nil || len(a.in.Prefixes) == 0 {
			continue
		}
		al, err := outbound.NewAllowance(a.in.Prefixes)
		if err != nil {
			continue
		}
		*a.dst = al
	}
	if present(cfg.Outbound) {
		out.Observer = cfg.Outbound
	}
	return out
}

func transportsOf(t Transport) httpx.Transports {
	switch t {
	case Bearer:
		return httpx.BearerOnly
	case CookiesAndBearer:
		return httpx.CookiesAndBearer
	}
	return httpx.CookiesOnly
}

func buildTenants[C any](cfg *Config[C], v *problems) httpx.TenantResolver {
	spec, ok := specOf(cfg.Tenancy.tenancy)
	if !ok {
		return nil
	}
	switch spec.kind {
	case tenancySubdomain:
		r, err := httpx.TenantBySubdomain(cfg.PublicOrigin)
		if err != nil {
			v.add("PublicOrigin", err.Error())
			return nil
		}
		return r
	case tenancyRequest:
		return spec.resolver
	}
	return httpx.SingleTenant()
}

func samplePage(s string) string { return strings.ReplaceAll(s, tenantLabel, sampleTenant) }

func trustedAbsolute(public string, extra []string) []string {
	return append([]string{public}, extra...)
}

func sampleOrigins[C any](cfg *Config[C]) (redirect.Origins, error) {
	extra := make([]string, len(cfg.ExtraOrigins))
	for i, o := range cfg.ExtraOrigins {
		extra[i] = samplePage(o)
	}
	public := samplePage(cfg.PublicOrigin)
	return redirect.NewOrigins(public, trustedAbsolute(public, extra))
}

func landingPath(t redirect.Target, public string) (string, bool) {
	ref := t.String()
	if strings.HasPrefix(ref, "/") {
		return ref, true
	}
	rest, ok := strings.CutPrefix(ref, strings.ToLower(public))
	switch {
	case !ok:
		return "", false
	case rest == "":
		return "/", true
	case rest[0] == '?':
		return "/" + rest, true
	case rest[0] == '/':
		return rest, true
	}
	return "", false
}

func buildPages[C any](cfg *Config[C], v *problems) (out issuance.Pages, login redirect.Target) {
	o, err := sampleOrigins(cfg)
	if err != nil {
		return out, login
	}
	public := samplePage(cfg.PublicOrigin)
	for _, p := range []struct {
		field string
		raw   string
		dst   *string
	}{
		{"Pages.AfterLogin", cfg.Pages.AfterLogin, &out.AfterLogin},
		{"Pages.MFA", cfg.Pages.MFA, &out.MFA},
		{"Pages.Reauth", cfg.Pages.Reauth, &out.Reauth},
	} {
		if strings.TrimSpace(p.raw) == "" {
			continue
		}
		t, err := redirect.Parse(samplePage(p.raw), o)
		if err != nil {
			v.add(p.field, err.Error())
			continue
		}
		path, ok := landingPath(t, public)
		if !ok {
			v.add(p.field, "must be a path on PublicOrigin: a login lands on it through issuance, which serves no other origin")
			continue
		}
		*p.dst = path
	}
	if raw := cfg.Pages.Login; strings.TrimSpace(raw) != "" {
		t, err := redirect.Parse(samplePage(raw), o)
		if err != nil {
			v.add("Pages.Login", err.Error())
			return out, login
		}
		if strings.Contains(cfg.PublicOrigin, tenantLabel) {
			path, ok := landingPath(t, public)
			if !ok {
				v.add("Pages.Login", "under a "+tenantLabel+" public origin it must be a path or a URL on PublicOrigin")
				return out, login
			}
			if t, err = redirect.Parse(path, o); err != nil {
				v.add("Pages.Login", err.Error())
				return out, login
			}
		}
		login = t
	}
	return out, login
}

func checkNoticePath[C any](cfg *Config[C], v *problems) {
	if cfg.Pages == (Pages{}) {
		v.add("Pages.SecurityRevert", "is required: every account can hold a verified email and receives security notices")
	}
}

func checkRecoveryPage[C any](cfg *Config[C], v *problems) {
	m := cfg.Modules.Verification
	if m == nil || !m.RecoveryEmail {
		return
	}
	if strings.TrimSpace(cfg.Pages.ConfirmEmailChange) == "" && strings.TrimSpace(cfg.Pages.VerifyEmail) == "" {
		v.add("Pages.ConfirmEmailChange", "is required by Modules.Verification.RecoveryEmail: the recovery link opens it")
	}
}

func checkExtraOriginLabels[C any](cfg *Config[C], v *problems) {
	if tenancyOf(cfg.Tenancy) != tenancySubdomain {
		return
	}
	for i, o := range cfg.ExtraOrigins {
		if strings.Contains(o, tenantLabel) {
			v.add("ExtraOrigins["+strconv.Itoa(i)+"]", "a "+tenantLabel+" label is not supported: list each trusted origin exactly")
		}
	}
}

type origins struct {
	public string
	extra  []string
}

var errTenantLabel = errors.New("egauth: the tenant cannot form a host label")

func tenantHostLabel(t core.TenantID) (string, error) {
	label := t.String()
	if label == "" || len(label) > maxTenantLabel {
		return "", errTenantLabel
	}
	for i := range len(label) {
		c := label[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return "", errTenantLabel
		}
	}
	return label, nil
}

func (o origins) expand(t core.TenantID) (string, error) {
	if !strings.Contains(o.public, tenantLabel) {
		return o.public, nil
	}
	label, err := tenantHostLabel(t)
	if err != nil {
		return "", err
	}
	return strings.Replace(o.public, tenantLabel, label, 1), nil
}

func (o origins) PublicOrigin(t core.TenantID) (string, error) {
	return o.expand(t)
}

func (o origins) Origins(t core.TenantID) (redirect.Origins, error) {
	public, err := o.expand(t)
	if err != nil {
		return redirect.Origins{}, err
	}
	return redirect.NewOrigins(public, trustedAbsolute(public, o.extra))
}

type links struct {
	origins origins
	pages   Pages
}

var errNoPage = errors.New("egauth: the deployment has no page for this link kind")

func (l links) page(k ceremony.Kind) string {
	switch k {
	case ceremony.PendingRegistration:
		return l.pages.ConfirmRegistration
	case ceremony.PasswordReset:
		return l.pages.PasswordReset
	case ceremony.MagicLink:
		return l.pages.MagicLink
	case ceremony.EmailVerification:
		return l.pages.VerifyEmail
	case ceremony.EmailChange:
		return l.pages.ConfirmEmailChange
	case ceremony.RecoveryEmail:
		return firstNonBlank(l.pages.ConfirmEmailChange, l.pages.VerifyEmail)
	case ceremony.SecurityRevert:
		return l.pages.SecurityRevert
	}
	return ""
}

func firstNonBlank(values ...string) string {
	for _, s := range values {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func (l links) Link(_ context.Context, t core.TenantID, k ceremony.Kind, handle string) (string, error) {
	raw := l.page(k)
	if strings.TrimSpace(raw) == "" {
		return "", errNoPage
	}
	if strings.Contains(raw, tenantLabel) {
		label, err := tenantHostLabel(t)
		if err != nil {
			return "", err
		}
		raw = strings.ReplaceAll(raw, tenantLabel, label)
	}
	ro, err := l.origins.Origins(t)
	if err != nil {
		return "", err
	}
	target, err := redirect.Parse(raw, ro)
	if err != nil {
		return "", err
	}
	public, err := l.origins.expand(t)
	if err != nil {
		return "", err
	}
	ref := target.String()
	if strings.HasPrefix(ref, "/") {
		ref = public + ref
	}
	u, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(routes.FieldToken, handle)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func claimsFingerprint[C any]() string {
	t := reflect.TypeFor[C]()
	sum := sha256.Sum256([]byte(claimsWireDomain + "\x00" + t.PkgPath() + "\x00" + t.String()))
	return hex.EncodeToString(sum[:])
}
