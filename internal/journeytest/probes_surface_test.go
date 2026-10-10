package journeytest_test

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/journeytest"
	"github.com/JLugagne/egauth/internal/routes"
)

func (e *env) userRouteCSRFProbes() []journeytest.Probe {
	var ps []journeytest.Probe
	forbidden := refused(http.StatusForbidden, "cross_site_request")
	cookie := func(r *journeytest.Req) {
		r.NoJar, r.Cookies = true, []*http.Cookie{{Name: "__Host-access_token", Value: "junk"}}
	}
	c := e.w.NewClient()
	add := func(name string, t target, want string, mut func(*journeytest.Req), expect func(target, *journeytest.Resp, observed) (string, bool)) {
		ps = append(ps, journeytest.Probe{
			Category: "csrf", Name: "csrf/" + name + "/" + t.label(), Want: want,
			Run: func() (string, bool) {
				r, o := e.hit(c, t, cookie, mut)
				return expect(t, r, o)
			},
		})
	}
	for _, t := range e.where(func(t target) bool { return t.kind == kProtect || t.kind == kOptional }) {
		if t.unsafeMethod() {
			add("user-cross-origin-with-cookie", t, "403 cross_site_request", func(r *journeytest.Req) { r.Header = http.Header{"Origin": {evil}} }, forbidden)
			add("user-null-origin-with-cookie", t, "403 cross_site_request", func(r *journeytest.Req) { r.Header = http.Header{"Origin": {"null"}} }, forbidden)
			add("user-no-origin-no-referer-with-cookie", t, "403 cross_site_request", func(r *journeytest.Req) { r.NoOrig = true }, forbidden)
			add("user-same-site-fetch-with-cookie", t, "403 cross_site_request", func(r *journeytest.Req) { r.Header = http.Header{"Sec-Fetch-Site": {"same-site"}} }, forbidden)
			continue
		}
		fetch := func(r *journeytest.Req) {
			r.Header = http.Header{"Sec-Fetch-Site": {"cross-site"}, "Sec-Fetch-Mode": {"cors"}}
		}
		if t.kind == kProtect {
			add("user-cross-site-get-with-cookie", t, "403 cross_site_request", fetch, forbidden)
			continue
		}
	}
	ps = append(ps, e.validCookieCSRFProbes()...)
	return ps
}

func (e *env) validCookieCSRFProbes() []journeytest.Probe {
	if !e.cookiesAllowed() {
		return nil
	}
	var ps []journeytest.Probe
	session := lazy(func() *journeytest.Client { c, _ := e.loggedIn("csrfcookie", false); return c })
	crossSite := func(r *journeytest.Req) {
		r.Header = http.Header{"Sec-Fetch-Site": {"cross-site"}, "Sec-Fetch-Mode": {"cors"}}
	}
	sameOrigin := func(r *journeytest.Req) { r.Header = http.Header{"Sec-Fetch-Site": {"same-origin"}} }
	add := func(name string, t target, want string, mut func(*journeytest.Req), expect func(target, *journeytest.Resp, observed) (string, bool), control bool) {
		ps = append(ps, journeytest.Probe{
			Category: "csrf", Name: "csrf/" + name + "/" + t.label(), Want: want, Control: control,
			Run: func() (string, bool) {
				r, o := e.hit(session(), t, mut)
				return expect(t, r, o)
			},
		})
	}
	authenticated := func(_ target, r *journeytest.Resp, o observed) (string, bool) {
		return got(r, o), r.Status == http.StatusOK && o.ran && !o.anon
	}
	for _, t := range e.where(func(t target) bool { return t.kind == kOptional && !t.unsafeMethod() }) {
		add("user-cross-site-get-with-valid-cookie", t, "anonymous principal", crossSite, anonymousOnly, false)
		add("user-same-origin-get-with-valid-cookie", t, "authenticated principal", sameOrigin, authenticated, true)
	}
	for _, t := range e.where(func(t target) bool {
		return t.kind == kProtect && t.path == journeytest.ProtectRoute && !t.unsafeMethod()
	}) {
		add("user-cross-site-get-with-valid-cookie", t, "403 cross_site_request", crossSite, refused(http.StatusForbidden, "cross_site_request"), false)
		add("user-same-origin-get-with-valid-cookie", t, "200", sameOrigin, served, true)
	}
	return ps
}

const evil = journeytest.ForeignOrigin

func (e *env) tenancyProbes() []journeytest.Probe {
	var ps []journeytest.Probe
	if e.w.Settings.Tenancy == journeytest.Single {
		return ps
	}
	c := e.w.NewClient()
	for _, host := range []string{journeytest.BaseDomain, "acme." + journeytest.BaseDomain + ".evil.test", "bad_label." + journeytest.BaseDomain} {
		for _, t := range e.where(func(t target) bool { return t.kind != kPublic }) {
			ps = append(ps, journeytest.Probe{
				Category: "tenancy", Name: "tenancy/unresolvable-tenant/" + host + "/" + t.label(), Want: "401",
				Run: func() (string, bool) {
					r, o := e.hit(c, t, func(r *journeytest.Req) {
						r.Host, r.NoJar = host, true
						r.Header = http.Header{"Origin": {"https://" + host}}
					})
					return refused(http.StatusUnauthorized, "")(t, r, o)
				},
			})
		}
	}
	ps = append(ps, e.credentialedTenancyProbes()...)
	ps = append(ps, e.crossTenantHandles()...)
	return ps
}

func (e *env) credentialedTenancyProbes() []journeytest.Probe {
	var ps []journeytest.Probe
	bearer := !e.cookiesAllowed()
	session := lazy(func() *journeytest.Client { c, _ := e.loggedIn("tenancycred", bearer); return c })
	for _, host := range []string{journeytest.BaseDomain, "acme." + journeytest.BaseDomain + ".evil.test", "bad_label." + journeytest.BaseDomain} {
		for _, t := range e.where(func(t target) bool { return t.kind != kPublic && !t.meta.EndsSession }) {
			ps = append(ps, journeytest.Probe{
				Category: "tenancy", Name: "tenancy/valid-credential-on-unresolvable-tenant/" + transportName(bearer) + "/" + host + "/" + t.label(), Want: "401",
				Run: func() (string, bool) {
					r, o := e.hit(session(), t, func(r *journeytest.Req) {
						r.Host = host
						r.Header = http.Header{"Origin": {"https://" + host}}
					})
					return refused(http.StatusUnauthorized, "")(t, r, o)
				},
			})
		}
	}
	return ps
}

func (e *env) crossTenantHandles() []journeytest.Probe {
	w := e.w
	other := "globex." + journeytest.BaseDomain
	onHost := func(host string, r journeytest.Req) journeytest.Req {
		r.Host = host
		h := r.Header.Clone()
		if h == nil {
			h = http.Header{}
		}
		h.Set("Origin", "https://"+host)
		r.Header = h
		return r
	}
	var ps []journeytest.Probe
	if lc := w.Config.Modules.LoginCode; lc != nil && lc.Email {
		ps = append(ps, e.codeHandleProbe("email", onHost, other, func(c *journeytest.Client) map[string]any {
			email, _ := e.user("codetenant", false)
			n := w.MailCount("LoginCode") + 1
			begun := c.Post(egauth.PathCodeRequest, map[string]any{egauth.FieldIdentifier: email})
			return e.codeFields(c, begun, w.WaitMail("LoginCode", n).Code)
		}))
	}
	if lc := w.Config.Modules.LoginCode; lc != nil && lc.SMS && e.serves(routes.PhoneVerifyRequest) {
		ps = append(ps, e.codeHandleProbe("sms", onHost, other, func(c *journeytest.Client) map[string]any {
			phone := e.verifiedPhone()
			n := w.TextCount("LoginCode") + 1
			begun := c.Post(egauth.PathCodeRequest, map[string]any{egauth.FieldIdentifier: phone})
			return e.codeFields(c, begun, w.WaitText("LoginCode", n).Code)
		}))
	}
	if w.Config.Modules.MFA != nil && e.bearerAllowed() {
		ps = append(ps, journeytest.Probe{
			Category: "tenancy", Name: "tenancy/mfa-flow-handle-of-another-tenant", Want: "401, then the flow still completes for its own tenant",
			Run: func() (string, bool) {
				acct := w.MFAUser("flowtenant")
				c := w.NewClient()
				flow := c.LoginPassword(journeytest.Credentials{Email: acct.Email, Password: journeytest.Password}, true).Field("flow")
				fields := map[string]any{egauth.FieldFlow: flow, egauth.FieldFactor: "totp", egauth.FieldCode: journeytest.TOTPCode(acct.Secret, w.Clock.Now())}
				wrong := c.Do(onHost(other, journeytest.Req{Method: http.MethodPost, Path: "/auth" + egauth.PathMFAChallenge, JSON: fields, Remote: c.FreshRemote()}))
				right := c.Post(egauth.PathMFAChallenge, fields)
				return journeytest.Describe(wrong) + " then " + journeytest.Describe(right), wrong.Status == http.StatusUnauthorized && !wrong.Established() && right.Established()
			},
		})
	}
	ps = append(ps, e.crossTenantTokens(onHost, other)...)
	return ps
}

func refusedAsUnknown(r *journeytest.Resp) bool {
	return r.Status == http.StatusUnauthorized || (r.Status == http.StatusBadRequest && r.Code() == "invalid_token")
}

func tokenOf(link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return u.Query().Get("token")
}

func (e *env) crossTenantTokens(onHost func(string, journeytest.Req) journeytest.Req, other string) []journeytest.Probe {
	w := e.w
	var ps []journeytest.Probe
	add := func(name string, run func() (wrong, right *journeytest.Resp, rightHeld func(*journeytest.Resp) bool)) {
		ps = append(ps, journeytest.Probe{
			Category: "tenancy", Name: "tenancy/" + name + "-of-another-tenant", Want: "401 or the library's 400 invalid_token, then the record still verifies for its own tenant",
			Run: func() (string, bool) {
				wrong, right, rightHeld := run()
				return journeytest.Describe(wrong) + " then " + journeytest.Describe(right),
					refusedAsUnknown(wrong) && !wrong.Established() && rightHeld(right)
			},
		})
	}
	established := func(r *journeytest.Resp) bool { return r.Established() }
	ok := func(r *journeytest.Resp) bool { return r.Status == http.StatusOK }
	consume := func(c *journeytest.Client, path string, fields map[string]any) (*journeytest.Resp, *journeytest.Resp) {
		wrong := c.Do(onHost(other, journeytest.Req{Method: http.MethodPost, Path: "/auth" + path, JSON: fields, Remote: c.FreshRemote()}))
		return wrong, c.Post(path, fields)
	}
	if w.Config.Modules.MagicLink != nil {
		add("magic-link-token", func() (*journeytest.Resp, *journeytest.Resp, func(*journeytest.Resp) bool) {
			email, _ := e.user("magictenant", false)
			n := w.MailCount("MagicLink") + 1
			c := w.NewClient()
			begun := c.Post(egauth.PathMagicLinkRequest, map[string]any{egauth.FieldIdentifier: email})
			fields := map[string]any{egauth.FieldToken: tokenOf(w.WaitMail("MagicLink", n).Link)}
			if bind := c.Bind(begun); bind != "" && !e.cookiesAllowed() {
				fields[egauth.FieldBind] = bind
			}
			wrong, right := consume(c, egauth.PathMagicLink, fields)
			return wrong, right, established
		})
	}
	if w.Config.Modules.Password != nil {
		add("password-reset-token", func() (*journeytest.Resp, *journeytest.Resp, func(*journeytest.Resp) bool) {
			email, _ := e.user("resettenant", false)
			n := w.MailCount("PasswordResetLink") + 1
			c := w.NewClient()
			c.Post(egauth.PathPasswordForgot, map[string]any{egauth.FieldIdentifier: email})
			fields := map[string]any{egauth.FieldToken: tokenOf(w.WaitMail("PasswordResetLink", n).Link), egauth.FieldNewPassword: "tapir-granite-velvet-orbit-29"}
			wrong, right := consume(c, egauth.PathPasswordReset, fields)
			return wrong, right, ok
		})
		if w.Config.Modules.Password.Registration != egauth.RegistrationInviteOnly {
			add("registration-token", func() (*journeytest.Resp, *journeytest.Resp, func(*journeytest.Resp) bool) {
				email := w.FreshEmail("regtenant")
				n := w.MailCount("RegistrationLink") + 1
				c := w.NewClient()
				c.Post(egauth.PathRegister, map[string]any{egauth.FieldEmail: email, egauth.FieldIdentifier: email, egauth.FieldPassword: "tapir-granite-velvet-orbit-29"})
				fields := map[string]any{egauth.FieldToken: tokenOf(w.WaitMail("RegistrationLink", n).Link)}
				wrong, right := consume(c, egauth.PathRegisterConfirm, fields)
				return wrong, right, func(r *journeytest.Resp) bool { return r.Status < http.StatusBadRequest }
			})
		}
	}
	for _, a := range []struct {
		name, mail, request, confirm, field string
		registry                            string
	}{
		{"email-change-token", "EmailChangeLink", egauth.PathEmailChange, egauth.PathEmailChangeConfirm, egauth.FieldEmail, routes.EmailChange},
		{"recovery-email-token", "RecoveryEmailLink", egauth.PathRecoveryEmail, egauth.PathRecoveryEmailConfirm, egauth.FieldEmail, routes.RecoveryEmail},
	} {
		if !e.serves(a.registry) {
			continue
		}
		add(a.name, func() (*journeytest.Resp, *journeytest.Resp, func(*journeytest.Resp) bool) {
			c, _ := e.loggedIn("accounttenant", !e.cookiesAllowed())
			n := w.MailCount(a.mail) + 1
			c.Post(a.request, map[string]any{a.field: w.FreshEmail("newaddress")})
			wrong, right := consume(c, a.confirm, map[string]any{egauth.FieldToken: tokenOf(w.WaitMail(a.mail, n).Link)})
			return wrong, right, ok
		})
	}
	if w.Config.Modules.OAuth != nil && e.bearerAllowed() {
		ps = append(ps, journeytest.Probe{
			Category: "tenancy", Name: "tenancy/oauth-exchange-handle-of-another-tenant", Want: "401 or the library's 400 invalid_token, then the exchange still completes for its own tenant",
			Run: func() (string, bool) {
				o, built := e.bearerOAuthCeremony()
				if !built {
					return o.got, o.closed
				}
				fields := map[string]any{egauth.FieldHandle: o.handle, egauth.FieldBind: o.bind}
				wrong := o.client.Do(onHost(other, journeytest.Req{Method: http.MethodPost, Path: "/auth" + egauth.PathExchange, JSON: fields, Header: bearerHeader(true), Remote: o.client.FreshRemote()}))
				right := o.exchange(true)
				return journeytest.Describe(wrong) + " then " + journeytest.Describe(right), refusedAsUnknown(wrong) && !wrong.Established() && right.Established()
			},
		})
	}
	if w.Config.Modules.OAuth != nil && e.cookiesAllowed() {
		ps = append(ps, journeytest.Probe{
			Category: "tenancy", Name: "tenancy/oauth-state-of-another-tenant", Want: "refused, then the ceremony still completes for its own tenant",
			Run: func() (string, bool) {
				d, err := w.Derive(func(s *journeytest.Settings) { s.LoopbackIdP = true })
				if err != nil {
					return err.Error(), false
				}
				c := d.NewClient()
				back := d.AuthorizeAtIdP(c.BeginOAuth())
				wrong := c.Do(onHost(other, journeytest.Req{Path: back, Remote: c.FreshRemote()}))
				right := c.Do(journeytest.Req{Path: back, Remote: c.FreshRemote()})
				return journeytest.Describe(wrong) + " then " + journeytest.Describe(right),
					refusedAsUnknown(wrong) && !wrong.Established() && (right.Established() || slices.Contains([]string{"email_unverified", "registration_closed"}, right.Code()))
			},
		})
	}
	return ps
}

func (e *env) codeFields(c *journeytest.Client, begun *journeytest.Resp, code string) map[string]any {
	fields := map[string]any{egauth.FieldHandle: begun.Field("handle"), egauth.FieldCode: code}
	if bind := c.Bind(begun); bind != "" && !e.cookiesAllowed() {
		fields[egauth.FieldBind] = bind
	}
	return fields
}

func (e *env) verifiedPhone() string {
	w := e.w
	c, _ := e.loggedIn("phoneowner", !e.cookiesAllowed())
	phone := "+1415555" + strconv.Itoa(1000+int(nextPhone()%9000))
	n := w.TextCount("PhoneVerificationCode") + 1
	begun := c.Post(egauth.PathPhoneVerifyRequest, map[string]any{egauth.FieldPhone: phone})
	c.Post(egauth.PathPhoneVerify, map[string]any{egauth.FieldHandle: begun.Field("handle"), egauth.FieldCode: w.WaitText("PhoneVerificationCode", n).Code})
	return phone
}

func (e *env) codeHandleProbe(channel string, onHost func(string, journeytest.Req) journeytest.Req, other string, request func(*journeytest.Client) map[string]any) journeytest.Probe {
	w := e.w
	return journeytest.Probe{
		Category: "tenancy", Name: "tenancy/code-handle-of-another-tenant/" + channel, Want: "401, then the record still verifies for its own tenant",
		Run: func() (string, bool) {
			c := w.NewClient()
			fields := request(c)
			wrong := c.Do(onHost(other, journeytest.Req{Method: http.MethodPost, Path: "/auth" + egauth.PathCodeVerify, JSON: fields, Remote: c.FreshRemote()}))
			right := c.Post(egauth.PathCodeVerify, fields)
			return journeytest.Describe(wrong) + " then " + journeytest.Describe(right), wrong.Status == http.StatusUnauthorized && !wrong.Established() && right.Established()
		},
	}
}

func (e *env) serves(registry string) bool {
	return len(e.where(func(t target) bool { return t.kind == kAuth && t.registry == registry })) > 0
}

func (e *env) credentialKindProbes() []journeytest.Probe {
	var ps []journeytest.Probe
	if e.w.Config.Modules.APIKeys == nil {
		return ps
	}
	w := e.w
	key := lazy(func() string {
		_, sub := e.user("keyowner", false)
		return w.SeedAPIKey(sub, journeytest.APIKeyKind, []string{"user"}, []string{"items:read"})
	})
	bearer := func(r *journeytest.Req) {
		if r.Header == nil {
			r.Header = http.Header{}
		}
		r.Header.Set("Authorization", "Bearer "+key())
	}
	c := w.NewClient()
	for _, t := range e.where(isSession) {
		ps = append(ps, journeytest.Probe{
			Category: "credential-kind", Name: "credential-kind/api-key-on-session-route/" + t.label(), Want: "401 (anonymous on Optional)",
			Run: func() (string, bool) {
				r, o := e.hit(c, t, func(r *journeytest.Req) { r.NoJar = true }, bearer)
				return denied401(t, r, o)
			},
		})
	}
	for _, t := range e.where(func(t target) bool { return t.kind == kAPI }) {
		ps = append(ps, journeytest.Probe{
			Category: "credential-kind", Name: "credential-kind/api-key-on-api-route/" + t.label(), Want: "200", Control: true,
			Run: func() (string, bool) {
				r, o := e.hit(c, t, func(r *journeytest.Req) { r.NoJar = true }, bearer)
				return served(t, r, o)
			},
		})
	}
	for _, b := range e.transports() {
		session := lazy(func() *journeytest.Client {
			s, _ := e.loggedIn("apisession", b)
			return s
		})
		for _, t := range e.where(func(t target) bool { return t.kind == kAPI }) {
			ps = append(ps, journeytest.Probe{
				Category: "credential-kind", Name: "credential-kind/session-on-api-route/" + transportName(b) + "/" + t.label(), Want: "401",
				Run: func() (string, bool) {
					r, o := e.hit(session(), t)
					return refused(http.StatusUnauthorized, "")(t, r, o)
				},
			})
		}
	}
	return ps
}

func (e *env) controlProbes() []journeytest.Probe {
	var ps []journeytest.Probe
	for _, b := range e.transports() {
		session := lazy(func() *journeytest.Client {
			s, _ := e.loggedIn("control", b)
			return s
		})
		for _, t := range e.where(func(t target) bool {
			return t.kind == kProtect && t.path == journeytest.ProtectRoute || t.kind == kOptional
		}) {
			ps = append(ps, journeytest.Probe{
				Category: "control", Name: "control/valid-session-reaches-handler/" + transportName(b) + "/" + t.label(), Want: "200", Control: true,
				Run: func() (string, bool) {
					r, o := e.hit(session(), t)
					return served(t, r, o)
				},
			})
		}
		ps = append(ps, journeytest.Probe{
			Category: "control", Name: "control/valid-session-reads-its-session/" + transportName(b), Want: "200", Control: true,
			Run: func() (string, bool) {
				r := session().Session()
				return journeytest.Describe(r), r.Status == http.StatusOK && r.Field("subject") != ""
			},
		})
	}
	return ps
}

func (e *env) facadeProbes() []journeytest.Probe {
	w := e.w
	var ps []journeytest.Probe
	post := func(c *journeytest.Client, path string, mut ...func(*journeytest.Req)) string {
		r := journeytest.Req{Method: http.MethodPost, Path: path, Remote: c.FreshRemote()}
		for _, m := range mut {
			m(&r)
		}
		return c.Do(r).Field("result")
	}
	add := func(name, want string, control bool, run func() string) {
		ps = append(ps, journeytest.Probe{
			Category: "facades", Name: "facades/" + name, Want: want, Control: control,
			Run: func() (string, bool) { g := run(); return g, g == want },
		})
	}
	member := lazy(func() *journeytest.Client { c, _ := e.loggedIn("member", false); return c })
	add("system-caller-inside-a-protect-handler", "ErrSystemCallerInRequest", false, func() string {
		return post(member(), journeytest.FacadeSystemRoute)
	})
	add("non-admin-disables-another-user", "ErrForbidden", false, func() string {
		_, victim := e.user("victim", false)
		return post(member(), journeytest.FacadeDisableRoute+victim.User.String())
	})
	add("non-admin-disables-an-unknown-user", "ErrForbidden", false, func() string {
		return post(member(), journeytest.FacadeDisableRoute+uuid.NewString())
	})
	add("key-with-roles-beyond-the-callers", "ErrClaimsNotSubset", false, func() string {
		return post(member(), journeytest.FacadeKeyRoute+"?role=admin")
	})
	add("key-within-the-callers-roles", "ok", true, func() string {
		return post(member(), journeytest.FacadeKeyRoute+"?role=user")
	})
	add("admin-disables-another-user", "ok", true, func() string {
		email, sub := e.user("admin", false)
		w.Grant(sub, []string{journeytest.AdminRole, "user"}, []string{"items:read"})
		c := w.NewClient()
		c.Login(email, false)
		_, victim := e.user("victim", false)
		return post(c, journeytest.FacadeDisableRoute+victim.User.String())
	})
	if w.Config.Modules.APIKeys != nil {
		add("api-key-caller-on-a-facade", "ErrAPIKeyCaller", false, func() string {
			_, owner := e.user("keyfacade", false)
			secret := w.SeedAPIKey(owner, journeytest.APIKeyKind, []string{"user"}, nil)
			_, victim := e.user("victim", false)
			c := w.NewClient()
			return post(c, journeytest.FacadeAPIRoute+victim.User.String(), func(r *journeytest.Req) {
				r.NoJar, r.Header = true, http.Header{"Authorization": {"Bearer " + secret}}
			})
		})
	}
	return ps
}

var bypassCorpus = []string{
	`/\evil.example`, `/%5Cevil.example`, `/%5cevil.example`, "/\t/evil.example", "/\n/evil.example", `/%09/evil.example`,
	`//evil.example`, `///evil.example`, `//evil.example/path`, `/%2F%2Fevil.example`, `/%2f%2fevil.example`,
	`/%252F%252Fevil.example`, `https:evil.example`, `https:/evil.example`, `/.//evil.example`, `/..//evil.example`,
	`\\evil.example`, `\/evil.example`, `https://evil.example`, `http://evil.example/`, `HTTPS://EVIL.EXAMPLE/`,
	`https://acme.example.com.evil.example/`, `https://acme.example.com@evil.example/`, `javascript:alert(1)`,
	`JavaScript:alert(1)`, `data:text/html,<script>alert(1)</script>`, `/%0d%0aSet-Cookie:%20x=y`, "/\x00evil", "/\x7fevil",
	` /evil`, `/ev il`, `evil.example`, `/path#fragment`,
}

var returnToCeremonies = []string{
	routes.Register, routes.Login, routes.PasswordForgot, routes.MagicLinkRequest, routes.CodeRequest,
	routes.PasskeyLoginBegin, routes.ExternalLogin, routes.OAuthBegin,
	routes.EmailVerifyRequest, routes.SecurityRevert, routes.EmailChange, routes.PhoneVerifyRequest,
	routes.RecoveryEmail, routes.PasskeyRegisterBegin, routes.OAuthLink,
}

func randomHandle() string {
	h, err := ceremonycodec.NewHandle()
	if err != nil {
		return ""
	}
	return h.Encode()
}

func (e *env) returnToRequest(registry, raw string) (journeytest.Req, func() *journeytest.Client) {
	path := "/auth" + providerPaths.Replace(registry)
	id := e.w.FreshEmail("redirect")
	fields := map[string]any{
		egauth.FieldIdentifier: id, egauth.FieldEmail: id, egauth.FieldPassword: "tapir-granite-velvet-orbit-29", egauth.FieldReturnTo: raw,
	}
	switch registry {
	case routes.CodeRequest:
		if !e.w.Config.Modules.LoginCode.Email {
			fields[egauth.FieldIdentifier] = "+1415555" + strconv.Itoa(1000+int(nextPhone()%9000))
		}
	case routes.PhoneVerifyRequest:
		fields[egauth.FieldPhone] = "+1415555" + strconv.Itoa(1000+int(nextPhone()%9000))
	case routes.SecurityRevert:
		fields[egauth.FieldToken] = randomHandle()
	case routes.OAuthBegin:
		return journeytest.Req{Path: path + "?" + url.Values{egauth.FieldReturnTo: {raw}}.Encode(), NoJar: true}, nil
	}
	req := journeytest.Req{Method: http.MethodPost, Path: path, NoJar: true, JSON: fields}
	meta, _ := routes.MetaFor(registry)
	if !meta.Authenticated {
		return req, nil
	}
	req.NoJar = false
	return req, func() *journeytest.Client {
		c, _ := e.loggedIn("redirect", !e.cookiesAllowed())
		return c
	}
}

var providerPaths = strings.NewReplacer("{provider}", journeytest.ProviderName, "{name}", journeytest.ExternalName)

func (e *env) redirectProbes() []journeytest.Probe {
	var ps []journeytest.Probe
	c := e.w.NewClient()
	served := map[string]bool{}
	for _, ep := range journeytest.Endpoints("/auth") {
		served[ep.Registry] = journeytest.Served(c, ep)
	}
	for _, registry := range returnToCeremonies {
		if !served[registry] || (registry == routes.OAuthLink && !e.cookiesAllowed()) {
			continue
		}
		path := providerPaths.Replace(registry)
		for _, raw := range bypassCorpus {
			ps = append(ps, journeytest.Probe{
				Category: "redirects", Name: "redirects/" + path + "/" + url.QueryEscape(raw), Want: "400 invalid_return_to",
				Run: func() (string, bool) {
					req, signedIn := e.returnToRequest(registry, raw)
					client := c
					if signedIn != nil {
						client = signedIn()
					}
					req.Remote = client.FreshRemote()
					r := client.Do(req)
					return journeytest.Describe(r) + " location=" + r.Header.Get("Location"), r.Status == http.StatusBadRequest && r.Code() == "invalid_return_to"
				},
			})
		}
	}
	ps = append(ps, journeytest.Probe{
		Category: "redirects", Name: "redirects/login/relative-target-is-kept", Want: "return_to /home", Control: true,
		Run: func() (string, bool) {
			email, _ := e.user("redirect", false)
			cl := e.w.NewClient()
			resp := cl.Post(egauth.PathLogin, map[string]any{egauth.FieldIdentifier: email, egauth.FieldPassword: journeytest.Password, egauth.FieldReturnTo: "/home"})
			return journeytest.Describe(resp), resp.Established() && resp.Field("return_to") == "/home"
		},
	})
	return ps
}

func bearerHeader(bearer bool) http.Header {
	if !bearer {
		return nil
	}
	return http.Header{egauth.HeaderTransport: {"bearer"}}
}

func (e *env) ceremonyBindProbes() []journeytest.Probe {
	var ps []journeytest.Probe
	if e.w.Config.Modules.MagicLink != nil {
		for _, bearer := range e.transports() {
			ps = append(ps, e.magicLinkBindProbes(bearer)...)
		}
	}
	if e.w.Config.Modules.OAuth != nil && e.bearerAllowed() {
		ps = append(ps, e.oauthExchangeBindProbes()...)
	}
	return ps
}

func (e *env) magicLinkBindProbes(bearer bool) []journeytest.Probe {
	w := e.w
	post := func(c *journeytest.Client, path string, fields map[string]any) *journeytest.Resp {
		return c.Do(journeytest.Req{Method: http.MethodPost, Path: "/auth" + path, JSON: fields, Header: bearerHeader(bearer)})
	}
	begin := func() (owner *journeytest.Client, token, bind string) {
		email, _ := e.user("magic", false)
		n := w.MailCount("MagicLink") + 1
		owner = w.NewClient()
		begun := post(owner, egauth.PathMagicLinkRequest, map[string]any{egauth.FieldIdentifier: email})
		return owner, tokenOf(w.WaitMail("MagicLink", n).Link), owner.Bind(begun)
	}
	name := "ceremony-binding/magic-link-consumed-%s/" + transportName(bearer)
	return []journeytest.Probe{{
		Category: "ceremony-binding", Name: fmt.Sprintf(name, "without-bind"), Want: "confirm_required, no session",
		Run: func() (string, bool) {
			_, token, _ := begin()
			r := post(w.NewClient(), egauth.PathMagicLink, map[string]any{egauth.FieldToken: token})
			return journeytest.Describe(r), r.Code() == "confirm_required" && !r.Established()
		},
	}, {
		Category: "ceremony-binding", Name: fmt.Sprintf(name, "with-bind"), Want: "a session", Control: true,
		Run: func() (string, bool) {
			owner, token, bind := begin()
			fields := map[string]any{egauth.FieldToken: token}
			if bearer {
				fields[egauth.FieldBind] = bind
			}
			r := post(owner, egauth.PathMagicLink, fields)
			return journeytest.Describe(r), r.Established()
		},
	}}
}

type bearerOAuth struct {
	world  *journeytest.World
	client *journeytest.Client
	handle string
	bind   string
	got    string
	closed bool
}

func (e *env) bearerOAuthCeremony() (bearerOAuth, bool) {
	d, err := e.w.Derive(func(s *journeytest.Settings) { s.LoopbackIdP = true })
	if err != nil {
		return bearerOAuth{got: err.Error()}, false
	}
	c := d.NewClient()
	hdr := bearerHeader(true)
	begin := c.Do(journeytest.Req{Path: "/auth" + providerPaths.Replace(routes.OAuthBegin), Header: hdr})
	cb := c.Do(journeytest.Req{Path: d.AuthorizeAtIdP(begin), Header: hdr})
	o := bearerOAuth{world: d, client: c, handle: cb.Field(egauth.FieldHandle), bind: c.Bind(begin), got: journeytest.Describe(cb)}
	o.closed = slices.Contains([]string{"email_unverified", "registration_closed"}, cb.Code())
	return o, cb.Code() == "exchange_required" && o.handle != "" && o.bind != ""
}

func (o bearerOAuth) exchange(withBind bool) *journeytest.Resp {
	fields := map[string]any{egauth.FieldHandle: o.handle}
	if withBind {
		fields[egauth.FieldBind] = o.bind
	}
	return o.client.Do(journeytest.Req{Method: http.MethodPost, Path: "/auth" + egauth.PathExchange, JSON: fields, Header: bearerHeader(true), Remote: o.client.FreshRemote()})
}

func (e *env) oauthExchangeBindProbes() []journeytest.Probe {
	return []journeytest.Probe{{
		Category: "ceremony-binding", Name: "ceremony-binding/oauth-exchange-without-bind/bearer", Want: "400 unbound_ceremony, no session",
		Run: func() (string, bool) {
			o, ok := e.bearerOAuthCeremony()
			if !ok {
				return o.got, o.closed
			}
			r := o.exchange(false)
			return journeytest.Describe(r), r.Status == http.StatusBadRequest && r.Code() == "unbound_ceremony" && !r.Established()
		},
	}, {
		Category: "ceremony-binding", Name: "ceremony-binding/oauth-exchange-with-bind/bearer", Want: "a session", Control: true,
		Run: func() (string, bool) {
			o, ok := e.bearerOAuthCeremony()
			if !ok {
				return o.got, o.closed
			}
			r := o.exchange(true)
			return journeytest.Describe(r), r.Established()
		},
	}}
}

func (e *env) forwardedClientProbes() []journeytest.Probe {
	w := e.w
	login, _ := routes.MetaFor(routes.Login)
	burst := login.ClientLimit.Budget().Burst
	want := "429 on request " + strconv.Itoa(burst+1)
	return []journeytest.Probe{{
		Category: "limits", Name: "limits/forwarded-clients-behind-trusted-proxies-have-independent-buckets", Want: want + " of one client, none for the other",
		Run: func() (string, bool) {
			d, err := w.Derive(func(s *journeytest.Settings) {
				*s = s.Configure(func(c *egauth.Config[journeytest.Claims]) {
					c.Proxy = egauth.TrustedProxies(netip.MustParsePrefix("198.51.0.0/16"))
				})
			})
			if err != nil {
				return err.Error(), false
			}
			c := d.NewClient()
			path := "/auth" + egauth.PathLogin
			send := func(client string, i int) *journeytest.Resp {
				return c.Do(journeytest.Req{Method: http.MethodPost, Path: path, NoJar: true,
					Header: http.Header{"X-Forwarded-For": {client}},
					JSON:   map[string]any{egauth.FieldIdentifier: "bucket-" + client + "-" + strconv.Itoa(i) + "@mail.test", egauth.FieldPassword: "x"}})
			}
			limited := 0
			for i := 0; i <= burst; i++ {
				if send("203.0.113.10", i).Status == http.StatusTooManyRequests {
					limited = i + 1
					break
				}
			}
			other := send("203.0.113.11", 0)
			return "client A limited at " + strconv.Itoa(limited) + ", client B " + journeytest.Describe(other),
				limited == burst+1 && other.Status != http.StatusTooManyRequests
		},
	}, {
		Category: "limits", Name: "limits/forwarded-for-from-an-untrusted-peer-is-ignored", Want: want + " whatever X-Forwarded-For says",
		Run: func() (string, bool) {
			c := w.NewClient()
			limited := 0
			for i := 0; i <= burst; i++ {
				r := c.Do(journeytest.Req{Method: http.MethodPost, Path: "/auth" + egauth.PathLogin, NoJar: true,
					Header: http.Header{"X-Forwarded-For": {"203.0.113." + strconv.Itoa(i+1)}},
					JSON:   map[string]any{egauth.FieldIdentifier: "spoof-" + strconv.Itoa(i) + "@mail.test", egauth.FieldPassword: "x"}})
				if r.Status == http.StatusTooManyRequests {
					limited = i + 1
					break
				}
			}
			return "limited at " + strconv.Itoa(limited), limited == burst+1
		},
	}}
}

func worldProbes(w *journeytest.World) []journeytest.Probe {
	e := newEnv(w)
	var ps []journeytest.Probe
	ps = append(ps, journeytest.AuthProbes(w.NewClient(), "/auth")...)
	ps = append(ps, e.userRouteCSRFProbes()...)
	ps = append(ps, e.ceremonyBindProbes()...)
	ps = append(ps, e.forwardedClientProbes()...)
	ps = append(ps, e.sessionStateProbes()...)
	ps = append(ps, e.sensitiveProbes()...)
	ps = append(ps, e.sessionLimitProbes()...)
	ps = append(ps, e.tenancyProbes()...)
	ps = append(ps, e.credentialKindProbes()...)
	ps = append(ps, e.facadeProbes()...)
	ps = append(ps, e.redirectProbes()...)
	ps = append(ps, e.controlProbes()...)
	return ps
}

var phoneSeq atomic.Uint32

func nextPhone() uint32 { return phoneSeq.Add(1) }
