package journeytest

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/webauthntest"
)

func primaryDrivers() []PrimaryDriver {
	return []PrimaryDriver{
		{
			Primary: PrimaryRegister, Module: "Password", Factors: []string{"email_link"},
			LegEvents: []event.Type{event.UserRegistered},
			Prepare:   func(r *Run) { r.Email = r.World.FreshEmail("register") },
			Login:     loginRegister,
		},
		{
			Primary: PrimaryPassword, Module: "Password", Factors: []string{"pwd"},
			Prepare: seedAccount, Login: loginPassword,
		},
		{
			Primary: PrimaryMagicLink, Module: "MagicLink", Factors: []string{"email_link"},
			Prepare: seedAccount, Login: loginMagicLink,
		},
		{
			Primary: PrimaryEmailCode, Module: "LoginCode", Factors: []string{"email_code"},
			Prepare: seedAccount, Login: loginEmailCode,
		},
		{
			Primary: PrimarySMSCode, Module: "LoginCode", Factors: []string{"sms_code"},
			Prepare: prepareSMS, Login: loginSMSCode,
		},
		{
			Primary: PrimaryPasskeyUsernameFirst, Module: "Passkey", Factors: []string{"pk", "uv"}, SelfSufficient: true,
			Prepare: preparePasskey, Login: func(r *Run, c *Client) *Resp { return loginPasskey(r, c, true) },
		},
		{
			Primary: PrimaryPasskeyDiscoverable, Module: "Passkey", Factors: []string{"pk", "uv"}, SelfSufficient: true,
			Prepare: preparePasskey, Login: func(r *Run, c *Client) *Resp { return loginPasskey(r, c, false) },
		},
		{
			Primary: PrimaryOAuthOIDC, Module: "OAuth", Factors: []string{"fed"}, JIT: true, CreateEvents: []event.Type{event.UserRegistered},
			Settings: func(s *Settings) { s.LoopbackIdP = true },
			Prepare:  prepareOAuth, Login: func(r *Run, c *Client) *Resp { return loginOAuth(r, c, false) },
		},
		{
			Primary: PrimaryOAuthPlain, Module: "OAuth", Factors: []string{"fed"}, JIT: true, CreateEvents: []event.Type{event.UserRegistered},
			Settings: func(s *Settings) {
				s.LoopbackIdP = true
				*s = s.Configure(plainProvider)
			},
			Prepare: prepareOAuth, Login: func(r *Run, c *Client) *Resp { return loginOAuth(r, c, true) },
		},
		{
			Primary: PrimaryExternal, Module: "External", Factors: []string{"ext"}, JIT: true, CreateEvents: []event.Type{event.UserRegistered},
			Prepare: func(r *Run) { r.Email = r.World.FreshEmail("external") }, Login: loginExternal,
		},
	}
}

func plainProvider(c *egauth.Config[Claims]) {
	providers := c.Modules.OAuth.Providers
	for i := range providers {
		providers[i].Issuer = ""
		providers[i].JWKSURL = ""
	}
}

func seedAccount(r *Run) {
	r.T.Helper()
	r.Email = r.World.FreshEmail("journey")
	r.Account = r.World.SeedUser(r.Email, false)
}

func loginRegister(r *Run, c *Client) *Resp {
	r.T.Helper()
	w := r.World
	n := w.MailCount("RegistrationLink")
	begin := r.post(c, egauth.PathRegister, r.fields(map[string]any{egauth.FieldIdentifier: r.Email, egauth.FieldPassword: registerPassword}))
	r.expect(begin, http.StatusAccepted, "registration request")
	token := queryOf(w.WaitMail("RegistrationLink", n+1).Link, egauth.FieldToken)
	return r.post(c, egauth.PathRegisterConfirm, r.withBind(c, begin, map[string]any{egauth.FieldToken: token}))
}

func loginPassword(r *Run, c *Client) *Resp {
	r.T.Helper()
	res := r.post(c, egauth.PathLogin, r.fields(map[string]any{egauth.FieldIdentifier: r.Email, egauth.FieldPassword: Password}))
	c.flow = flowOf(res)
	return res
}

func flowOf(res *Resp) string {
	return res.Field(egauth.FieldFlow)
}

func loginMagicLink(r *Run, c *Client) *Resp {
	r.T.Helper()
	w := r.World
	n := w.MailCount("MagicLink")
	begin := r.post(c, egauth.PathMagicLinkRequest, r.fields(map[string]any{egauth.FieldIdentifier: r.Email}))
	r.expect(begin, http.StatusAccepted, "magic link request")
	token := queryOf(w.WaitMail("MagicLink", n+1).Link, egauth.FieldToken)
	res := r.post(c, egauth.PathMagicLink, r.withBind(c, begin, map[string]any{egauth.FieldToken: token}))
	c.flow = flowOf(res)
	return res
}

func loginEmailCode(r *Run, c *Client) *Resp {
	r.T.Helper()
	w := r.World
	n := w.MailCount("LoginCode")
	begin := r.post(c, egauth.PathCodeRequest, r.fields(map[string]any{egauth.FieldIdentifier: r.Email}))
	r.expect(begin, http.StatusOK, "email code request")
	code := w.WaitMail("LoginCode", n+1).Code
	res := r.post(c, egauth.PathCodeVerify, r.withBind(c, begin, map[string]any{egauth.FieldHandle: begin.Field(egauth.FieldHandle), egauth.FieldCode: code}))
	c.flow = flowOf(res)
	return res
}

func prepareSMS(r *Run) {
	r.T.Helper()
	seedAccount(r)
	w := r.World
	c := w.NewClient()
	c.Login(r.Email, r.bearer())
	n := w.TextCount("PhoneVerificationCode")
	begin := r.post(c, egauth.PathPhoneVerifyRequest, map[string]any{egauth.FieldPhone: journeyPhone})
	r.expect(begin, http.StatusOK, "phone verification request")
	code := w.WaitText("PhoneVerificationCode", n+1).Code
	r.expect(r.post(c, egauth.PathPhoneVerify, map[string]any{egauth.FieldHandle: begin.Field(egauth.FieldHandle), egauth.FieldCode: code}), http.StatusOK, "phone verification")
	r.settle()
	r.Phone = journeyPhone
}

func loginSMSCode(r *Run, c *Client) *Resp {
	r.T.Helper()
	w := r.World
	n := w.TextCount("LoginCode")
	begin := r.post(c, egauth.PathCodeRequest, r.fields(map[string]any{egauth.FieldIdentifier: r.Phone}))
	r.expect(begin, http.StatusOK, "SMS code request")
	code := w.WaitText("LoginCode", n+1).Code
	res := r.post(c, egauth.PathCodeVerify, r.withBind(c, begin, map[string]any{egauth.FieldHandle: begin.Field(egauth.FieldHandle), egauth.FieldCode: code}))
	c.flow = flowOf(res)
	return res
}

func preparePasskey(r *Run) {
	r.T.Helper()
	seedAccount(r)
	c := r.World.NewClient()
	c.Login(r.Email, r.bearer())
	r.Passkey = webauthntest.New(r.World.Origin)
	r.registerPasskey(c, r.Passkey)
}

func (r *Run) registerPasskey(c *Client, a *webauthntest.Authenticator) {
	r.T.Helper()
	begin := r.post(c, egauth.PathPasskeyRegisterBegin, nil)
	r.expect(begin, http.StatusOK, "passkey registration begin")
	b := decodeOptions(r.T, begin)
	body := mergeJSON(r.T, a.Register(r.T, b.Options), map[string]any{egauth.FieldHandle: b.Handle})
	r.expect(r.post(c, egauth.PathPasskeyRegisterFinish, body), http.StatusOK, "passkey registration finish")
	r.settle()
}

func loginPasskey(r *Run, c *Client, usernameFirst bool) *Resp {
	r.T.Helper()
	extra := map[string]any{}
	if usernameFirst {
		extra[egauth.FieldIdentifier] = r.Email
	}
	begin := r.post(c, egauth.PathPasskeyLoginBegin, r.fields(extra))
	r.expect(begin, http.StatusOK, "passkey login begin")
	b := decodeOptions(r.T, begin)
	var assertion []byte
	if usernameFirst {
		assertion = r.Passkey.Login(r.T, b.Options)
	} else {
		assertion = r.Passkey.DiscoverableLogin(r.T, b.Options)
	}
	body := mergeJSON(r.T, assertion, r.withBind(c, begin, map[string]any{egauth.FieldHandle: b.Handle}))
	res := r.post(c, egauth.PathPasskeyLoginFinish, body)
	c.flow = flowOf(res)
	return res
}

func prepareOAuth(r *Run) {
	r.T.Helper()
	r.Email = r.World.FreshEmail("oauth")
	r.World.IdP.SetUser(egauthtest.IdPUser{Subject: "idp-" + r.Email, Email: r.Email, EmailVerified: true, Name: "Journey User"})
}

func loginOAuth(r *Run, c *Client, plain bool) *Resp {
	r.T.Helper()
	q := url.Values{egauth.FieldRemember: {strconv.FormatBool(r.Remember)}, egauth.FieldReturnTo: {JourneyReturnTo}}
	begin := c.Do(Req{Path: "/auth" + concrete(egauth.PathOAuthBegin) + "?" + q.Encode()})
	if AuthorizationURL(begin) == "" {
		r.T.Fatalf("journeytest: OAuth begin: %s", Describe(begin))
	}
	callback := r.authorize(begin, plain)
	res := c.Do(Req{Path: callback})
	c.keepTokens(res)
	if r.bearer() {
		res = r.exchange(c, begin, res)
	}
	c.flow = flowOf(res)
	return res
}

func (r *Run) authorize(begin *Resp, plain bool) string {
	r.T.Helper()
	if !plain {
		return r.World.AuthorizeAtIdP(begin)
	}
	u, err := url.Parse(AuthorizationURL(begin))
	if err != nil {
		r.T.Fatalf("journeytest: authorization URL: %v", err)
	}
	q := u.Query()
	q.Set("nonce", "plain-oauth-has-no-id-token")
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u.String(), nil)
	if err != nil {
		r.T.Fatalf("journeytest: authorization request: %v", err)
	}
	res, err := r.World.IdP.HTTPClient().Do(req)
	if err != nil {
		r.T.Fatalf("journeytest: authorizing at the provider: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	back, err := url.Parse(res.Header.Get("Location"))
	if err != nil || back.Path == "" {
		r.T.Fatalf("journeytest: the provider answered %d without a redirect", res.StatusCode)
	}
	return back.RequestURI()
}

func (r *Run) exchange(c *Client, begin, callback *Resp) *Resp {
	r.T.Helper()
	handle := callback.Field(egauth.FieldHandle)
	if handle == "" {
		if loc, err := url.Parse(callback.Header.Get("Location")); err == nil {
			handle = loc.Query().Get(egauth.FieldHandle)
		}
	}
	if handle == "" {
		r.T.Fatalf("journeytest: OAuth callback handed out no exchange handle: %s", Describe(callback))
	}
	return r.post(c, egauth.PathExchange, map[string]any{egauth.FieldHandle: handle, egauth.FieldBind: c.Bind(begin)})
}

func loginExternal(r *Run, c *Client) *Resp {
	r.T.Helper()
	res := c.Do(Req{Method: http.MethodPost, Path: "/auth" + concrete(egauth.PathExternalLogin), JSON: r.fields(map[string]any{
		egauth.FieldIdentifier: r.Email, egauth.FieldPassword: Password,
	})})
	c.keepTokens(res)
	c.flow = flowOf(res)
	return res
}

func lookupSubject(r *Run) {
	r.T.Helper()
	id, err := identity.NewIdentifier(identity.IdentifierEmail, r.Email)
	if err != nil {
		r.T.Fatalf("journeytest: identifier: %v", err)
	}
	u, err := r.World.Storage.Identity.FindUser(context.Background(), r.World.Tenant, id)
	if err != nil {
		r.T.Fatalf("journeytest: finding the account of %s: %v", r.Email, err)
	}
	r.Account = u.Subject
}
