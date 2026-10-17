package journeytest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/journeytest"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/webauthntest"
)

func TestRegressionP07ConcurrentPasskeyBeginsLeaveTheFirstFinishable(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		a := newAccount(t, w, s, "p07")
		key := a.withPasskeys(1)[0]

		c := w.NewClient()
		first := a.loginBegin(c, map[string]any{egauth.FieldIdentifier: a.Email})
		second := a.loginBegin(c, map[string]any{egauth.FieldIdentifier: a.Email})
		require.NotEqual(t, decodeOptions(t, first).Handle, decodeOptions(t, second).Handle)
		res := a.loginFinish(c, first, key.Login(t, decodeOptions(t, first).Options))
		require.True(t, res.Established(), "the first of two concurrent begins could not finish: "+journeytest.Describe(res))
	})
}

func TestRegressionP07ParallelBeginsOfOneAccountAllFinish(t *testing.T) {
	s := shape{backend: journeytest.JWT}
	w := journeytest.NewWorld(t, s.settings())
	a := newAccount(t, w, s, "p07parallel")
	key := a.withPasskeys(1)[0]

	const n = 6
	clients := make([]*journeytest.Client, n)
	for i := range clients {
		clients[i] = w.NewClient()
	}
	begins := make([]*journeytest.Resp, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			begins[i] = clients[i].Post(egauth.PathPasskeyLoginBegin, map[string]any{egauth.FieldIdentifier: a.Email})
		}()
	}
	wg.Wait()
	for i := n - 1; i >= 0; i-- {
		require.Equal(t, http.StatusOK, begins[i].Status, journeytest.Describe(begins[i]))
		res := a.loginFinish(clients[i], begins[i], key.Login(t, decodeOptions(t, begins[i]).Options))
		require.True(t, res.Established(), "begin %d: %s", i, journeytest.Describe(res))
	}
}

func TestRegressionP07ConcurrentRegistrationBeginsLeaveTheFirstFinishable(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		a := newAccount(t, w, s, "p07register")
		sess := a.signIn(false)
		first := sess.post(egauth.PathPasskeyRegisterBegin, nil)
		require.Equal(t, http.StatusOK, first.Status, journeytest.Describe(first))
		sess.adopt(first)
		second := sess.post(egauth.PathPasskeyRegisterBegin, nil)
		require.Equal(t, http.StatusOK, second.Status, journeytest.Describe(second))
		sess.adopt(second)
		b := decodeOptions(t, first)
		key := webauthntest.New(w.Origin)
		res := sess.post(egauth.PathPasskeyRegisterFinish, mergeFields(t, key.Register(t, b.Options), map[string]any{egauth.FieldHandle: b.Handle}))
		require.Equal(t, http.StatusOK, res.Status, "the first registration begin died when a second one started: "+journeytest.Describe(res))
	})
}

type credentialList struct {
	Credentials []struct {
		ID       string `json:"credential_id"`
		Nickname string `json:"nickname"`
	} `json:"credentials"`
}

func listCredentials(t testing.TB, s *session) credentialList {
	t.Helper()
	res := s.c.Do(journeytest.Req{Path: "/auth" + egauth.PathPasskeyCredentials})
	require.Equal(t, http.StatusOK, res.Status, journeytest.Describe(res))
	var l credentialList
	require.NoError(t, json.Unmarshal(res.Body, &l))
	return l
}

func TestRegressionP05ListThenRenameEveryCredentialID(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		a := newAccount(t, w, s, "p05")
		keys := a.withPasskeys(6)
		sess := a.passkeySession(keys[0])
		list := listCredentials(t, sess)
		require.Len(t, list.Credentials, len(keys))
		for _, c := range list.Credentials {
			require.NotContains(t, c.ID, "+")
			require.NotContains(t, c.ID, "/")
			require.NotContains(t, c.ID, "=")
		}
		for i, c := range list.Credentials {
			nickname := "key-" + strings.Repeat("x", i+1)
			res := sess.post(egauth.PathPasskeyCredentialsRename, map[string]any{egauth.FieldCredentialID: c.ID, egauth.FieldNickname: nickname})
			require.Equal(t, http.StatusOK, res.Status, "renaming credential %q: %s", c.ID, journeytest.Describe(res))
			sess.adopt(res)
		}
		got := map[string]string{}
		for _, c := range listCredentials(t, sess).Credentials {
			got[c.ID] = c.Nickname
		}
		for i, c := range list.Credentials {
			require.Equal(t, "key-"+strings.Repeat("x", i+1), got[c.ID], "the rename of %q did not stick", c.ID)
		}
	})
}

type countingCeremonies struct {
	ceremony.Store
	puts atomic.Int64
}

func (c *countingCeremonies) Put(ctx context.Context, r ceremony.Record) (int, error) {
	c.puts.Add(1)
	return c.Store.Put(ctx, r)
}

func TestRegressionC13C50DiscoverableFloodWritesNoCeremonyRow(t *testing.T) {
	for _, backend := range []journeytest.Backend{journeytest.JWT, journeytest.Stateful} {
		t.Run(backend.String(), func(t *testing.T) {
			s := shape{backend: backend}
			counter := &countingCeremonies{}
			w := journeytest.NewWorld(t, s.settings().Configure(func(c *egauth.Config[journeytest.Claims]) {
				counter.Store = c.Storage.Ceremonies
				c.Storage.Ceremonies = counter
			}))
			known := newAccount(t, w, s, "known")
			setup := known.signIn(false)
			secret := setup.enrollTOTP()
			settle(w)

			c := w.NewClient()
			before := counter.puts.Load()
			for range 400 {
				res := c.Do(journeytest.Req{Method: http.MethodPost, Path: "/auth" + egauth.PathPasskeyLoginBegin, JSON: map[string]any{}, Remote: c.FreshRemote()})
				require.Equal(t, http.StatusOK, res.Status, journeytest.Describe(res))
			}
			require.Equal(t, before, counter.puts.Load(), "a discoverable begin wrote a ceremony row")

			mfa := known.multiFactorSession(secret)
			require.Equal(t, http.StatusOK, mfa.status(), "password plus TOTP login failed after the flood")
			mc, fields := known.magicLink()
			link := mc.Post(egauth.PathMagicLink, fields)
			require.True(t, link.Established() || link.Code() == "mfa_required", "magic link login failed after the flood: "+journeytest.Describe(link))
		})
	}
}

func TestRegressionC29AttackerDiscoverableCredentialCannotAnswerAVictimBind(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		victim := newAccount(t, w, s, "victim")
		victim.withPasskeys(1)
		attacker := newAccount(t, w, s, "attacker")
		attackerKey := attacker.withPasskeys(1)[0]

		c := w.NewClient()
		begin := victim.loginBegin(c, map[string]any{egauth.FieldIdentifier: victim.Email})
		options := withoutAllowList(t, decodeOptions(t, begin).Options)
		res := victim.loginFinish(c, begin, attackerKey.Login(t, options))
		require.Equal(t, http.StatusUnauthorized, res.Status, journeytest.Describe(res))
		require.False(t, res.Established(), "an attacker credential answered the ceremony bound to the victim")
		require.Equal(t, http.StatusUnauthorized, c.Session().Status)
	})
}

func withoutAllowList(t testing.TB, options []byte) []byte {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(options, &m))
	target := m
	if inner, ok := m["publicKey"].(map[string]any); ok {
		target = inner
	}
	delete(target, "allowCredentials")
	out, err := json.Marshal(m)
	require.NoError(t, err)
	return out
}

type codeRequest struct {
	client *journeytest.Client
	handle string
	bind   string
	code   string
}

func requestEmailCode(t testing.TB, w *journeytest.World, s shape, email string) codeRequest {
	t.Helper()
	seen := len(w.Mailbox.Messages())
	c := w.NewClient()
	begin := c.Post(egauth.PathCodeRequest, map[string]any{egauth.FieldIdentifier: email})
	require.Equal(t, http.StatusOK, begin.Status, journeytest.Describe(begin))
	r := codeRequest{client: c, handle: begin.Field(egauth.FieldHandle)}
	if s.bearer {
		r.bind = c.Bind(begin)
	}
	waitFor(t, "the login code for "+email, func() bool {
		for _, m := range w.Mailbox.Messages()[seen:] {
			if m.Kind == "LoginCode" && m.To == email {
				r.code = m.Code
				return true
			}
		}
		return false
	})
	return r
}

func (r codeRequest) verify(handle, code string) *journeytest.Resp {
	fields := map[string]any{egauth.FieldHandle: handle, egauth.FieldCode: code}
	if r.bind != "" {
		fields[egauth.FieldBind] = r.bind
	}
	return r.client.Post(egauth.PathCodeVerify, fields)
}

func TestRegressionC30ACodeOfAnotherUserNeverAnswersAHandleAndChargesNoOneElse(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		userA := newAccount(t, w, s, "codea")
		userB := newAccount(t, w, s, "codeb")
		forA := requestEmailCode(t, w, s, userA.Email)
		forB := requestEmailCode(t, w, s, userB.Email)
		require.NotEqual(t, forA.handle, forB.handle)

		for i := range 8 {
			res := forA.verify(forA.handle, forB.code)
			require.Equal(t, http.StatusUnauthorized, res.Status, "attempt %d: %s", i, journeytest.Describe(res))
			require.False(t, res.Established())
		}
		for range 4 {
			res := forB.verify(forB.handle, "000000")
			require.Equal(t, http.StatusUnauthorized, res.Status, journeytest.Describe(res))
		}
		res := forB.verify(forB.handle, forB.code)
		require.True(t, res.Established(), "the attempts of user B were charged by the attacker: "+journeytest.Describe(res))
	})
}

func TestRegressionC28PasskeyLoginWithoutUserVerificationNeverGivesASession(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		a := newAccount(t, w, s, "c28")
		key := a.withPasskeys(1)[0]
		key.ClientUserVerification = "discouraged"

		c := w.NewClient()
		begin := a.loginBegin(c, map[string]any{egauth.FieldIdentifier: a.Email})
		res := a.loginFinish(c, begin, key.Login(t, decodeOptions(t, begin).Options))
		require.Equal(t, http.StatusUnauthorized, res.Status, journeytest.Describe(res))
		require.Equal(t, "passkey_rejected", res.Code(), "a passkey assertion without user verification must be refused outright, not parked as a flow: "+journeytest.Describe(res))
		require.Empty(t, c.FlowHandle(res), "the refused assertion left a flow to continue")
		require.False(t, res.Established(), "a passkey assertion without user verification admitted a session: "+journeytest.Describe(res))
		require.Equal(t, http.StatusUnauthorized, c.Session().Status)
	})
}

func TestRegressionC28PasswordThenAPasskeyStepUpIsTheOnlyCompletion(t *testing.T) {
	forEachShape(t, func(t *testing.T, s shape, w *journeytest.World) {
		a := newAccount(t, w, s, "c28pw")
		key := a.withPasskeys(1)[0]

		c := w.NewClient()
		parked := c.LoginPassword(journeytest.Credentials{Email: a.Email, Password: journeytest.Password}, s.bearer)
		require.Equal(t, "mfa_required", parked.Code(), journeytest.Describe(parked))
		require.False(t, parked.Established())
		flow := c.FlowHandle(parked)
		fields := map[string]any{}
		if s.bearer {
			fields[egauth.FieldFlow] = flow
		}
		begin := c.Post(egauth.PathMFAPasskeyBegin, fields)
		require.Equal(t, http.StatusOK, begin.Status, journeytest.Describe(begin))
		b := decodeOptions(t, begin)
		extra := map[string]any{egauth.FieldHandle: b.Handle}
		if s.bearer {
			extra[egauth.FieldFlow] = flow
		}
		done := c.Post(egauth.PathMFAPasskeyFinish, mergeFields(t, key.Login(t, b.Options), extra))
		require.True(t, done.Established(), journeytest.Describe(done))
	})
}

func TestRegressionC01AnEnrolledUserIsNeverAuthenticatedWithoutTheirSecondFactorModule(t *testing.T) {
	for _, s := range shapes() {
		t.Run(s.String(), func(t *testing.T) {
			w := journeytest.NewWorld(t, s.settings().Configure(func(c *egauth.Config[journeytest.Claims]) { c.Modules.MFA = nil }))
			a := newAccount(t, w, s, "c01")
			w.EnrollTOTP(a.Sub)
			settle(w)
			before := w.Seen.Count()

			c := w.NewClient()
			res := c.LoginPassword(journeytest.Credentials{Email: a.Email, Password: journeytest.Password}, s.bearer)
			require.False(t, res.Established(), "a password login of an enrolled user was authenticated with the MFA module absent: "+journeytest.Describe(res))
			require.False(t, c.HasSessionCookie())
			require.Empty(t, c.Bearer)
			require.Equal(t, http.StatusUnauthorized, c.Session().Status)
			require.Contains(t, w.Events.Types(), event.MFAModuleMissing)

			mc, fields := a.magicLink()
			link := mc.Post(egauth.PathMagicLink, fields)
			require.False(t, link.Established(), "a magic link login of an enrolled user was authenticated with the MFA module absent: "+journeytest.Describe(link))
			code := requestEmailCode(t, w, s, a.Email)
			verified := code.verify(code.handle, code.code)
			require.False(t, verified.Established(), "an email code login of an enrolled user was authenticated with the MFA module absent: "+journeytest.Describe(verified))
			require.Equal(t, before, w.Seen.Count())
		})
	}
}

func oauthWorld(t *testing.T, s shape, verification federation.EmailVerification) *journeytest.World {
	t.Helper()
	set := s.settings()
	set.LoopbackIdP = true
	return journeytest.NewWorld(t, set.Configure(func(c *egauth.Config[journeytest.Claims]) {
		p := &c.Modules.OAuth.Providers[0]
		p.EmailVerification = verification
		if verification == federation.ClaimBased {
			p.Domains = []string{"mail.test"}
		}
	}))
}

func cookieShapes() []shape {
	return []shape{{backend: journeytest.JWT}, {backend: journeytest.Stateful}}
}

func TestRegressionC05AnExistingAccountIsNeverAutoLinkedWhateverEmailVerificationSays(t *testing.T) {
	for _, verification := range []federation.EmailVerification{federation.Never, federation.ClaimBased, federation.Always} {
		for _, s := range cookieShapes() {
			t.Run(s.String()+"/verification-"+verificationName(verification), func(t *testing.T) {
				w := oauthWorld(t, s, verification)
				owner := newAccount(t, w, s, "owner")
				w.IdP.SetUser(egauthtest.IdPUser{Subject: "idp-" + owner.Email, Email: owner.Email, EmailVerified: true, Name: "Pre Hijacker"})
				before := w.Events.Mark()

				c := w.NewClient()
				res := c.CompleteOAuth(w)
				require.False(t, res.Established(), "an OAuth sign-in with the email of an existing account was authenticated: "+journeytest.Describe(res))
				wantStatus, wantCode := http.StatusConflict, "account_exists"
				if verification == federation.Never {
					wantStatus, wantCode = http.StatusForbidden, "email_unverified"
				}
				require.Equal(t, wantStatus, res.Status, journeytest.Describe(res))
				require.Equal(t, wantCode, res.Code())
				require.False(t, c.HasSessionCookie())

				links, err := w.Storage.Identity.ListFederated(context.Background(), owner.Sub)
				require.NoError(t, err)
				require.Empty(t, links, "the provider account was linked to an existing account")
				require.NotContains(t, w.Events.Since(before), event.SessionIssued)
				login := w.NewClient().LoginPassword(journeytest.Credentials{Email: owner.Email, Password: journeytest.Password}, false)
				require.True(t, login.Established(), "the owner lost access: "+journeytest.Describe(login))
			})
		}
	}
}

func verificationName(v federation.EmailVerification) string {
	switch v {
	case federation.Never:
		return "never"
	case federation.ClaimBased:
		return "claim-based"
	}
	return "always"
}

func TestRegressionC39PreHijackAttackerRegistersFirst(t *testing.T) {
	for _, s := range cookieShapes() {
		t.Run(s.String(), func(t *testing.T) {
			w := oauthWorld(t, s, federation.Always)
			victimEmail := w.FreshEmail("prehijack")
			attackerPassword := "attacker-chosen mango lantern 83!"
			n := w.MailCount("RegistrationLink")
			attacker := w.NewClient()
			res := attacker.Post(egauth.PathRegister, map[string]any{egauth.FieldIdentifier: victimEmail, egauth.FieldPassword: attackerPassword})
			require.Equal(t, http.StatusAccepted, res.Status, journeytest.Describe(res))
			link := w.WaitMail("RegistrationLink", n+1)
			require.Equal(t, victimEmail, link.To, "the registration link must go to the address owner only")

			id, err := identity.NewIdentifier(identity.IdentifierEmail, victimEmail)
			require.NoError(t, err)
			_, err = w.Storage.Identity.FindUser(context.Background(), w.Tenant, id)
			require.ErrorIs(t, err, store.ErrNotFound, "a registration request created an account before the email was verified")
			by := attacker.LoginPassword(journeytest.Credentials{Email: victimEmail, Password: attackerPassword}, false)
			require.False(t, by.Established(), "the attacker password works before any proof of ownership")

			w.IdP.SetUser(egauthtest.IdPUser{Subject: "idp-victim-" + victimEmail, Email: victimEmail, EmailVerified: true, Name: "Victim"})
			victim := w.NewClient()
			signUp := victim.CompleteOAuth(w)
			require.True(t, signUp.Established(), "the provider-proven owner could not sign up: "+journeytest.Describe(signUp))

			replay := w.NewClient().Post(egauth.PathRegisterConfirm, map[string]any{egauth.FieldToken: queryParam(link.Link, egauth.FieldToken)})
			require.False(t, replay.Established(), "the attacker pending registration was confirmed over the real account: "+journeytest.Describe(replay))
			by = w.NewClient().LoginPassword(journeytest.Credentials{Email: victimEmail, Password: attackerPassword}, false)
			require.False(t, by.Established(), "the attacker password works on the victim account after the victim signed up")
			u, err := w.Storage.Identity.FindUser(context.Background(), w.Tenant, id)
			require.NoError(t, err)
			_, err = w.Storage.Identity.GetPassword(context.Background(), u.Subject)
			require.ErrorIs(t, err, store.ErrNotFound, "the victim account carries a password the victim never set")
		})
	}
}

func TestRegressionC39PreHijackVictimSignsUpFirst(t *testing.T) {
	for _, s := range cookieShapes() {
		t.Run(s.String(), func(t *testing.T) {
			w := oauthWorld(t, s, federation.Always)
			victimEmail := w.FreshEmail("prehijack2")
			w.IdP.SetUser(egauthtest.IdPUser{Subject: "idp-victim-" + victimEmail, Email: victimEmail, EmailVerified: true, Name: "Victim"})
			victim := w.NewClient()
			require.True(t, victim.CompleteOAuth(w).Established())

			attackerPassword := "attacker-chosen mango lantern 83!"
			links, notices := w.MailCount("RegistrationLink"), w.MailCount("AccountExistsNotice")
			res := w.NewClient().Post(egauth.PathRegister, map[string]any{egauth.FieldIdentifier: victimEmail, egauth.FieldPassword: attackerPassword})
			require.Equal(t, http.StatusAccepted, res.Status, journeytest.Describe(res))
			notice := w.WaitMail("AccountExistsNotice", notices+1)
			require.Equal(t, victimEmail, notice.To)
			require.Equal(t, links, w.MailCount("RegistrationLink"), "a registration link was sent for an address that already has an account")

			by := w.NewClient().LoginPassword(journeytest.Credentials{Email: victimEmail, Password: attackerPassword}, false)
			require.False(t, by.Established(), "the attacker password works on the account the victim created through the provider")
			id, err := identity.NewIdentifier(identity.IdentifierEmail, victimEmail)
			require.NoError(t, err)
			u, err := w.Storage.Identity.FindUser(context.Background(), w.Tenant, id)
			require.NoError(t, err)
			_, err = w.Storage.Identity.GetPassword(context.Background(), u.Subject)
			require.ErrorIs(t, err, store.ErrNotFound)
			require.Equal(t, http.StatusOK, victim.Session().Status, "the victim session was disturbed by the attacker registration")
		})
	}
}
