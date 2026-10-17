package journeytest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/journeytest"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/principal"
)

const strongPassword = "tapir-granite-velvet-orbit-29"

type shape struct {
	backend journeytest.Backend
	bearer  bool
}

func (s shape) String() string {
	if s.bearer {
		return s.backend.String() + "/bearer"
	}
	return s.backend.String() + "/cookies"
}

func shapes() []shape {
	var out []shape
	for _, b := range []journeytest.Backend{journeytest.JWT, journeytest.Stateful} {
		for _, bearer := range []bool{false, true} {
			out = append(out, shape{backend: b, bearer: bearer})
		}
	}
	return out
}

func (s shape) settings() journeytest.Settings {
	t := egauth.Cookies
	if s.bearer {
		t = egauth.Bearer
	}
	return journeytest.Settings{Backend: s.backend, Tenancy: journeytest.Single, Transport: t}
}

func forEachShape(t *testing.T, fn func(t *testing.T, s shape, w *journeytest.World)) {
	t.Helper()
	for _, s := range shapes() {
		t.Run(s.String(), func(t *testing.T) {
			fn(t, s, journeytest.NewWorld(t, s.settings()))
		})
	}
}

type account struct {
	w     *journeytest.World
	s     shape
	t     testing.TB
	Email string
	Sub   principal.Subject
}

func newAccount(t testing.TB, w *journeytest.World, s shape, local string) *account {
	t.Helper()
	email := w.FreshEmail(local)
	return &account{w: w, s: s, t: t, Email: email, Sub: w.SeedUser(email, false)}
}

type session struct {
	a       *account
	c       *journeytest.Client
	refresh string
	login   *journeytest.Resp
}

func (a *account) signIn(remember bool) *session {
	a.t.Helper()
	c := a.w.NewClient()
	req := journeytest.Req{Method: http.MethodPost, Path: "/auth" + egauth.PathLogin, JSON: map[string]any{
		egauth.FieldIdentifier: a.Email, egauth.FieldPassword: journeytest.Password,
		egauth.FieldRemember: remember, egauth.FieldReturnTo: journeytest.JourneyReturnTo,
	}}
	if a.s.bearer {
		req.Header = http.Header{egauth.HeaderTransport: {"bearer"}}
	}
	res := c.Do(req)
	if !res.Established() {
		a.t.Fatalf("sign-in of %s: %s", a.Email, journeytest.Describe(res))
	}
	if a.s.bearer {
		c.Bearer = res.Token()
	}
	return &session{a: a, c: c, refresh: res.Refresh(), login: res}
}

func (s *session) fork() *session {
	return &session{a: s.a, c: s.a.w.Fork(s.c), refresh: s.refresh}
}

func (s *session) status() int { return s.c.Session().Status }

func (s *session) view() sessionView {
	s.a.t.Helper()
	res := s.c.Session()
	require.Equal(s.a.t, http.StatusOK, res.Status, journeytest.Describe(res))
	var v sessionView
	require.NoError(s.a.t, json.Unmarshal(res.Body, &v))
	return v
}

type sessionView struct {
	Subject                string   `json:"subject"`
	Factors                []string `json:"factors"`
	AMR                    []string `json:"amr"`
	RememberMe             bool     `json:"remember_me"`
	ReturnTo               string   `json:"return_to"`
	PasswordChangeRequired bool     `json:"password_change_required"`
}

func (s *session) refreshBearer() *journeytest.Resp {
	s.a.t.Helper()
	bearer := s.c.Bearer
	s.c.Bearer = ""
	res := s.c.Do(journeytest.Req{Method: http.MethodPost, Path: "/auth" + egauth.PathRefresh, NoJar: true, Header: http.Header{
		journeytest.HeaderRefreshToken: {s.refresh},
		egauth.HeaderTransport:         {"bearer"},
	}})
	s.c.Bearer = bearer
	if tok := res.Token(); tok != "" {
		s.c.Bearer = tok
	}
	if rt := res.Refresh(); rt != "" {
		s.refresh = rt
	}
	return res
}

func (s *session) renew() *journeytest.Resp {
	s.a.t.Helper()
	s.a.w.Clock.Advance(s.a.w.RecheckEvery() + time.Second)
	if s.a.s.bearer && s.a.s.backend == journeytest.JWT {
		return s.refreshBearer()
	}
	return s.c.Session()
}

func (s *session) post(path string, fields map[string]any) *journeytest.Resp {
	return s.c.Post(path, fields)
}

func (s *session) protect() (*journeytest.Resp, bool) {
	before := s.a.w.Seen.Count()
	res := s.c.Do(journeytest.Req{Path: journeytest.ProtectRoute})
	return res, s.a.w.Seen.Count() > before
}

func (s *session) lineage() string {
	s.a.t.Helper()
	res, ran := s.protect()
	require.True(s.a.t, ran, journeytest.Describe(res))
	p, ok := s.a.w.Seen.Last()
	require.True(s.a.t, ok)
	attrs, ok := p.Session()
	require.True(s.a.t, ok)
	return attrs.Lineage().String()
}

func settle(w *journeytest.World) { w.Clock.Advance(revoke.PollBound) }

func queryParam(link, key string) string {
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return u.Query().Get(key)
}

func isSessionCookie(name string) bool {
	return strings.HasSuffix(name, "access_token") || strings.HasSuffix(name, "refresh_token") || strings.HasSuffix(name, "-session")
}

func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (a *account) multiFactorSession(secret string) *session {
	a.t.Helper()
	c := a.w.NewClient()
	res := c.LoginPassword(journeytest.Credentials{Email: a.Email, Password: journeytest.Password}, a.s.bearer)
	require.Equal(a.t, "mfa_required", res.Code(), journeytest.Describe(res))
	done := c.ChallengeTOTP(a.w, secret)
	a.w.Clock.Advance(30 * time.Second)
	require.True(a.t, done.Established(), journeytest.Describe(done))
	if a.s.bearer {
		c.Bearer = done.Token()
	}
	return &session{a: a, c: c, refresh: done.Refresh(), login: done}
}

func (a *account) forgot() (*journeytest.Client, map[string]any) {
	a.t.Helper()
	w := a.w
	n := w.MailCount("PasswordResetLink")
	c := w.NewClient()
	begin := c.Post(egauth.PathPasswordForgot, map[string]any{egauth.FieldIdentifier: a.Email})
	require.Equal(a.t, http.StatusAccepted, begin.Status, journeytest.Describe(begin))
	fields := map[string]any{
		egauth.FieldToken:       queryParam(w.WaitMail("PasswordResetLink", n+1).Link, egauth.FieldToken),
		egauth.FieldNewPassword: strongPassword,
	}
	if bind := c.Bind(begin); bind != "" && a.s.bearer {
		fields[egauth.FieldBind] = bind
	}
	return c, fields
}

func (a *account) magicLink() (*journeytest.Client, map[string]any) {
	a.t.Helper()
	w := a.w
	n := w.MailCount("MagicLink")
	c := w.NewClient()
	begin := c.Post(egauth.PathMagicLinkRequest, map[string]any{egauth.FieldIdentifier: a.Email})
	require.Equal(a.t, http.StatusAccepted, begin.Status, journeytest.Describe(begin))
	fields := map[string]any{egauth.FieldToken: queryParam(w.WaitMail("MagicLink", n+1).Link, egauth.FieldToken)}
	if bind := c.Bind(begin); bind != "" && a.s.bearer {
		fields[egauth.FieldBind] = bind
	}
	return c, fields
}

func (a *account) changeEmail(sess *session, to string) *journeytest.Resp {
	a.t.Helper()
	n := a.w.MailCount("EmailChangeLink")
	res := sess.post(egauth.PathEmailChange, map[string]any{egauth.FieldEmail: to})
	require.Equal(a.t, http.StatusAccepted, res.Status, journeytest.Describe(res))
	token := queryParam(a.w.WaitMail("EmailChangeLink", n+1).Link, egauth.FieldToken)
	return sess.post(egauth.PathEmailChangeConfirm, map[string]any{egauth.FieldToken: token})
}

func (s *session) adopt(res *journeytest.Resp) {
	if !s.a.s.bearer {
		return
	}
	if tok := res.Token(); tok != "" {
		s.c.Bearer = tok
	}
	if rt := res.Refresh(); rt != "" {
		s.refresh = rt
	}
}

func (s *session) enrollTOTP() string {
	s.a.t.Helper()
	begin := s.post(egauth.PathMFATOTPEnroll, nil)
	secret := begin.Field("secret")
	require.Equal(s.a.t, http.StatusOK, begin.Status, journeytest.Describe(begin))
	require.NotEmpty(s.a.t, secret)
	s.adopt(begin)
	confirm := s.post(egauth.PathMFATOTPConfirm, map[string]any{egauth.FieldCode: journeytest.TOTPCode(secret, s.a.w.Clock.Now())})
	require.Equal(s.a.t, http.StatusOK, confirm.Status, journeytest.Describe(confirm))
	s.adopt(confirm)
	s.a.w.Clock.Advance(30 * time.Second)
	return secret
}

func hasPasskey(t testing.TB, w *journeytest.World, s principal.Subject) bool {
	t.Helper()
	ok, err := w.Storage.Passkeys.HasActive(context.Background(), s)
	require.NoError(t, err)
	return ok
}
