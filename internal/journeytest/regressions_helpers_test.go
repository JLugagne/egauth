package journeytest_test

import (
	"encoding/json"
	"maps"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/journeytest"
	"github.com/JLugagne/egauth/webauthntest"
)

type optionsBody struct {
	Options json.RawMessage `json:"options"`
	Handle  string          `json:"handle"`
}

func decodeOptions(t testing.TB, res *journeytest.Resp) optionsBody {
	t.Helper()
	var b optionsBody
	require.NoError(t, json.Unmarshal(res.Body, &b), journeytest.Describe(res))
	require.NotEmpty(t, b.Options, "no passkey options in "+journeytest.Describe(res))
	return b
}

func mergeFields(t testing.TB, raw []byte, extra map[string]any) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	maps.Copy(m, extra)
	return m
}

func (s *session) registerPasskey(key *webauthntest.Authenticator) {
	s.a.t.Helper()
	begin := s.post(egauth.PathPasskeyRegisterBegin, nil)
	require.Equal(s.a.t, http.StatusOK, begin.Status, journeytest.Describe(begin))
	s.adopt(begin)
	b := decodeOptions(s.a.t, begin)
	finish := s.post(egauth.PathPasskeyRegisterFinish, mergeFields(s.a.t, key.Register(s.a.t, b.Options), map[string]any{egauth.FieldHandle: b.Handle}))
	require.Equal(s.a.t, http.StatusOK, finish.Status, journeytest.Describe(finish))
	s.adopt(finish)
	settle(s.a.w)
}

func (a *account) loginBegin(c *journeytest.Client, extra map[string]any) *journeytest.Resp {
	a.t.Helper()
	fields := map[string]any{}
	maps.Copy(fields, extra)
	res := c.Post(egauth.PathPasskeyLoginBegin, fields)
	require.Equal(a.t, http.StatusOK, res.Status, journeytest.Describe(res))
	return res
}

func (a *account) loginFinish(c *journeytest.Client, begin *journeytest.Resp, assertion []byte) *journeytest.Resp {
	a.t.Helper()
	b := decodeOptions(a.t, begin)
	extra := map[string]any{egauth.FieldHandle: b.Handle}
	if bind := c.Bind(begin); bind != "" && a.s.bearer {
		extra[egauth.FieldBind] = bind
	}
	return c.Post(egauth.PathPasskeyLoginFinish, mergeFields(a.t, assertion, extra))
}

func (a *account) passkeySession(key *webauthntest.Authenticator) *session {
	a.t.Helper()
	c := a.w.NewClient()
	begin := a.loginBegin(c, map[string]any{egauth.FieldIdentifier: a.Email})
	res := a.loginFinish(c, begin, key.Login(a.t, decodeOptions(a.t, begin).Options))
	require.True(a.t, res.Established(), journeytest.Describe(res))
	if a.s.bearer {
		c.Bearer = res.Token()
	}
	return &session{a: a, c: c, refresh: res.Refresh(), login: res}
}

func (a *account) withPasskeys(n int) []*webauthntest.Authenticator {
	a.t.Helper()
	keys := []*webauthntest.Authenticator{webauthntest.New(a.w.Origin)}
	a.signIn(false).registerPasskey(keys[0])
	for len(keys) < n {
		next := webauthntest.New(a.w.Origin)
		a.passkeySession(keys[len(keys)-1]).registerPasskey(next)
		keys = append(keys, next)
	}
	return keys
}
