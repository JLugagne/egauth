package journeytest_test

import (
	"net/http"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/journeytest"
)

type resourceEnv struct {
	rw *journeytest.ResourceWorld
	w  *journeytest.World
}

func (r *resourceEnv) token(c *journeytest.Client, audience string) string {
	resp := c.Post(egauth.PathResourceToken, map[string]any{egauth.FieldResource: audience})
	return resp.Field("token")
}

func (r *resourceEnv) call(bearer string, mut ...func(*journeytest.Req)) *journeytest.Resp {
	rc := journeytest.NewBareClient(r.w.T, r.rw.Handler, "https://resources.example.test")
	req := journeytest.Req{Path: journeytest.ResourceRoute, NoJar: true, Remote: rc.FreshRemote()}
	if bearer != "" {
		req.Header = http.Header{"Authorization": {"Bearer " + bearer}}
	}
	for _, m := range mut {
		m(&req)
	}
	return rc.Do(req)
}

func resourceProbes(rw *journeytest.ResourceWorld) []journeytest.Probe {
	w := rw.Auth
	e := &resourceEnv{rw: rw, w: w}
	ae := newEnv(w)
	var ps []journeytest.Probe
	add := func(name, want string, control bool, run func() (string, bool)) {
		ps = append(ps, journeytest.Probe{Category: "resource-server", Name: "resource-server/" + name, Want: want, Control: control, Run: run})
	}
	deny := func(r *journeytest.Resp) (string, bool) {
		return journeytest.Describe(r), r.Status == http.StatusUnauthorized
	}
	session := func(bearer bool) (*journeytest.Client, string) {
		c, _ := ae.loggedIn("rs", bearer)
		return c, c.Bearer
	}
	add("resource-token-for-its-audience", "200", true, func() (string, bool) {
		c, _ := session(true)
		tok := e.token(c, journeytest.AudienceOne)
		r := e.call(tok)
		return journeytest.Describe(r), r.Status == http.StatusOK && tok != ""
	})
	add("no-credential", "401", false, func() (string, bool) { return deny(e.call("")) })
	add("garbage-bearer", "401", false, func() (string, bool) { return deny(e.call("not-a-token")) })
	add("session-access-token", "401", false, func() (string, bool) {
		_, access := session(true)
		return deny(e.call(access))
	})
	add("cookie-session", "401", false, func() (string, bool) {
		c, _ := session(false)
		return deny(e.call("", func(r *journeytest.Req) { r.Cookies, r.NoJar = c.Cookies(), true }))
	})
	add("api-key", "401", false, func() (string, bool) {
		_, sub := ae.user("rskey", false)
		return deny(e.call(w.SeedAPIKey(sub, journeytest.APIKeyKind, []string{"user"}, nil)))
	})
	add("resource-token-for-another-audience", "401", false, func() (string, bool) {
		c, _ := session(true)
		return deny(e.call(e.token(c, journeytest.AudienceTwo)))
	})
	add("expired-resource-token", "401", false, func() (string, bool) {
		c, _ := session(true)
		tok := e.token(c, journeytest.AudienceOne)
		w.Clock.Advance(w.RecheckEvery() + time.Minute)
		return deny(e.call(tok))
	})
	add("token-of-a-disabled-subject", "401", false, func() (string, bool) {
		c, sub := ae.loggedIn("rsdisabled", true)
		tok := e.token(c, journeytest.AudienceOne)
		w.SetDisabled(sub, true)
		w.Clock.Advance(10 * time.Second)
		return deny(e.call(tok))
	})
	add("token-after-logout-everywhere", "401", false, func() (string, bool) {
		c, _ := ae.loggedIn("rslogout", true)
		tok := e.token(c, journeytest.AudienceOne)
		c.Post(egauth.PathLogoutEverywhere, nil)
		w.Clock.Advance(10 * time.Second)
		return deny(e.call(tok))
	})
	add("unknown-path", "404", false, func() (string, bool) {
		rc := journeytest.NewBareClient(w.T, rw.Handler, "https://resources.example.test")
		r := rc.Do(journeytest.Req{Path: "/no-such-route", NoJar: true})
		return journeytest.Describe(r), r.Status == http.StatusNotFound
	})
	return ps
}
