package journeytest_test

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/journeytest"
	"github.com/JLugagne/egauth/store/identity"
)

const mustChangeExpect = "403 password_change_required (anonymous on Optional) unless the endpoint accepts a must-change session"

func (e *env) sessionStateProbes() []journeytest.Probe {
	var ps []journeytest.Probe
	for _, bearer := range e.transports() {
		ps = append(ps, e.handleAsSession(bearer)...)
		ps = append(ps, e.mustChange(bearer)...)
		ps = append(ps, e.disabled(bearer)...)
		ps = append(ps, e.epochStale(bearer)...)
	}
	return ps
}

func (e *env) handleAsSession(bearer bool) []journeytest.Probe {
	w := e.w
	attack := lazy(func() *journeytest.Client {
		acct := w.MFAUser("flow")
		victim := w.NewClient()
		r := victim.LoginPassword(journeytest.Credentials{Email: acct.Email, Password: journeytest.Password}, bearer)
		handle := victim.FlowHandle(r)
		if bearer {
			c := w.NewClient()
			c.Bearer = handle
			return c
		}
		c := w.NewClient()
		c.Jar([]*http.Cookie{
			{Name: "__Host-access_token", Value: handle},
			{Name: "__Host-refresh_token", Value: handle},
			{Name: "__Host-session", Value: handle},
		})
		return c
	})
	return e.stateProbes("session-state", state{
		name: "mfa-flow-handle-as-session", bearer: bearer, make: attack,
		filter: func(t target) bool { return isCredentialed(t) },
		expect: denied401, want: "401 (anonymous on Optional)",
	})
}

func (e *env) mustChange(bearer bool) []journeytest.Probe {
	w := e.w
	mk := func() *journeytest.Client {
		email, _ := e.user("must", true)
		c := w.NewClient()
		c.Login(email, bearer)
		return c
	}
	return e.stateProbes("session-state", state{
		name: "must-change", bearer: bearer, make: mk, want: mustChangeExpect,
		filter: isSession,
		expect: func(t target, r *journeytest.Resp, o observed) (string, bool) {
			switch {
			case t.kind == kOptional:
				return anonymousOnly(t, r, o)
			case t.kind == kAuth && t.meta.AcceptsMustChange:
				return got(r, o), (r.Status != http.StatusForbidden || r.Code() != "password_change_required") && (r.Status != http.StatusUnauthorized || r.Code() != "unauthenticated")
			}
			return refused(http.StatusForbidden, "password_change_required")(t, r, o)
		},
	})
}

func (e *env) disabled(bearer bool) []journeytest.Probe {
	w := e.w
	mk := func() *journeytest.Client {
		c, sub := e.loggedIn("disabled", bearer)
		w.SetDisabled(sub, true)
		advance(w, 10*time.Second)
		return c
	}
	return e.stateProbes("session-state", state{
		name: "disabled-subject", bearer: bearer, make: mk, want: "401 (anonymous on Optional)",
		filter: isSession, expect: denied401,
	})
}

func (e *env) epochStale(bearer bool) []journeytest.Probe {
	w := e.w
	mk := func() *journeytest.Client {
		c, sub := e.loggedIn("epoch", bearer)
		if _, err := w.Storage.Identity.Apply(context.Background(), identity.BumpEpoch{Subject: sub, Change: identity.FactorRecoveryCodesRegenerated}); err != nil {
			w.T.Fatalf("bumping the epoch: %v", err)
		}
		advance(w, 10*time.Second)
		return c
	}
	return e.stateProbes("session-state", state{
		name: "epoch-stale", bearer: bearer, make: mk, want: "401 (anonymous on Optional)",
		filter: isSession, expect: denied401,
	})
}

func (e *env) age(c *journeytest.Client, bearer bool, d time.Duration) {
	advance(e.w, d)
	if bearer && e.w.Settings.Backend != journeytest.Stateful {
		c.RefreshBearer()
	}
}

func (e *env) sensitiveProbes() []journeytest.Probe {
	var ps []journeytest.Probe
	sensitive := func(t target) bool { return t.kind == kAuth && t.meta.Sensitive }
	reauth := refused(http.StatusForbidden, "reauth_required")
	w := e.w
	for _, bearer := range e.transports() {
		stale := func() *journeytest.Client {
			c, _ := e.loggedIn("stale", bearer)
			e.age(c, bearer, w.ReauthWindow()+time.Minute)
			return c
		}
		ps = append(ps, e.stateProbes("sensitive", state{
			name: "stale-primary-at", bearer: bearer, make: stale, want: "403 reauth_required",
			filter: sensitive, expect: reauth,
		})...)
		ps = append(ps, e.stateProbes("sensitive", state{
			name: "stale-primary-at-fresh-route", bearer: bearer, make: stale, want: "403 forbidden",
			filter: func(t target) bool { return t.path == journeytest.FreshRoute },
			expect: refused(http.StatusForbidden, "forbidden"),
		})...)
		enrolled := func() *journeytest.Client {
			c, sub := e.loggedIn("enrolled", bearer)
			w.EnrollTOTP(sub)
			return c
		}
		ps = append(ps, e.stateProbes("sensitive", state{
			name: "enrolled-without-multifactor", bearer: bearer, make: enrolled, want: "403 reauth_required",
			filter: sensitive, expect: reauth,
		})...)
		ps = append(ps, e.stateProbes("sensitive", state{
			name: "enrolled-without-multifactor-mfa-route", bearer: bearer, make: enrolled, want: "403 forbidden",
			filter: func(t target) bool { return t.path == journeytest.MFARoute },
			expect: refused(http.StatusForbidden, "forbidden"),
		})...)
		ps = append(ps, e.passwordOnlyReauth(bearer, sensitive)...)
	}
	return ps
}

func (e *env) passwordOnlyReauth(bearer bool, sensitive func(target) bool) []journeytest.Probe {
	w := e.w
	prefix := "sensitive/password-only-reauth-on-mfa-session/" + transportName(bearer) + "/"
	mk := lazy(func() *journeytest.Client {
		acct := w.MFAUser("mfareauth")
		c := w.NewClient()
		c.LoginPassword(journeytest.Credentials{Email: acct.Email, Password: journeytest.Password}, bearer)
		if r := c.ChallengeTOTP(w, acct.Secret); !r.Established() {
			w.T.Fatalf("MFA login: %s", journeytest.Describe(r))
		}
		e.age(c, bearer, w.ReauthWindow()+time.Minute)
		return c
	})
	ps := []journeytest.Probe{{
		Category: "sensitive", Name: prefix + "reauth", Want: "200 mfa_required",
		Run: func() (string, bool) {
			r := mk().Post(egauth.PathReauth, map[string]any{egauth.FieldPassword: journeytest.Password})
			return journeytest.Describe(r), r.Status == http.StatusOK && r.Code() == "mfa_required"
		},
	}}
	for _, t := range e.where(sensitive) {
		ps = append(ps, journeytest.Probe{
			Category: "sensitive", Name: prefix + t.label(), Want: "403 reauth_required",
			Run: func() (string, bool) {
				r, o := e.hit(mk(), t)
				return refused(http.StatusForbidden, "reauth_required")(t, r, o)
			},
		})
	}
	return ps
}

func (e *env) sessionLimitProbes() []journeytest.Probe {
	var ps []journeytest.Probe
	for _, bearer := range e.transports() {
		for _, t := range e.where(func(t target) bool { return t.kind == kAuth && t.meta.SessionLimit != 0 && !t.meta.EndsSession }) {
			burst := t.meta.SessionLimit.Budget().Burst
			ps = append(ps, journeytest.Probe{
				Category: "limits", Name: "limits/session-burst-plus-one/" + transportName(bearer) + "/" + t.label(),
				Want: "429 on request " + strconv.Itoa(burst+1),
				Run: func() (string, bool) {
					c, _ := e.loggedIn("sessionlimit", bearer)
					at, last := 0, (*journeytest.Resp)(nil)
					for i := 0; i <= burst+1; i++ {
						r := journeytest.Req{Method: t.method, Path: t.path, Remote: c.FreshRemote()}
						if t.meta.Mutation {
							r.JSON = map[string]any{}
						}
						last = c.Do(r)
						if last.Status == http.StatusTooManyRequests {
							at = i + 1
							break
						}
					}
					return "429 on request " + strconv.Itoa(at) + " (" + journeytest.Describe(last) + ")", at == burst+1
				},
			})
		}
	}
	return ps
}
