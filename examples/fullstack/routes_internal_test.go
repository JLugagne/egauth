package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/internal/journeytest"
)

const registrantPassword = "tapir-granite-velvet-orbit-29"

type rig struct {
	t      *testing.T
	box    *egauthtest.Mailbox
	admins map[uuid.UUID]bool
	h      http.Handler
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, box: &egauthtest.Mailbox{}, admins: map[uuid.UUID]bool{}}
	h, closeFn, err := compose(slog.New(slog.NewTextHandler(io.Discard, nil)), journeytest.ExampleOrigin, r.box, r.admins)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	t.Cleanup(func() { _ = closeFn() })
	r.h = h
	return r
}

func (r *rig) client() *journeytest.Client {
	return journeytest.NewBareClient(r.t, r.h, journeytest.ExampleOrigin)
}

func (r *rig) waitToken(kind string) string {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m, ok := r.box.Last(kind); ok {
			u, err := url.Parse(m.Link)
			if err != nil {
				r.t.Fatalf("link: %v", err)
			}
			return u.Query().Get(egauth.FieldToken)
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.t.Fatalf("no %s mail", kind)
	return ""
}

func (r *rig) register(c *journeytest.Client, email string) {
	r.t.Helper()
	begin := c.Post(egauth.PathRegister, map[string]any{egauth.FieldIdentifier: email, egauth.FieldPassword: registrantPassword})
	if begin.Status != http.StatusAccepted {
		r.t.Fatalf("register: %d %s", begin.Status, begin.Body)
	}
	done := c.Post(egauth.PathRegisterConfirm, map[string]any{egauth.FieldToken: r.waitToken("RegistrationLink")})
	if !done.Established() {
		r.t.Fatalf("confirm: %d %s", done.Status, done.Body)
	}
}

func (r *rig) subject(c *journeytest.Client) uuid.UUID {
	r.t.Helper()
	res := c.Do(journeytest.Req{Path: "/me"})
	if res.Status != http.StatusOK {
		r.t.Fatalf("/me: %d %s", res.Status, res.Body)
	}
	const prefix = "user="
	body := string(res.Body)
	end := len(prefix)
	for end < len(body) && body[end] != ' ' {
		end++
	}
	id, err := uuid.Parse(body[len(prefix):end])
	if err != nil {
		r.t.Fatalf("/me body %q: %v", body, err)
	}
	return id
}

func (r *rig) disable(c *journeytest.Client) int {
	res := c.Do(journeytest.Req{Method: http.MethodPost, Path: "/admin/disable/" + uuid.NewString()})
	return res.Status
}

func TestRoutesAuthorizeEstablishedCallers(t *testing.T) {
	r := newRig(t)
	email := "member@example.test"
	c := r.client()
	r.register(c, email)

	if got := c.Do(journeytest.Req{Path: "/me"}).Status; got != http.StatusOK {
		t.Fatalf("/me for a session: %d", got)
	}
	if got := r.disable(c); got != http.StatusForbidden && got != http.StatusUnauthorized {
		t.Fatalf("a non-admin session reached /admin/disable: %d", got)
	}
	if got := c.Do(journeytest.Req{Path: "/api/report"}).Status; got != http.StatusUnauthorized && got != http.StatusForbidden {
		t.Fatalf("a session caller reached the API-key route: %d", got)
	}

	r.admins[r.subject(c)] = true
	admin := r.client()
	if res := admin.LoginPassword(journeytest.Credentials{Email: email, Password: registrantPassword}, false); !res.Established() {
		t.Fatalf("admin login: %d %s", res.Status, res.Body)
	}
	if got := r.disable(admin); got == http.StatusNotFound || got == http.StatusNoContent {
		t.Fatalf("an admin without a second factor reached the disable handler: %d", got)
	}

	enroll := admin.Post(egauth.PathMFATOTPEnroll, nil)
	secret := enroll.Field("secret")
	if enroll.Status != http.StatusOK || secret == "" {
		t.Fatalf("enroll: %d %s", enroll.Status, enroll.Body)
	}
	confirmAt := time.Now()
	if res := admin.Post(egauth.PathMFATOTPConfirm, map[string]any{egauth.FieldCode: journeytest.TOTPCode(secret, confirmAt)}); res.Status != http.StatusOK {
		t.Fatalf("confirm: %d %s", res.Status, res.Body)
	}

	if got := admin.Do(journeytest.Req{Path: "/me"}).Status; got != http.StatusOK {
		t.Fatalf("the enrolling session was refused right after the second factor was confirmed: %d", got)
	}
	second := r.client()
	login := second.LoginPassword(journeytest.Credentials{Email: email, Password: registrantPassword}, false)
	if login.Established() {
		t.Fatalf("an MFA subject was established by the password alone: %d %s", login.Status, login.Body)
	}
	if got := r.disable(second); got != http.StatusUnauthorized && got != http.StatusForbidden {
		t.Fatalf("a pending MFA flow reached /admin/disable: %d", got)
	}
	code := journeytest.TOTPCode(secret, confirmAt.Add(30*time.Second))
	if res := second.Post(egauth.PathMFAChallenge, map[string]any{egauth.FieldFactor: "totp", egauth.FieldCode: code}); !res.Established() {
		t.Fatalf("challenge: %d %s", res.Status, res.Body)
	}
	if got := r.disable(second); got != http.StatusNotFound {
		t.Fatalf("an admin with a completed second factor: want 404 from the handler, got %d", got)
	}
}

func TestAPIKeyRouteRequiresItsScope(t *testing.T) {
	r := newRig(t)
	c := r.client()
	r.register(c, "keys@example.test")

	issue := func(scope string) string {
		res := c.Do(journeytest.Req{Method: http.MethodPost, Path: "/api/keys?scope=" + scope})
		if res.Status != http.StatusOK || len(res.Body) == 0 {
			t.Fatalf("issue key (scope %q): %d %s", scope, res.Status, res.Body)
		}
		return string(res.Body)
	}
	call := func(key string) int {
		return r.client().Do(journeytest.Req{Path: "/api/report", Header: http.Header{"Authorization": {"Bearer " + key}}}).Status
	}

	if got := call(issue("report:read")); got != http.StatusOK {
		t.Fatalf("a key with report:read: want 200, got %d", got)
	}
	if got := call(issue("")); got != http.StatusForbidden && got != http.StatusUnauthorized {
		t.Fatalf("a key without report:read reached the report: %d", got)
	}
}
