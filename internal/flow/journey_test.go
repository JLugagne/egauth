package flow_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/issuance"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session/stateful"
	"github.com/JLugagne/egauth/store/identity"
)

func TestLoginWithoutEnrollmentStartsASession(t *testing.T) {
	for _, bearer := range []bool{false, true} {
		w := newWorld(t)
		w.user("alice@example.com", "correct horse")
		c := w.browser()
		if bearer {
			c = w.native()
		}
		rec := c.login("alice@example.com", "correct horse", map[string]any{routes.FieldReturnTo: "/app"})
		expect(t, rec, http.StatusOK)
		if b := decode[journeyBody](t, rec); b.State != issuance.StateAuthenticated || b.ReturnTo != "/app" || b.Flow != "" {
			t.Fatalf("bearer=%v body %+v", bearer, b)
		}
		v := c.session()
		if !slices.Equal(v.Factors, []string{"pwd"}) || v.ReturnTo != "/app" {
			t.Fatalf("bearer=%v session %+v", bearer, v)
		}
		if w.sink.count(event.SessionIssued) != 1 || w.sink.count(event.LoginSucceeded) != 1 || w.sink.count(event.MFAChallengeRequired) != 0 {
			t.Fatalf("bearer=%v events issued=%d succeeded=%d", bearer, w.sink.count(event.SessionIssued), w.sink.count(event.LoginSucceeded))
		}
		if e, _ := w.sink.last(event.SessionIssued); e.Attrs[string(event.KeyMethod)] != "pwd" {
			t.Fatalf("SessionIssued attrs %v", e.Attrs)
		}
	}
}

func TestBrowserFormLoginIsRedirectedToReturnTo(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	c := w.browser()
	rec := c.form(routes.Login, url.Values{routes.FieldIdentifier: {"alice@example.com"}, routes.FieldPassword: {"correct horse"}, routes.FieldReturnTo: {"/app"}})
	expect(t, rec, http.StatusSeeOther)
	if loc := rec.Header().Get("Location"); loc != "/app" {
		t.Fatalf("Location %q", loc)
	}
	if _, ok := c.cookie(cookie.StatefulSession); !ok {
		t.Fatal("no session cookie")
	}
}

func TestRefusedReturnToFailsTheLogin(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	c := w.browser()
	expectError(t, c.login("alice@example.com", "correct horse", map[string]any{routes.FieldReturnTo: "https://evil.example/"}), http.StatusBadRequest, "invalid_return_to")
	if _, ok := c.cookie(cookie.StatefulSession); ok {
		t.Fatal("a refused return_to must not start a session")
	}
}

// TestEnrolledLoginParksAFlowAndIssuesNoCredential closes T-01, I-06, I-17 and T-07: an enrolled
// subject's password login answers mfa_required, issues no session credential, clears any session
// cookie of the client, and the flow handle cannot authenticate anywhere.
func TestEnrolledLoginParksAFlowAndIssuesNoCredential(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	w.user("bob@example.com", "battery staple")
	w.enrollTOTP("alice@example.com", "correct horse")

	c := w.browser()
	expect(t, c.login("bob@example.com", "battery staple", nil), http.StatusOK)
	if _, ok := c.cookie(cookie.StatefulSession); !ok {
		t.Fatal("bob has no session")
	}
	w.sink.reset()
	rec := c.login("alice@example.com", "correct horse", nil)
	expect(t, rec, http.StatusOK)
	b := decode[journeyBody](t, rec)
	if b.State != issuance.StateMFARequired || !slices.Equal(b.Factors, []string{"totp", "recovery_code"}) || b.Flow != "" {
		t.Fatalf("body %+v", b)
	}
	if _, ok := c.cookie(cookie.StatefulSession); ok {
		t.Fatal("the previous session cookie was not cleared")
	}
	fc, ok := c.cookie(cookie.Flow)
	if !ok || fc.SameSite != http.SameSiteStrictMode || !fc.HttpOnly || !fc.Secure {
		t.Fatalf("flow cookie %+v", fc)
	}
	expect(t, c.get(routes.Session), http.StatusUnauthorized)
	if w.sink.count(event.SessionIssued) != 0 || w.sink.count(event.MFAChallengeRequired) != 1 {
		t.Fatal("a parked login must emit MFAChallengeRequired once and no SessionIssued")
	}

	n := w.native()
	rec = n.login("alice@example.com", "correct horse", nil)
	expect(t, rec, http.StatusOK)
	b = decode[journeyBody](t, rec)
	if b.State != issuance.StateMFARequired || b.Flow == "" || rec.Header().Get(stateful.HeaderSessionToken) != "" {
		t.Fatalf("bearer body %+v", b)
	}
	if _, ok := n.cookie(cookie.Flow); ok {
		t.Fatal("a Bearer flow must not be delivered in a cookie")
	}
	n.token = b.Flow
	expect(t, n.get(routes.Session), http.StatusUnauthorized)
	expect(t, n.post(routes.MFATOTPEnroll, nil), http.StatusUnauthorized)
}

func TestChallengeCompletesTheFlow(t *testing.T) {
	for _, bearer := range []bool{false, true} {
		w := newWorld(t)
		w.user("alice@example.com", "correct horse")
		e := w.enrollTOTP("alice@example.com", "correct horse")
		c := w.browser()
		if bearer {
			c = w.native()
		}
		rec := c.login("alice@example.com", "correct horse", map[string]any{routes.FieldRemember: true, routes.FieldReturnTo: "/app"})
		expect(t, rec, http.StatusOK)
		flowHandle := decode[journeyBody](t, rec).Flow
		presented, _ := c.cookie(cookie.Flow)
		fields := map[string]any{routes.FieldFactor: "totp", routes.FieldCode: totpAt(t, e.secret, w.clock.Now())}
		if bearer {
			fields[routes.FieldFlow] = flowHandle
		}
		rec = c.post(routes.MFAChallenge, fields)
		expect(t, rec, http.StatusOK)
		if b := decode[journeyBody](t, rec); b.State != issuance.StateAuthenticated || b.ReturnTo != "/app" {
			t.Fatalf("bearer=%v body %+v", bearer, b)
		}
		if _, ok := c.cookie(cookie.Flow); ok {
			t.Fatal("the flow cookie was not cleared")
		}
		v := c.session()
		if !slices.Equal(v.Factors, []string{"pwd", "totp"}) || !v.RememberMe || v.ReturnTo != "/app" {
			t.Fatalf("bearer=%v session %+v", bearer, v)
		}
		if a := c.attrs(); a.SecondAt().IsZero() || !a.MultiFactor() {
			t.Fatal("the completed flow is not multi-factor")
		}
		if !bearer {
			if ck, _ := c.cookie(cookie.StatefulSession); ck.MaxAge <= 0 {
				t.Fatal("remember-me sealed at the primary step was lost")
			}
		}
		if w.sink.count(event.MFAVerified) != 1 || w.sink.count(event.SessionIssued) != 1 || w.sink.count(event.LoginSucceeded) != 1 {
			t.Fatalf("bearer=%v events verified=%d issued=%d", bearer, w.sink.count(event.MFAVerified), w.sink.count(event.SessionIssued))
		}
		replay := w.browser()
		if bearer {
			replay = w.native()
		} else {
			replay.cookies[presented.Name] = presented
		}
		fields[routes.FieldCode] = totpAt(t, e.secret, w.clock.Now().Add(30*time.Second))
		expectError(t, replay.post(routes.MFAChallenge, fields), http.StatusUnauthorized, "invalid_flow")
	}
}

func TestRecoveryCodeCompletesTheFlow(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	e := w.enrollTOTP("alice@example.com", "correct horse")
	c := w.browser()
	expect(t, c.login("alice@example.com", "correct horse", nil), http.StatusOK)
	rec := c.post(routes.MFAChallenge, map[string]any{routes.FieldFactor: "recovery_code", routes.FieldCode: e.codes[0]})
	expect(t, rec, http.StatusOK)
	if v := c.session(); !slices.Equal(v.Factors, []string{"pwd", "rc"}) {
		t.Fatalf("session %+v", v)
	}
}

// TestChallengeRequiresAnExplicitFactor closes D-06 and I-22: the factor is never inferred, so a
// mistyped TOTP never consumes a recovery code.
func TestChallengeRequiresAnExplicitFactor(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	e := w.enrollTOTP("alice@example.com", "correct horse")
	c := w.browser()
	expect(t, c.login("alice@example.com", "correct horse", nil), http.StatusOK)
	for _, f := range []any{nil, "", "passkey", "TOTP", "rc"} {
		fields := map[string]any{routes.FieldCode: e.codes[0]}
		if f != nil {
			fields[routes.FieldFactor] = f
		}
		expectError(t, c.post(routes.MFAChallenge, fields), http.StatusBadRequest, "invalid_factor")
	}
	expectError(t, c.post(routes.MFAChallenge, map[string]any{routes.FieldFactor: "totp", routes.FieldCode: e.codes[0]}), http.StatusUnauthorized, "invalid_code")
	expect(t, c.post(routes.MFAChallenge, map[string]any{routes.FieldFactor: "recovery_code", routes.FieldCode: e.codes[0]}), http.StatusOK)
}

func TestFlowHandleOnAnotherTransportIsRefused(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	e := w.enrollTOTP("alice@example.com", "correct horse")
	c := w.browser()
	expect(t, c.login("alice@example.com", "correct horse", nil), http.StatusOK)
	fc, _ := c.cookie(cookie.Flow)
	stolen := w.browser()
	code := totpAt(t, e.secret, w.clock.Now())
	expectError(t, stolen.post(routes.MFAChallenge, map[string]any{routes.FieldFlow: fc.Value, routes.FieldFactor: "totp", routes.FieldCode: code}),
		http.StatusUnauthorized, "invalid_flow")

	n := w.native()
	rec := n.login("alice@example.com", "correct horse", nil)
	bearerFlow := decode[journeyBody](t, rec).Flow
	viaCookie := w.browser()
	viaCookie.cookies[w.cookies.CookieName(cookie.Flow)] = &http.Cookie{Name: w.cookies.CookieName(cookie.Flow), Value: bearerFlow}
	expectError(t, viaCookie.post(routes.MFAChallenge, map[string]any{routes.FieldFactor: "totp", routes.FieldCode: code}), http.StatusUnauthorized, "invalid_flow")

	expect(t, c.post(routes.MFAChallenge, map[string]any{routes.FieldFactor: "totp", routes.FieldCode: code}), http.StatusOK)
}

// TestGuessesAcrossFlowsShareThePerSubjectLockout closes C-40: restarting the flow never resets the
// budget, because mfasvc.Verify charges the subject, not the flow.
func TestGuessesAcrossFlowsShareThePerSubjectLockout(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	e := w.enrollTOTP("alice@example.com", "correct horse")
	right := totpAt(t, e.secret, w.clock.Now())
	clients := []*client{w.browser(), w.browser(), w.browser()}
	for _, c := range clients {
		expect(t, c.login("alice@example.com", "correct horse", nil), http.StatusOK)
	}
	for i := range 5 {
		c := clients[i%len(clients)]
		expectError(t, c.post(routes.MFAChallenge, map[string]any{routes.FieldFactor: "totp", routes.FieldCode: wrongCode(right)}), http.StatusUnauthorized, "invalid_code")
	}
	expectError(t, clients[2].post(routes.MFAChallenge, map[string]any{routes.FieldFactor: "totp", routes.FieldCode: right}), http.StatusTooManyRequests, "too_many_attempts")
	if w.sink.count(event.SessionIssued) != 0 {
		t.Fatal("a locked subject was admitted")
	}
}

// TestAccountStateIsReadAtCompletion closes P-06: a subject disabled, or whose epoch moved, between
// the primary step and the second factor is never admitted.
func TestAccountStateIsReadAtCompletion(t *testing.T) {
	cases := map[string]func(w *world, s core.Subject){
		"disabled": func(w *world, s core.Subject) {
			_, err := w.identity.Apply(context.Background(), identity.SetDisabledState{Subject: s, Disable: true})
			must(w.t, err)
		},
		"epoch bumped": func(w *world, s core.Subject) {
			_, err := w.identity.Apply(context.Background(), identity.BumpEpoch{Subject: s, Change: identity.FactorPasskeyAdded})
			must(w.t, err)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			sub := w.user("alice@example.com", "correct horse")
			e := w.enrollTOTP("alice@example.com", "correct horse")
			c := w.browser()
			expect(t, c.login("alice@example.com", "correct horse", nil), http.StatusOK)
			change(w, sub)
			expect(t, c.post(routes.MFAChallenge, map[string]any{routes.FieldFactor: "totp", routes.FieldCode: totpAt(t, e.secret, w.clock.Now())}), http.StatusUnauthorized)
			if _, ok := c.cookie(cookie.StatefulSession); ok || w.sink.count(event.SessionIssued) != 0 {
				t.Fatal("a session was issued")
			}
		})
	}
}

// TestModuleMissingNeverIssues closes C-01: an enrolled subject is never authenticated when the
// module completing its factor is absent; the decision itself does not depend on modules.
func TestModuleMissingNeverIssues(t *testing.T) {
	w := newWorldWith(t, options{noMFAModule: true})
	w.user("alice@example.com", "correct horse")
	w.enrollTOTP("alice@example.com", "correct horse")
	c := w.browser()
	rec := c.login("alice@example.com", "correct horse", nil)
	expect(t, rec, http.StatusOK)
	if b := decode[journeyBody](t, rec); b.State != issuance.StateMFARequired || len(b.Factors) != 0 {
		t.Fatalf("body %+v", b)
	}
	if _, ok := c.cookie(cookie.Flow); ok {
		t.Fatal("a flow nobody can complete was parked")
	}
	if _, ok := c.cookie(cookie.StatefulSession); ok || w.sink.count(event.SessionIssued) != 0 {
		t.Fatal("a session was issued")
	}
	if w.sink.count(event.MFAModuleMissing) != 1 {
		t.Fatal("MFAModuleMissing was not emitted")
	}
	expect(t, c.post(routes.MFAChallenge, map[string]any{routes.FieldFactor: "totp", routes.FieldCode: "000000"}), http.StatusNotFound)
}

func TestPasskeyStepUpCompletesTheFlow(t *testing.T) {
	for _, bearer := range []bool{false, true} {
		w := newWorld(t)
		w.user("alice@example.com", "correct horse")
		a := w.enrollPasskey("alice@example.com", "correct horse")
		c := w.browser()
		if bearer {
			c = w.native()
		}
		rec := c.login("alice@example.com", "correct horse", nil)
		expect(t, rec, http.StatusOK)
		b := decode[journeyBody](t, rec)
		if !slices.Equal(b.Factors, []string{"recovery_code", "passkey"}) {
			t.Fatalf("factors %v", b.Factors)
		}
		rec = c.finishStepUp(a, b.Flow)
		expect(t, rec, http.StatusOK)
		if v := c.session(); !slices.Equal(v.Factors, []string{"pk_stepup", "pwd"}) {
			t.Fatalf("bearer=%v session %+v", bearer, v)
		}
		if w.sink.count(event.MFAVerified) != 1 || w.sink.count(event.SessionIssued) != 1 {
			t.Fatalf("bearer=%v events verified=%d issued=%d", bearer, w.sink.count(event.MFAVerified), w.sink.count(event.SessionIssued))
		}
		if e, _ := w.sink.last(event.MFAVerified); e.Attrs[string(event.KeyFactor)] != "pk_stepup" {
			t.Fatalf("MFAVerified attrs %v", e.Attrs)
		}
	}
}

func TestStepUpOfAnotherFlowIsRefused(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	a := w.enrollPasskey("alice@example.com", "correct horse")
	first, second := w.native(), w.native()
	flowA := decode[journeyBody](t, first.login("alice@example.com", "correct horse", nil)).Flow
	w.clock.Advance(time.Second)
	flowB := decode[journeyBody](t, second.login("alice@example.com", "correct horse", map[string]any{routes.FieldReturnTo: "/b"})).Flow
	rec := first.post(routes.MFAPasskeyBegin, map[string]any{routes.FieldFlow: flowA})
	expect(t, rec, http.StatusOK)
	ch := decode[passkeyChallenge](t, rec)
	body := map[string]any{}
	must(t, json.Unmarshal(a.Login(t, ch.Options), &body))
	body[routes.FieldHandle] = ch.Handle
	body[routes.FieldFlow] = flowB
	expectError(t, second.post(routes.MFAPasskeyFinish, body), http.StatusUnauthorized, "invalid_flow")
	if w.sink.count(event.SessionIssued) != 0 {
		t.Fatal("a step-up of flow A completed flow B")
	}
	expect(t, second.finishStepUp(a, flowB), http.StatusOK)
}

func TestAClaimsOutageAtAdmissionIssuesNothing(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	w.claims.down.Store(true)
	c := w.browser()
	expectError(t, c.login("alice@example.com", "correct horse", nil), http.StatusServiceUnavailable, "claims_unavailable")
	if _, ok := c.cookie(cookie.StatefulSession); ok || w.sink.count(event.ClaimsUnavailable) != 1 {
		t.Fatal("a claims outage must fail the login with ClaimsUnavailable")
	}
}

func TestAnEnrollmentReadFailureFailsClosed(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	w.mfa.down.Store(true)
	c := w.browser()
	expectError(t, c.login("alice@example.com", "correct horse", nil), http.StatusServiceUnavailable, "auth_unavailable")
	if _, ok := c.cookie(cookie.StatefulSession); ok || w.sink.count(event.SessionIssued) != 0 {
		t.Fatal("an enrollment outage admitted the login")
	}
}

func TestPagesRedirectBrowsers(t *testing.T) {
	w := newWorldWith(t, options{pages: issuance.Pages{AfterLogin: "/home", MFA: "/mfa"}})
	w.user("alice@example.com", "correct horse")
	w.user("bob@example.com", "battery staple")
	w.enrollTOTP("bob@example.com", "battery staple")
	c := w.browser()
	rec := c.form(routes.Login, url.Values{routes.FieldIdentifier: {"alice@example.com"}, routes.FieldPassword: {"correct horse"}})
	expect(t, rec, http.StatusSeeOther)
	if loc := rec.Header().Get("Location"); loc != "/home" {
		t.Fatalf("after login Location %q", loc)
	}
	rec = w.browser().form(routes.Login, url.Values{routes.FieldIdentifier: {"bob@example.com"}, routes.FieldPassword: {"battery staple"}})
	expect(t, rec, http.StatusSeeOther)
	if loc := rec.Header().Get("Location"); loc != "/mfa" {
		t.Fatalf("parked Location %q", loc)
	}
}
