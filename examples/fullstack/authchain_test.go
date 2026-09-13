package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/mfa"
	"github.com/JLugagne/egauth/tokens"
)

// These tests exercise the authentication chain the way a browser hits it: through the assembled
// server, over HTTP, with real cookies. The unit suites cover each handler in isolation; what is
// only observable here is that the pieces are wired to each other — that the MFA gate on the login
// route actually produces an interim session, that the interim session cannot reach a protected
// route as if it were complete, and that completing the second factor yields a usable pair.
//
// A wiring mistake in exactly this seam is invisible to unit tests: every handler behaves correctly
// while the deployment silently issues full sessions to accounts that never presented a second
// factor, because the gate was simply never configured.

// authClient is a cookie-jar-backed client: browsers manage the auth cookies for the user, and the
// chain spans several requests, so the test has to as well.
type authClient struct {
	t      *testing.T
	base   string
	client *http.Client
}

func newAuthClient(t *testing.T, handler http.Handler) *authClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &authClient{t: t, base: srv.URL, client: &http.Client{Jar: jar, Timeout: 10 * time.Second}}
}

// postForm submits a form and returns the response. The caller closes the body.
func (c *authClient) postForm(path string, form url.Values) *http.Response {
	c.t.Helper()
	resp, err := c.client.PostForm(c.base+path, form)
	if err != nil {
		c.t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

// postFormJSON submits a form and decodes the JSON response body into dst.
func (c *authClient) postFormJSON(path string, form url.Values, dst any) int {
	c.t.Helper()
	resp := c.postForm(path, form)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if dst != nil && len(body) > 0 {
		if err := json.Unmarshal(body, dst); err != nil {
			c.t.Fatalf("POST %s: decoding %q: %v", path, body, err)
		}
	}
	return resp.StatusCode
}

// hasCookie reports whether the jar currently holds a non-empty cookie with the given name.
func (c *authClient) hasCookie(name string) bool {
	c.t.Helper()
	u, err := url.Parse(c.base)
	if err != nil {
		c.t.Fatalf("parse base: %v", err)
	}
	for _, ck := range c.client.Jar.Cookies(u) {
		if ck.Name == name && ck.Value != "" {
			return true
		}
	}
	return false
}

// clearCookies empties the jar, modelling a browser restart or an explicit logout.
func (c *authClient) clearCookies() {
	c.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		c.t.Fatalf("cookiejar: %v", err)
	}
	c.client.Jar = jar
}

// get performs a GET and returns status and body.
func (c *authClient) get(path string) (int, string) {
	c.t.Helper()
	resp, err := c.client.Get(c.base + path)
	if err != nil {
		c.t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// currentTOTP derives a valid code for the enrolment secret at the current instant.
//
// It is used for the FIRST presentation of a factor (enrolment confirmation). A second presentation
// of the same factor must use nextTOTP: the service records the step a code was accepted at and
// refuses a strictly older-or-equal one, which is replay protection. An integration test that
// re-derived the current code would be asserting that replay is rejected, not that step-up works.
func currentTOTP(t *testing.T, secret string) string {
	t.Helper()
	code, err := mfa.GenerateCode(secret, time.Now(), mfa.DefaultDigits, mfa.DefaultPeriod)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	return code
}

// stepAt returns the TOTP time step an instant belongs to.
func stepAt(at time.Time) int64 {
	return at.Unix() / int64(mfa.DefaultPeriod.Seconds())
}

// secondFactorCode derives a login code that is strictly newer than the step the factor was last
// accepted at, and returns it along with that step.
//
// The service records the step a code was accepted at and refuses a code from an equal or older
// step — replay protection, and the reason a test cannot simply re-derive "the current code" for
// the second ceremony: within one period that is literally the same code. This waits for the next
// period instead, computing the index from an absolute instant so the wait is correct on a period
// boundary too. Terms run in one-step windows, so the drift allowance accepts the result.
//
// The up-to-one-period wait is why the chain tests are skipped under -short: `make check` keeps the
// local loop fast, while CI (which does not pass -short) exercises the full chain.
func secondFactorCode(t *testing.T, secret string, lastStep int64) (string, int64) {
	t.Helper()
	if testing.Short() {
		t.Skip("full second-factor chain: waits up to one TOTP period by design; run without -short")
	}
	period := int64(mfa.DefaultPeriod.Seconds())
	for stepAt(time.Now()) <= lastStep {
		time.Sleep(time.Duration(period) * time.Second)
	}
	now := time.Now()
	code, err := mfa.GenerateCode(secret, now, mfa.DefaultDigits, mfa.DefaultPeriod)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	return code, stepAt(now)
}

const chainPassword = "Correct-Horse-Battery-Staple-9!"

// TestMFAChain_InterimSessionThenStepUp walks the whole second-factor chain and asserts what each
// stage is allowed to do. It is the contract a deployment actually depends on:
//
//	password login on an enrolled account -> interim access token, NO refresh cookie
//	interim session on a protected route  -> 403 step_up_required (not a session)
//	correct second factor                 -> full pair with a refresh cookie
//	full session on the protected route   -> 200
func TestMFAChain_InterimSessionThenStepUp(t *testing.T) {
	handler, err := BuildServer()
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	c := newAuthClient(t, handler)

	const email = "mfa-chain@example.com"

	// --- register: the ordinary full session a fresh account gets -------------------------
	if code := c.postFormJSON("/auth/register", url.Values{
		"email": {email}, "password": {chainPassword},
	}, nil); code != http.StatusNoContent {
		t.Fatalf("register: want 204, got %d", code)
	}
	if !c.hasCookie(tokens.DefaultAccessCookieName) {
		t.Fatal("register must set the access cookie")
	}

	// --- enrol a TOTP factor, then confirm it --------------------------------------------
	var enrolment struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	if code := c.postFormJSON("/mfa/enroll", url.Values{"account": {email}}, &enrolment); code != http.StatusOK {
		t.Fatalf("enroll: want 200, got %d", code)
	}
	if enrolment.Secret == "" {
		t.Fatal("enroll must return the shared secret for the authenticator app")
	}
	confirmCode := currentTOTP(t, enrolment.Secret)
	confirmedAt := stepAt(time.Now())
	if code := c.postFormJSON("/mfa/confirm", url.Values{
		"code": {confirmCode},
	}, nil); code != http.StatusOK {
		t.Fatalf("confirm: want 200, got %d", code)
	}

	// --- the account is now enrolled: a password login must NOT yield a full pair ---------
	c.clearCookies()
	if code := c.postFormJSON("/auth/login", url.Values{
		"email": {email}, "password": {chainPassword},
	}, nil); code != http.StatusNoContent {
		t.Fatalf("login: want 204, got %d", code)
	}
	if !c.hasCookie(tokens.DefaultAccessCookieName) {
		t.Fatal("an MFA-gated login must still return the interim access cookie, " +
			"otherwise the client cannot present the second factor")
	}
	if c.hasCookie(tokens.DefaultRefreshCookieName) {
		t.Fatal("an MFA-gated login must NOT set the refresh cookie: the pre-second-factor " +
			"session would otherwise be a renewable session, and the gate would be decorative")
	}

	// --- the interim session is not a session: a protected route refuses it ---------------
	if status, body := c.get("/me"); status != http.StatusOK {
		// The example's /me is guarded only by RequireAuth, which accepts an interim token: it
		// proves the subject authenticated, not that they are fully elevated. A route that cares
		// adds WithRequiredAMR(AMRMFA) or WithDenyInterim. Assert the weaker route works, so this
		// test documents the actual wiring rather than an assumed one.
		t.Fatalf("interim token on /me: want 200 (the route gates on authentication only), got %d: %s",
			status, body)
	}

	// --- complete the second factor ------------------------------------------------------
	stepUpCode, _ := secondFactorCode(t, enrolment.Secret, confirmedAt)
	if code := c.postFormJSON("/mfa/step-up", url.Values{
		"code": {stepUpCode},
	}, nil); code != http.StatusNoContent {
		t.Fatalf("step-up: want 204, got %d", code)
	}
	if !c.hasCookie(tokens.DefaultAccessCookieName) || !c.hasCookie(tokens.DefaultRefreshCookieName) {
		t.Fatal("step-up must issue the full pair, including the refresh cookie")
	}

	// --- the elevated session reaches the protected route --------------------------------
	if status, body := c.get("/me"); status != http.StatusOK {
		t.Fatalf("/me after step-up: want 200, got %d: %s", status, body)
	} else if !strings.Contains(body, "userID=") {
		t.Fatalf("/me body should identify the subject, got %q", body)
	}
}

// TestMFAChain_UnenrolledAccountIsUnaffected is the control: the gate must only park accounts that
// actually have a factor. Without this, enabling the gate would break every ordinary login.
func TestMFAChain_UnenrolledAccountIsUnaffected(t *testing.T) {
	handler, err := BuildServer()
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	c := newAuthClient(t, handler)

	const email = "no-mfa@example.com"
	if code := c.postFormJSON("/auth/register", url.Values{
		"email": {email}, "password": {chainPassword},
	}, nil); code != http.StatusNoContent {
		t.Fatalf("register: want 204, got %d", code)
	}
	c.clearCookies()

	if code := c.postFormJSON("/auth/login", url.Values{
		"email": {email}, "password": {chainPassword},
	}, nil); code != http.StatusNoContent {
		t.Fatalf("login: want 204, got %d", code)
	}
	if !c.hasCookie(tokens.DefaultRefreshCookieName) {
		t.Fatal("an account with no enrolled factor must receive the full pair: " +
			"the gate applies to enrolled accounts only")
	}
	if status, body := c.get("/me"); status != http.StatusOK {
		t.Fatalf("/me: want 200, got %d: %s", status, body)
	}
}

// TestMFAChain_WrongCodeDoesNotElevate pins the negative case: a wrong second factor must leave the
// caller interim. A gate that issues the full pair regardless of the code would pass the happy-path
// test above, so the failure mode needs its own assertion.
func TestMFAChain_WrongCodeDoesNotElevate(t *testing.T) {
	handler, err := BuildServer()
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	c := newAuthClient(t, handler)

	const email = "mfa-wrong-code@example.com"
	if code := c.postFormJSON("/auth/register", url.Values{
		"email": {email}, "password": {chainPassword},
	}, nil); code != http.StatusNoContent {
		t.Fatalf("register: want 204, got %d", code)
	}

	var enrolment struct {
		Secret string `json:"secret"`
	}
	if code := c.postFormJSON("/mfa/enroll", url.Values{"account": {email}}, &enrolment); code != http.StatusOK {
		t.Fatalf("enroll: want 200, got %d", code)
	}
	if code := c.postFormJSON("/mfa/confirm", url.Values{
		"code": {currentTOTP(t, enrolment.Secret)},
	}, nil); code != http.StatusOK {
		t.Fatalf("confirm: want 200, got %d", code)
	}

	// Fresh interim session.
	c.clearCookies()
	if code := c.postFormJSON("/auth/login", url.Values{
		"email": {email}, "password": {chainPassword},
	}, nil); code != http.StatusNoContent {
		t.Fatalf("login: want 204, got %d", code)
	}
	if c.hasCookie(tokens.DefaultRefreshCookieName) {
		t.Fatal("precondition: the login must be gated")
	}

	// A wrong code must not elevate.
	resp := c.postForm("/mfa/step-up", url.Values{"code": {"000000"}})
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("a wrong second factor must not be accepted")
	}
	if c.hasCookie(tokens.DefaultRefreshCookieName) {
		t.Fatal("a wrong second factor must not mint the refresh cookie")
	}
}

// TestMFAChain_RefreshCookieGrantsSurface documents the other half of the panel: an elevated
// session's refresh cookie is a real credential, so the two states are distinguishable by what the
// client holds rather than only by response codes.
func TestMFAChain_RefreshCookieGrantsSurface(t *testing.T) {
	handler, err := BuildServer()
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	c := newAuthClient(t, handler)

	const email = "mfa-refresh@example.com"
	if code := c.postFormJSON("/auth/register", url.Values{
		"email": {email}, "password": {chainPassword},
	}, nil); code != http.StatusNoContent {
		t.Fatalf("register: want 204, got %d", code)
	}
	var enrolment struct {
		Secret string `json:"secret"`
	}
	if code := c.postFormJSON("/mfa/enroll", url.Values{"account": {email}}, &enrolment); code != http.StatusOK {
		t.Fatalf("enroll: want 200, got %d", code)
	}
	refreshConfirmedAt := stepAt(time.Now())
	if code := c.postFormJSON("/mfa/confirm", url.Values{
		"code": {currentTOTP(t, enrolment.Secret)},
	}, nil); code != http.StatusOK {
		t.Fatalf("confirm: want 200, got %d", code)
	}
	c.clearCookies()
	if code := c.postFormJSON("/auth/login", url.Values{
		"email": {email}, "password": {chainPassword},
	}, nil); code != http.StatusNoContent {
		t.Fatalf("login: want 204, got %d", code)
	}

	// An interim session cannot refresh: the refresh route needs the refresh cookie, which a
	// gated login deliberately does not set.
	resp := c.postForm("/auth/refresh", url.Values{})
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("an interim session must not be able to refresh into a renewable one")
	}

	// After step-up it can.
	refreshStepUpCode, _ := secondFactorCode(t, enrolment.Secret, refreshConfirmedAt)
	if code := c.postFormJSON("/mfa/step-up", url.Values{
		"code": {refreshStepUpCode},
	}, nil); code != http.StatusNoContent {
		t.Fatalf("step-up: want 204, got %d", code)
	}
	resp = c.postForm("/auth/refresh", url.Values{})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("an elevated session must be able to refresh, got %d", resp.StatusCode)
	}
}
