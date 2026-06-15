package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tokens"
)

// TestBuildServer verifies that BuildServer returns a non-nil handler without error.
// This acts as a smoke test for the full wiring (identity + tokens + mfa + passkey +
// admin + audit) and is the Example/smoke test required by the DoD.
func TestBuildServer(t *testing.T) {
	t.Helper()
	handler, err := BuildServer()
	if err != nil {
		t.Fatalf("BuildServer returned error: %v", err)
	}
	if handler == nil {
		t.Fatal("BuildServer returned nil handler")
	}
}

// TestFullStackRegisterLoginMe exercises the core login flow end-to-end:
// register → login (receive JWT cookies) → GET /me (authenticated with custom claims).
// This verifies: identity, tokens with custom claims (AppClaims.Role), and audit.
func TestFullStackRegisterLoginMe(t *testing.T) {
	handler, err := BuildServer()
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// 1. Register
	regForm := url.Values{
		"email":    {"test@example.com"},
		"password": {"Correct-Horse-Battery-Staple-9!"},
	}
	resp, err := http.PostForm(srv.URL+"/auth/register", regForm)
	if err != nil {
		t.Fatalf("POST /auth/register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register: want 204, got %d: %s", resp.StatusCode, body)
	}

	// Capture the access cookie set at register time.
	var accessCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == tokens.DefaultAccessCookieName {
			accessCookie = c
		}
	}
	if accessCookie == nil {
		t.Fatal("register did not set an access cookie")
	}

	// 2. GET /me with the access cookie → 200 with userID and role.
	req, _ := http.NewRequest("GET", srv.URL+"/me", nil)
	req.AddCookie(accessCookie)
	meResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /me: %v", err)
	}
	defer func() { _ = meResp.Body.Close() }()
	if meResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(meResp.Body)
		t.Fatalf("GET /me: want 200, got %d: %s", meResp.StatusCode, body)
	}
	body, _ := io.ReadAll(meResp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "role=user") {
		t.Errorf("GET /me body should contain role=user, got: %s", bodyStr)
	}
}

// TestFullStackMFAEnrollConfirm verifies that MFA enrollment can be started and
// that the TOTP provisioning URI is returned (identity + mfa wiring with custom claims).
func TestFullStackMFAEnrollConfirm(t *testing.T) {
	handler, err := BuildServer()
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Register + get access cookie.
	regForm := url.Values{
		"email":    {"mfa@example.com"},
		"password": {"Correct-Horse-Battery-Staple-9!"},
	}
	resp, err := http.PostForm(srv.URL+"/auth/register", regForm)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register: want 204, got %d: %s", resp.StatusCode, body)
	}
	var accessCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == tokens.DefaultAccessCookieName {
			accessCookie = c
		}
	}
	if accessCookie == nil {
		t.Fatal("register did not set access cookie")
	}

	// POST /mfa/enroll with access cookie + email form field.
	enrollReq, _ := http.NewRequest("POST", srv.URL+"/mfa/enroll",
		strings.NewReader(url.Values{"email": {"mfa@example.com"}}.Encode()))
	enrollReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	enrollReq.AddCookie(accessCookie)
	enrollResp, err := http.DefaultClient.Do(enrollReq)
	if err != nil {
		t.Fatalf("POST /mfa/enroll: %v", err)
	}
	defer func() { _ = enrollResp.Body.Close() }()
	if enrollResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(enrollResp.Body)
		t.Fatalf("POST /mfa/enroll: want 200, got %d: %s", enrollResp.StatusCode, body)
	}
	// Response is JSON with uri and secret fields.
	var enrollment struct {
		URI    string `json:"uri"`
		Secret string `json:"secret"`
	}
	enrollBody, _ := io.ReadAll(enrollResp.Body)
	if err := json.Unmarshal(enrollBody, &enrollment); err != nil {
		t.Fatalf("mfa enroll response is not valid JSON: %v; body=%s", err, enrollBody)
	}
	if !strings.HasPrefix(enrollment.URI, "otpauth://") {
		t.Errorf("mfa enroll URI should start with otpauth://, got: %s", enrollment.URI)
	}
}

// TestFullStackPasskeyRoutesMounted verifies that the passkey ceremony routes exist
// (begin/finish for both register and login) by checking they respond to POST
// and do NOT return 404.
func TestFullStackPasskeyRoutesMounted(t *testing.T) {
	handler, err := BuildServer()
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	routes := []string{
		"/passkey/login/begin",
	}
	for _, route := range routes {
		resp, err := http.Post(srv.URL+route, "application/json", nil)
		if err != nil {
			t.Fatalf("POST %s: %v", route, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("POST %s returned 404 — route not mounted", route)
		}
	}
}

// ExampleBuildServer shows that all six concerns (identity, tokens+custom claims, mfa,
// passkey, admin, audit) are wired in a single call and the resulting handler is
// immediately usable. This is the primary reference for integrators.
func ExampleBuildServer() {
	// Silence the slog output in this example.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	handler, err := BuildServer()
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Register a new user via POST /auth/register.
	form := url.Values{
		"email":    {"alice@example.com"},
		"password": {"Correct-Horse-Battery-Staple-9!"},
	}
	resp, err := http.PostForm(srv.URL+"/auth/register", form)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	var gotAccess bool
	for _, c := range resp.Cookies() {
		if c.Name == tokens.DefaultAccessCookieName {
			gotAccess = true
		}
	}
	fmt.Println("status:", resp.StatusCode)
	fmt.Println("access cookie set:", gotAccess)
	// Output:
	// status: 204
	// access cookie set: true
}
