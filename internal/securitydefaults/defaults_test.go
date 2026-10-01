// Executable defaults: the security promises the documentation makes, asserted against the code
// so a doc-only default cannot drift from the implementation. Everything here is cheap and
// in-process; nothing needs a live network or a running server.
package securitydefaults

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/secretpolicy"

	tokensmemory "github.com/JLugagne/egauth/tokens/memory"

	"github.com/JLugagne/egauth/authflow"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/origin"
	"github.com/JLugagne/egauth/passkey"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/webapp"
)

func defaultsRandomBytes(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return buf
}

// TestCookieDefaultsAreSecure pins the cookie contract the docs promise: __Host- prefixes,
// Secure, HttpOnly, SameSite=Lax and Path=/ out of the box.
func TestCookieDefaultsAreSecure(t *testing.T) {
	cookies := tokens.DefaultCookies()
	if cookies.Insecure {
		t.Error("tokens.DefaultCookies must not be insecure")
	}
	rec := httptest.NewRecorder()
	cookies.SetAccess(rec, "access-token")
	cookies.SetRefresh(rec, "refresh-token", time.Now().Add(time.Hour), true)
	set := rec.Result().Cookies()
	if len(set) != 2 {
		t.Fatalf("want the access and refresh cookies, got %d", len(set))
	}
	for _, c := range set {
		if !c.Secure {
			t.Errorf("cookie %s must be Secure by default", c.Name)
		}
		if !c.HttpOnly {
			t.Errorf("cookie %s must be HttpOnly by default", c.Name)
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("cookie %s SameSite = %v, want Lax", c.Name, c.SameSite)
		}
		if c.Path != "/" {
			t.Errorf("cookie %s Path = %q, want /", c.Name, c.Path)
		}
		if !strings.HasPrefix(c.Name, "__Host-") {
			t.Errorf("cookie %s must carry the __Host- prefix by default", c.Name)
		}
	}
}

// TestOriginMiddlewareBlocksCrossSiteByDefault pins CSRF-by-default: origin.Middleware refuses
// unsafe cross-site requests and requests with neither Origin nor Referer even with no options.
func TestOriginMiddlewareBlocksCrossSiteByDefault(t *testing.T) {
	var reached int
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.WriteHeader(http.StatusNoContent)
	})
	h := origin.Middleware(next)

	cross := httptest.NewRequest(http.MethodPost, "https://app.example.com/x", nil)
	cross.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, cross)
	if rec.Code != http.StatusForbidden || reached != 0 {
		t.Fatalf("cross-site POST must be rejected by default, got %d (handler reached %d times)", rec.Code, reached)
	}

	bare := httptest.NewRequest(http.MethodPost, "https://app.example.com/x", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, bare)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a POST with neither Origin nor Referer must be rejected by default, got %d", rec.Code)
	}

	same := httptest.NewRequest(http.MethodPost, "https://app.example.com/x", nil)
	same.Header.Set("Origin", "https://app.example.com")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, same)
	if rec.Code != http.StatusNoContent || reached != 1 {
		t.Fatalf("same-origin POST must pass by default, got %d (handler reached %d times)", rec.Code, reached)
	}

	get := httptest.NewRequest(http.MethodGet, "https://app.example.com/x", nil)
	get.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, get)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("safe methods must never be blocked, got %d", rec.Code)
	}
}

// TestWebAppRateLimitsByDefault pins throttle-by-default: a webapp built with no rate-limit
// configuration answers 429 once the default burst is exhausted. CSRF is opted out so only the
// rate-limit default is under test; construction otherwise refuses an empty TrustedOrigins.
func TestWebAppRateLimitsByDefault(t *testing.T) {
	app, err := webapp.NewWebApp(webapp.Config{
		Identity: &servicetest.MockService{
			RegisterFunc: func(context.Context, string, string, string) (*identity.User, error) {
				return nil, errors.New("registration is not wired in this defaults check")
			},
		},
		TokenStore:            tokensmemory.NewStore[struct{}](),
		SigningKey:            base64.RawURLEncoding.EncodeToString(defaultsRandomBytes(t, 32)),
		Issuer:                "defaults-check",
		Tenant:                "tenant-1",
		InsecureNoOriginCheck: true,
	})
	if err != nil {
		t.Fatalf("webapp.NewWebApp: %v", err)
	}
	statuses := make([]int, 0, 30)
	throttled := 0
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest(http.MethodPost, "https://app.example.com/auth/register",
			strings.NewReader("email=ada@example.com&password=correct-horse-battery-staple"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		statuses = append(statuses, rec.Code)
		if rec.Code == http.StatusTooManyRequests {
			throttled++
		}
	}
	if throttled == 0 {
		t.Fatalf("webapp must rate-limit by default (burst %d); no request was throttled out of 30: %v", webapp.DefaultRateLimitBurst, statuses)
	}
	if statuses[webapp.DefaultRateLimitBurst] != http.StatusTooManyRequests {
		t.Fatalf("request %d must be throttled with the default burst of %d, got %d: %v",
			webapp.DefaultRateLimitBurst+1, webapp.DefaultRateLimitBurst, statuses[webapp.DefaultRateLimitBurst], statuses)
	}
}

// TestKeyLengthFloorsMatchDocs pins the documented key-length floors and checks the constructors
// actually enforce them: 32 bytes for the module-wide HS256 convention (secretpolicy, jwt,
// passkey), and the 16-byte backward-compatible floor authflow documents for flow-token keys.
func TestKeyLengthFloorsMatchDocs(t *testing.T) {
	if secretpolicy.MinKeyLength != 32 {
		t.Errorf("secretpolicy.MinKeyLength = %d, want the documented 32", secretpolicy.MinKeyLength)
	}
	if jwt.MinSecretKeyLength != 32 {
		t.Errorf("jwt.MinSecretKeyLength = %d, want the documented 32", jwt.MinSecretKeyLength)
	}
	if passkey.MinCookieKeyLength != 32 {
		t.Errorf("passkey.MinCookieKeyLength = %d, want the documented 32", passkey.MinCookieKeyLength)
	}

	// authflow documents a 16-byte floor for backward compatibility; the module-wide convention
	// for HS256-class keys is 32, enforced by jwt and passkey.
	if _, err := authflow.NewEngine(defaultsRandomBytes(t, 15)); err == nil {
		t.Error("authflow.NewEngine must reject a 15-byte flow-token key")
	}
	if _, err := authflow.NewEngine(defaultsRandomBytes(t, 16)); err != nil {
		t.Errorf("authflow.NewEngine must accept a 16-byte random flow-token key: %v", err)
	}

	if _, err := jwt.NewHMACSigner("kid", defaultsRandomBytes(t, 31)); err == nil {
		t.Error("jwt.NewHMACSigner must reject a 31-byte HMAC key")
	}
	if _, err := jwt.NewHMACSigner("kid", defaultsRandomBytes(t, 32)); err != nil {
		t.Errorf("jwt.NewHMACSigner must accept a 32-byte random key: %v", err)
	}
}
