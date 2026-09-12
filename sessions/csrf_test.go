package sessions_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/sessions"
	sessionsmem "github.com/JLugagne/egauth/sessions/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sessionCSRFFixture is a live session plus a recording handler, used to exercise the
// RequireSession origin gate.
type sessionCSRFFixture struct {
	svc     sessions.Service
	token   string
	ran     bool
	handler sessions.AuthenticatedSessionHandlerFunc
}

func newSessionCSRFFixture(t *testing.T) *sessionCSRFFixture {
	t.Helper()
	svc := sessions.NewService(sessionsmem.NewStore())
	victim := uuid.Must(uuid.NewV7())
	_, token, err := svc.CreateSession(context.Background(), "", victim, "victim-browser", "203.0.113.7", time.Hour)
	require.NoError(t, err)

	f := &sessionCSRFFixture{svc: svc, token: token}
	f.handler = func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, s sessions.Session) {
		f.ran = true
		w.WriteHeader(http.StatusNoContent)
	}
	return f
}

// TestRequireSession_CSRFOriginGate pins the secure default: a cookie-authenticated
// state-changing request is only admitted when its Origin (or Referer fallback) host is the
// request's own Host or a trusted origin. A Bearer-authenticated request is exempt because the
// header is a non-ambient credential that a cross-site attacker cannot attach.
func TestRequireSession_CSRFOriginGate(t *testing.T) {
	const target = "https://app.example.com/account/email"

	tests := []struct {
		name       string
		method     string
		auth       string
		origin     string
		referer    string
		opts       []sessions.HandlerOption
		wantStatus int
		wantRan    bool
	}{
		{
			name:       "cross-origin POST from an untrusted origin is rejected",
			method:     http.MethodPost,
			auth:       "cookie",
			origin:     "https://evil.example.com",
			wantStatus: http.StatusForbidden,
			wantRan:    false,
		},
		{
			name:       "POST carrying neither Origin nor Referer is rejected",
			method:     http.MethodPost,
			auth:       "cookie",
			wantStatus: http.StatusForbidden,
			wantRan:    false,
		},
		{
			name:       "opaque Origin is rejected without falling back to Referer",
			method:     http.MethodPost,
			auth:       "cookie",
			origin:     "null",
			referer:    "https://app.example.com/settings",
			wantStatus: http.StatusForbidden,
			wantRan:    false,
		},
		{
			name:       "same-host Origin is admitted",
			method:     http.MethodPost,
			auth:       "cookie",
			origin:     "https://app.example.com",
			wantStatus: http.StatusNoContent,
			wantRan:    true,
		},
		{
			name:       "same-host Referer fallback is admitted",
			method:     http.MethodPost,
			auth:       "cookie",
			referer:    "https://app.example.com/settings",
			wantStatus: http.StatusNoContent,
			wantRan:    true,
		},
		{
			name:       "trusted origin is admitted",
			method:     http.MethodPost,
			auth:       "cookie",
			origin:     "https://trusted.example.com",
			opts:       []sessions.HandlerOption{sessions.WithTrustedOrigins("trusted.example.com")},
			wantStatus: http.StatusNoContent,
			wantRan:    true,
		},
		{
			name:       "full-origin trusted entry is admitted",
			method:     http.MethodPost,
			auth:       "cookie",
			origin:     "https://trusted.example.com",
			opts:       []sessions.HandlerOption{sessions.WithTrustedOrigins("https://trusted.example.com")},
			wantStatus: http.StatusNoContent,
			wantRan:    true,
		},
		{
			name:       "full-origin lookalike is rejected",
			method:     http.MethodPost,
			auth:       "cookie",
			origin:     "https://trusted.example.com.evil.com",
			opts:       []sessions.HandlerOption{sessions.WithTrustedOrigins("https://trusted.example.com")},
			wantStatus: http.StatusForbidden,
			wantRan:    false,
		},
		{
			name:       "foreign origin stays rejected when a trusted origin is configured",
			method:     http.MethodPost,
			auth:       "cookie",
			origin:     "https://evil.example.com",
			opts:       []sessions.HandlerOption{sessions.WithTrustedOrigins("trusted.example.com")},
			wantStatus: http.StatusForbidden,
			wantRan:    false,
		},
		{
			name:       "GET is unaffected",
			method:     http.MethodGet,
			auth:       "cookie",
			wantStatus: http.StatusNoContent,
			wantRan:    true,
		},
		{
			name:       "bearer-authenticated POST is unaffected",
			method:     http.MethodPost,
			auth:       "bearer",
			wantStatus: http.StatusNoContent,
			wantRan:    true,
		},
		{
			name:       "insecure opt-out admits a cross-origin POST",
			method:     http.MethodPost,
			auth:       "cookie",
			origin:     "https://evil.example.com",
			opts:       []sessions.HandlerOption{sessions.WithInsecureNoOriginCheck()},
			wantStatus: http.StatusNoContent,
			wantRan:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newSessionCSRFFixture(t)

			req := httptest.NewRequest(tc.method, target, strings.NewReader("new_email=attacker%40evil.example.com"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			switch tc.auth {
			case "cookie":
				req.AddCookie(&http.Cookie{Name: sessions.DefaultSessionCookieName, Value: f.token})
			case "bearer":
				req.Header.Set("Authorization", "Bearer "+f.token)
			}

			rec := httptest.NewRecorder()
			sessions.RequireSession(f.svc, f.handler, tc.opts...).ServeHTTP(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)
			assert.Equal(t, tc.wantRan, f.ran, "protected handler run state")
		})
	}
}

// TestRequireSession_CSRFOriginGateUnsafeMethods proves every state-changing method is gated
// for cookie-authenticated requests, not just POST.
func TestRequireSession_CSRFOriginGateUnsafeMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			f := newSessionCSRFFixture(t)

			req := httptest.NewRequest(method, "https://app.example.com/account/email", nil)
			req.Header.Set("Origin", "https://evil.example.com")
			req.AddCookie(&http.Cookie{Name: sessions.DefaultSessionCookieName, Value: f.token})

			rec := httptest.NewRecorder()
			sessions.RequireSession(f.svc, f.handler).ServeHTTP(rec, req)

			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.False(t, f.ran, "protected handler must not run for a forged cross-origin request")
		})
	}
}
