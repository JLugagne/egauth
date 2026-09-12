package passkey_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/passkey"
	passkeymem "github.com/JLugagne/egauth/passkey/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const renameCSRFTarget = "https://app.example.com/passkey/credentials/rename"

// renameCSRFFixture is a passkey service holding one credential for a victim user, plus a
// RenameCredentialHandler wired to that user's session resolver.
type renameCSRFFixture struct {
	svc    *passkey.Service
	userID uuid.UUID
	credID []byte
	h      http.HandlerFunc
}

func newRenameCSRFFixture(t *testing.T, opts ...passkey.HandlerOption) *renameCSRFFixture {
	t.Helper()

	store := passkeymem.NewStore()
	svc, err := passkey.NewService(store, passkey.Config{
		RPID:           "app.example.com",
		RPDisplayName:  "App",
		RPOrigins:      []string{"https://app.example.com"},
		CookieKey:      bytes.Repeat([]byte{0x42}, 32),
		ChallengeStore: passkeymem.NewChallengeStore(),
	})
	require.NoError(t, err)

	userID := uuid.Must(uuid.NewV7())
	credID := []byte{0x01, 0x02, 0x03, 0x04}
	require.NoError(t, store.SaveCredential(context.Background(), "", &passkey.Credential{
		UserID:    userID,
		ID:        credID,
		PublicKey: []byte{0x01},
		Data:      []byte("{}"),
		CreatedAt: time.Now(),
	}))

	handlerOpts := []passkey.HandlerOption{
		passkey.WithUserResolver(func(*http.Request) (uuid.UUID, string, string, string, bool) {
			return userID, "", "", "", true
		}),
	}
	handlerOpts = append(handlerOpts, opts...)

	return &renameCSRFFixture{
		svc:    svc,
		userID: userID,
		credID: credID,
		h:      passkey.RenameCredentialHandler(svc, handlerOpts...),
	}
}

func (f *renameCSRFFixture) nickname(t *testing.T) string {
	t.Helper()
	creds, err := f.svc.ListCredentials(context.Background(), "", f.userID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	return creds[0].Nickname
}

// TestRenameCredentialHandler_CSRFBlocksCrossOriginByDefault pins the regression: a plain-text
// (CORS-simple) cross-origin POST must be rejected by the strict same-origin gate before the
// body is decoded or the service is called, so the victim's credential is left untouched.
func TestRenameCredentialHandler_CSRFBlocksCrossOriginByDefault(t *testing.T) {
	f := newRenameCSRFFixture(t)

	body := `{"credentialId":"` + base64.RawURLEncoding.EncodeToString(f.credID) + `","nickname":"pwned-by-csrf"}`
	req := httptest.NewRequest(http.MethodPost, renameCSRFTarget, strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Origin", "https://evil.example.com")

	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"a state-changing request from an untrusted Origin must be rejected")
	assert.Contains(t, rec.Body.String(), "cross_site_blocked")
	assert.Empty(t, f.nickname(t), "a cross-origin request must not rename the victim's passkey")
}

// TestRenameCredentialHandler_CSRFOriginGate exercises the gate's allow/deny matrix plus the
// application/json Content-Type requirement.
func TestRenameCredentialHandler_CSRFOriginGate(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		origin      string
		referer     string
		contentType string
		opts        []passkey.HandlerOption
		wantStatus  int
		wantNick    string
	}{
		{
			name:        "cross-origin POST is rejected",
			method:      http.MethodPost,
			origin:      "https://evil.example.com",
			contentType: "application/json",
			wantStatus:  http.StatusForbidden,
		},
		{
			name:        "POST with neither Origin nor Referer is rejected",
			method:      http.MethodPost,
			contentType: "application/json",
			wantStatus:  http.StatusForbidden,
		},
		{
			name:        "opaque Origin is rejected",
			method:      http.MethodPost,
			origin:      "null",
			referer:     "https://app.example.com/settings",
			contentType: "application/json",
			wantStatus:  http.StatusForbidden,
		},
		{
			name:        "same-host Origin is admitted",
			method:      http.MethodPost,
			origin:      "https://app.example.com",
			contentType: "application/json",
			wantStatus:  http.StatusNoContent,
			wantNick:    "renamed",
		},
		{
			name:        "same-host Referer fallback is admitted",
			method:      http.MethodPost,
			referer:     "https://app.example.com/settings",
			contentType: "application/json",
			wantStatus:  http.StatusNoContent,
			wantNick:    "renamed",
		},
		{
			name:        "trusted origin is admitted",
			method:      http.MethodPost,
			origin:      "https://trusted.example.com",
			contentType: "application/json",
			opts:        []passkey.HandlerOption{passkey.WithTrustedOrigins("trusted.example.com")},
			wantStatus:  http.StatusNoContent,
			wantNick:    "renamed",
		},
		{
			name:        "full-origin trusted entry is admitted",
			method:      http.MethodPost,
			origin:      "https://trusted.example.com",
			contentType: "application/json",
			opts:        []passkey.HandlerOption{passkey.WithTrustedOrigins("https://trusted.example.com")},
			wantStatus:  http.StatusNoContent,
			wantNick:    "renamed",
		},
		{
			name:        "full-origin lookalike is rejected",
			method:      http.MethodPost,
			origin:      "https://trusted.example.com.evil.com",
			contentType: "application/json",
			opts:        []passkey.HandlerOption{passkey.WithTrustedOrigins("https://trusted.example.com")},
			wantStatus:  http.StatusForbidden,
		},
		{
			name:        "foreign origin stays rejected when a trusted origin is configured",
			method:      http.MethodPost,
			origin:      "https://evil.example.com",
			contentType: "application/json",
			opts:        []passkey.HandlerOption{passkey.WithTrustedOrigins("trusted.example.com")},
			wantStatus:  http.StatusForbidden,
		},
		{
			name:       "safe GET is unaffected",
			method:     http.MethodGet,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:        "insecure opt-out admits a cross-origin POST",
			method:      http.MethodPost,
			origin:      "https://evil.example.com",
			contentType: "application/json",
			opts:        []passkey.HandlerOption{passkey.WithInsecureNoOriginCheck()},
			wantStatus:  http.StatusNoContent,
			wantNick:    "renamed",
		},
		{
			name:        "wrong Content-Type is rejected with 415",
			method:      http.MethodPost,
			origin:      "https://app.example.com",
			contentType: "text/plain",
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:       "missing Content-Type is rejected with 415",
			method:     http.MethodPost,
			origin:     "https://app.example.com",
			wantStatus: http.StatusUnsupportedMediaType,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRenameCSRFFixture(t, tc.opts...)

			body := fmt.Sprintf(`{"credentialId":"%s","nickname":"renamed"}`,
				base64.RawURLEncoding.EncodeToString(f.credID))
			req := httptest.NewRequest(tc.method, renameCSRFTarget, strings.NewReader(body))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}

			rec := httptest.NewRecorder()
			f.h.ServeHTTP(rec, req)
			assert.Equal(t, tc.wantStatus, rec.Code)
			assert.Equal(t, tc.wantNick, f.nickname(t))
		})
	}
}
