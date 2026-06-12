// body_limit_test.go — regression test for TASK-074
// guarded() must cap the request body (4 KiB) and return 413 when the body exceeds the cap.
package mfa_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/mfa"
	"github.com/JLugagne/egauth/mfa/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// okResolver returns a valid user so the handler proceeds past the auth guard into body parsing.
func okResolver() mfa.HandlerOption {
	uid := uuid.New()
	return mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) {
		return uid, "t1", true
	})
}

// oversizedBody returns a POST whose body is larger than DefaultMaxBodyBytes (4 KiB).
func oversizedBody() *http.Request {
	// DefaultMaxBodyBytes = 4096; send 5 KiB of padding encoded as a form value.
	const bodyBytes = 5 << 10 // 5 KiB
	body := "code=" + strings.Repeat("x", bodyBytes)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Same-origin so the strict-by-default CSRF check passes; this test targets the body cap.
	req.Header.Set("Origin", "https://"+req.Host)
	return req
}

// TestGuarded_RejectsOversizedBody verifies that every mfa handler that goes through guarded()
// returns HTTP 413 when the request body exceeds DefaultMaxBodyBytes.
// Before the fix this test fails because guarded() calls r.ParseForm() without installing
// http.MaxBytesReader, so net/http applies its own 10 MB limit and the handler proceeds.
func TestGuarded_RejectsOversizedBody(t *testing.T) {
	svc := mfa.NewService(memory.NewStore())
	resolver := okResolver()

	handlers := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"EnrollHandler", mfa.EnrollHandler(svc, resolver)},
		{"ConfirmHandler", mfa.ConfirmHandler(svc, resolver)},
		{"VerifyHandler", mfa.VerifyHandler(svc, resolver)},
		{"VerifyRecoveryHandler", mfa.VerifyRecoveryHandler(svc, resolver)},
		{"RegenerateRecoveryCodesHandler", mfa.RegenerateRecoveryCodesHandler(svc, resolver)},
		{"DisableHandler", mfa.DisableHandler(svc, resolver)},
	}

	for _, h := range handlers {
		t.Run(h.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.handler(rec, oversizedBody())
			assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code,
				"guarded() must cap the body and return 413 for oversized requests")
		})
	}
}

// TestGuarded_WithMaxBodyBytes_CustomCap verifies that WithMaxBodyBytes overrides the default.
// A body exactly at the custom cap is accepted; one byte over is rejected with 413.
func TestGuarded_WithMaxBodyBytes_CustomCap(t *testing.T) {
	svc := mfa.NewService(memory.NewStore())
	resolver := okResolver()

	const customCap = 64

	makeBody := func(n int) *http.Request {
		body := "code=" + strings.Repeat("x", n)
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// Same-origin so the strict-by-default CSRF check passes; this test targets the body cap.
		req.Header.Set("Origin", "https://"+req.Host)
		return req
	}

	t.Run("at_cap_allowed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		mfa.VerifyHandler(svc, resolver, mfa.WithMaxBodyBytes(customCap))(rec, makeBody(customCap-len("code=")))
		assert.NotEqual(t, http.StatusRequestEntityTooLarge, rec.Code)
	})

	t.Run("over_cap_rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		mfa.VerifyHandler(svc, resolver, mfa.WithMaxBodyBytes(customCap))(rec, makeBody(customCap))
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	})
}
