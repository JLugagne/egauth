package otp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/otp"
	"github.com/JLugagne/egauth/otp/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestIssueHandler_WithTrustedOrigins_AcceptsFullOrigin pins issue #124 for the OTP handlers.
func TestIssueHandler_WithTrustedOrigins_AcceptsFullOrigin(t *testing.T) {
	svc := otp.NewService(memory.NewStore())
	subject := uuid.Must(uuid.NewV7())

	h := otp.IssueHandler(svc, func(context.Context, *otp.Challenge) error { return nil },
		otp.WithSubjectResolver(func(*http.Request) (uuid.UUID, bool) { return subject, true }),
		otp.WithTrustedOrigins("https://app.example.com"))

	req := httptest.NewRequest(http.MethodPost, "/otp/issue", nil)
	req.Host = "api.example.com" // not the allowlisted host
	req.Header.Set("Origin", "https://app.example.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code, "a full-origin entry must match the bare Origin host")
}

// TestIssueHandler_WithTrustedOrigins_FullOriginLookalikeStillRejected pins exact matching.
func TestIssueHandler_WithTrustedOrigins_FullOriginLookalikeStillRejected(t *testing.T) {
	svc := otp.NewService(memory.NewStore())
	subject := uuid.Must(uuid.NewV7())

	h := otp.IssueHandler(svc, func(context.Context, *otp.Challenge) error { return nil },
		otp.WithSubjectResolver(func(*http.Request) (uuid.UUID, bool) { return subject, true }),
		otp.WithTrustedOrigins("https://app.example.com"))

	req := httptest.NewRequest(http.MethodPost, "/otp/issue", nil)
	req.Host = "api.example.com"
	req.Header.Set("Origin", "https://app.example.com.evil.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "normalization must not become suffix matching")
}
