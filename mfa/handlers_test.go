package mfa_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/libauth/mfa"
	"github.com/JLugagne/libauth/mfa/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mfaPost(form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestHandlers_FullFlow(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := mfa.NewService(memory.NewStore(), mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.New()
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })

	// Enroll → JSON secret + uri.
	rec := httptest.NewRecorder()
	mfa.EnrollHandler(svc, resolver)(rec, mfaPost(url.Values{"account": {"user@example.com"}}))
	require.Equal(t, http.StatusOK, rec.Code)
	var enroll struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &enroll))
	require.NotEmpty(t, enroll.Secret)
	assert.Contains(t, enroll.URI, "otpauth://totp/")

	// Confirm with a valid code → JSON recovery codes.
	code := clk.code(t, enroll.Secret)
	rec = httptest.NewRecorder()
	mfa.ConfirmHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {code}}))
	require.Equal(t, http.StatusOK, rec.Code)
	var confirm struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &confirm))
	require.Len(t, confirm.RecoveryCodes, mfa.DefaultRecoveryCodeCount)

	// Verify a fresh code (advance a period) → 204.
	clk.t = clk.t.Add(mfa.DefaultPeriod)
	rec = httptest.NewRecorder()
	mfa.VerifyHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {clk.code(t, enroll.Secret)}}))
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// Verify a bad code → 401.
	rec = httptest.NewRecorder()
	mfa.VerifyHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {"000000"}}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Recovery code works once → 204, reuse → 401.
	rec = httptest.NewRecorder()
	mfa.VerifyRecoveryHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {confirm.RecoveryCodes[0]}}))
	assert.Equal(t, http.StatusNoContent, rec.Code)
	rec = httptest.NewRecorder()
	mfa.VerifyRecoveryHandler(svc, resolver)(rec, mfaPost(url.Values{"code": {confirm.RecoveryCodes[0]}}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Disable → 204.
	rec = httptest.NewRecorder()
	mfa.DisableHandler(svc, resolver)(rec, mfaPost(url.Values{}))
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestHandlers_RequireResolvedUser(t *testing.T) {
	svc := mfa.NewService(memory.NewStore())

	// No resolver configured → 401.
	rec := httptest.NewRecorder()
	mfa.EnrollHandler(svc)(rec, mfaPost(url.Values{}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Resolver reports no user → 401.
	rec = httptest.NewRecorder()
	mfa.VerifyHandler(svc, mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) {
		return uuid.Nil, "", false
	}))(rec, mfaPost(url.Values{"code": {"123456"}}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandlers_RejectGET(t *testing.T) {
	svc := mfa.NewService(memory.NewStore())
	rec := httptest.NewRecorder()
	mfa.EnrollHandler(svc, mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) {
		return uuid.New(), "t1", true
	}))(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}
