package otp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/otp"
	"github.com/JLugagne/egauth/otp/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func codeForm(code string) *http.Request {
	form := url.Values{}
	form.Set("code", code)
	req := httptest.NewRequest(http.MethodPost, "/otp/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Same-origin by default so business-logic tests pass the strict-by-default CSRF check.
	req.Header.Set("Origin", "https://"+req.Host)
	return req
}

func TestIssueHandler_DeliversAndAlwaysSucceeds(t *testing.T) {
	svc := otp.NewService(memory.NewStore())
	subject := uuid.Must(uuid.NewV7())

	var delivered *otp.Challenge
	done := make(chan struct{})
	deliver := func(ctx context.Context, ch *otp.Challenge) error {
		delivered = ch
		close(done)
		return nil
	}
	h := otp.IssueHandler(svc, deliver, otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) {
		return subject, true
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, issuePost())

	assert.Equal(t, http.StatusNoContent, rec.Code)
	<-done
	require.NotNil(t, delivered)
	assert.Equal(t, subject, delivered.SubjectID)
	assert.NotEmpty(t, delivered.Code, "the plaintext code is handed to the delivery callback")
}

func TestIssueHandler_UnknownSubjectStillReturns204(t *testing.T) {
	svc := otp.NewService(memory.NewStore())
	h := otp.IssueHandler(svc, nil, otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) {
		return uuid.Nil, false // unknown / unauthenticated subject
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, issuePost())
	assert.Equal(t, http.StatusNoContent, rec.Code, "must not leak whether the subject exists")
}

func TestVerifyHandler_Success(t *testing.T) {
	svc := otp.NewService(memory.NewStore())
	subject := uuid.Must(uuid.NewV7())
	ch, err := svc.Issue(context.Background(), "", subject, "login")
	require.NoError(t, err)

	h := otp.VerifyHandler(svc, otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) {
		return subject, true
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, codeForm(ch.Code))
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestVerifyHandler_CollapsesAllFailures(t *testing.T) {
	subject := uuid.Must(uuid.NewV7())
	withSubject := otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) { return subject, true })

	// Wrong code (a challenge exists) and no-challenge-at-all must be indistinguishable.
	t.Run("wrong code", func(t *testing.T) {
		svc := otp.NewService(memory.NewStore())
		_, err := svc.Issue(context.Background(), "", subject, "login")
		require.NoError(t, err)
		rec := httptest.NewRecorder()
		otp.VerifyHandler(svc, withSubject).ServeHTTP(rec, codeForm("000000"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "invalid_code")
	})

	t.Run("no challenge in flight", func(t *testing.T) {
		svc := otp.NewService(memory.NewStore())
		rec := httptest.NewRecorder()
		otp.VerifyHandler(svc, withSubject).ServeHTTP(rec, codeForm("123456"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "invalid_code")
	})
}

func TestVerifyHandler_RequiresSubjectResolver(t *testing.T) {
	svc := otp.NewService(memory.NewStore())
	rec := httptest.NewRecorder()
	otp.VerifyHandler(svc).ServeHTTP(rec, codeForm("123456"))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// issuePost builds a POST to /otp/issue carrying a same-origin Origin so the strict-by-default
// CSRF check passes. These tests exercise issue/delivery behavior, not the origin path.
func issuePost() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/otp/issue", nil)
	req.Header.Set("Origin", "https://"+req.Host)
	return req
}

// TestIssueHandler_CSRFBlocksCrossOriginByDefault proves the secure-by-default CSRF behavior:
// with NO WithTrustedOrigins configured, a cross-origin POST must still be rejected, matching the
// tokens/identity handlers.
func TestIssueHandler_CSRFBlocksCrossOriginByDefault(t *testing.T) {
	svc := otp.NewService(memory.NewStore())
	subject := uuid.Must(uuid.NewV7())
	delivered := false
	deliver := func(context.Context, *otp.Challenge) error { delivered = true; return nil }
	h := otp.IssueHandler(svc, deliver, otp.WithSubjectResolver(func(*http.Request) (uuid.UUID, bool) {
		return subject, true
	}))

	req := httptest.NewRequest(http.MethodPost, "/otp/issue", nil)
	req.Host = "app.example.com"
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, delivered, "delivery must not run for a cross-site request with default config")
}

// TestIssueHandler_WithInsecureNoOriginCheck proves the loud opt-out restores accept-all behavior.
func TestIssueHandler_WithInsecureNoOriginCheck(t *testing.T) {
	svc := otp.NewService(memory.NewStore())
	subject := uuid.Must(uuid.NewV7())
	h := otp.IssueHandler(svc, nil, otp.WithSubjectResolver(func(*http.Request) (uuid.UUID, bool) {
		return subject, true
	}), otp.WithInsecureNoOriginCheck())

	req := httptest.NewRequest(http.MethodPost, "/otp/issue", nil)
	req.Host = "app.example.com"
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code, "the origin check is disabled by the insecure opt-out")
}

// TestIssueHandler_SynchronousIssuance_PersistsBeforeResponse verifies that svc.Issue
// completes and persists the OTP challenge synchronously on the request goroutine before
// returning 204, even while delivery remains pending or blocked in-flight.
func TestIssueHandler_SynchronousIssuance_PersistsBeforeResponse(t *testing.T) {
	store := memory.NewStore()
	svc := otp.NewService(store)
	subject := uuid.Must(uuid.NewV7())

	deliveryStarted := make(chan struct{})
	deliveryRelease := make(chan struct{})
	var deliveredCode string

	deliver := func(ctx context.Context, ch *otp.Challenge) error {
		deliveredCode = ch.Code
		close(deliveryStarted)
		<-deliveryRelease
		return nil
	}

	h := otp.IssueHandler(
		svc,
		deliver,
		otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) {
			return subject, true
		}),
	)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, issuePost())
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// Challenge must be synchronously saved in store immediately upon 204
	stored, err := store.GetOTP(context.Background(), "", subject, "login")
	require.NoError(t, err, "OTP challenge must be synchronously saved before HTTP response returns")
	require.NotNil(t, stored)

	// Delivery is in-flight and blocked
	<-deliveryStarted
	assert.NotEmpty(t, deliveredCode)

	// Verification succeeds immediately
	err = svc.Verify(context.Background(), "", subject, "login", deliveredCode)
	require.NoError(t, err, "OTP must verify successfully while delivery is still in-flight")

	close(deliveryRelease)
}

// TestIssueHandler_DecoupledDelivery_DroppedWhenSaturated verifies that under delivery semaphore
// saturation, out-of-band delivery is dropped but synchronous persistence still succeeds.
func TestIssueHandler_DecoupledDelivery_DroppedWhenSaturated(t *testing.T) {
	store := memory.NewStore()
	svc := otp.NewService(store)
	subject1 := uuid.Must(uuid.NewV7())
	subject2 := uuid.Must(uuid.NewV7())

	blockDelivery := make(chan struct{})
	delivery1Started := make(chan struct{}, 1)

	deliver := func(ctx context.Context, ch *otp.Challenge) error {
		select {
		case delivery1Started <- struct{}{}:
		default:
		}
		<-blockDelivery
		return nil
	}

	h := otp.IssueHandler(
		svc,
		deliver,
		otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) {
			if r.Header.Get("X-Subject") == "2" {
				return subject2, true
			}
			return subject1, true
		}),
		otp.WithMaxConcurrentDeliveries(1),
	)

	// Request 1 acquires the slot and blocks in delivery
	req1 := issuePost()
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusNoContent, rec1.Code)

	<-delivery1Started

	// Request 2 arrives while slot is saturated
	req2 := issuePost()
	req2.Header.Set("X-Subject", "2")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusNoContent, rec2.Code)

	// Subject 2's OTP MUST be persisted in store despite delivery being dropped
	stored2, err := store.GetOTP(context.Background(), "", subject2, "login")
	require.NoError(t, err, "OTP for subject 2 must be persisted even if delivery was dropped")
	require.NotNil(t, stored2)

	close(blockDelivery)
}

// TestIssueHandler_DeliveryFailureDoesNotAffectResponse asserts that out-of-band delivery errors
// are decoupled and swallowed so HTTP response remains 204 and OTP remains persisted.
func TestIssueHandler_DeliveryFailureDoesNotAffectResponse(t *testing.T) {
	store := memory.NewStore()
	svc := otp.NewService(store)
	subject := uuid.Must(uuid.NewV7())

	delivered := make(chan struct{})
	deliver := func(ctx context.Context, ch *otp.Challenge) error {
		close(delivered)
		return assert.AnError
	}

	h := otp.IssueHandler(svc, deliver, otp.WithSubjectResolver(func(*http.Request) (uuid.UUID, bool) {
		return subject, true
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, issuePost())
	assert.Equal(t, http.StatusNoContent, rec.Code)

	<-delivered
	stored, err := store.GetOTP(context.Background(), "", subject, "login")
	require.NoError(t, err)
	require.NotNil(t, stored)
}

// TestIssueHandler_UniformResponseResolvedAndUnresolved asserts the response is uniform (204)
// whether or not the subject resolver returns ok, so no account-existence signal leaks.
func TestIssueHandler_UniformResponseResolvedAndUnresolved(t *testing.T) {
	svc := otp.NewService(memory.NewStore())

	resolved := otp.IssueHandler(svc, func(context.Context, *otp.Challenge) error { return nil },
		otp.WithSubjectResolver(func(*http.Request) (uuid.UUID, bool) { return uuid.Must(uuid.NewV7()), true }))
	unresolved := otp.IssueHandler(svc, func(context.Context, *otp.Challenge) error { return nil },
		otp.WithSubjectResolver(func(*http.Request) (uuid.UUID, bool) { return uuid.Nil, false }))

	recResolved := httptest.NewRecorder()
	resolved.ServeHTTP(recResolved, issuePost())

	recUnresolved := httptest.NewRecorder()
	unresolved.ServeHTTP(recUnresolved, issuePost())

	assert.Equal(t, http.StatusNoContent, recResolved.Code)
	assert.Equal(t, http.StatusNoContent, recUnresolved.Code)
	assert.Equal(t, recResolved.Code, recUnresolved.Code, "response must be uniform for resolved and unresolved subjects")
}
