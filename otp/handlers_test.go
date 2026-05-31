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
	return req
}

func TestIssueHandler_DeliversAndAlwaysSucceeds(t *testing.T) {
	svc := otp.NewService(memory.NewStore())
	subject := uuid.New()

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
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/otp/issue", nil))

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
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/otp/issue", nil))
	assert.Equal(t, http.StatusNoContent, rec.Code, "must not leak whether the subject exists")
}

func TestVerifyHandler_Success(t *testing.T) {
	svc := otp.NewService(memory.NewStore())
	subject := uuid.New()
	ch, err := svc.Issue(context.Background(), subject, "login")
	require.NoError(t, err)

	h := otp.VerifyHandler(svc, otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) {
		return subject, true
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, codeForm(ch.Code))
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestVerifyHandler_CollapsesAllFailures(t *testing.T) {
	subject := uuid.New()
	withSubject := otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) { return subject, true })

	// Wrong code (a challenge exists) and no-challenge-at-all must be indistinguishable.
	t.Run("wrong code", func(t *testing.T) {
		svc := otp.NewService(memory.NewStore())
		_, err := svc.Issue(context.Background(), subject, "login")
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
