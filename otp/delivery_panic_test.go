package otp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth/otp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type panicDeliveryService struct{}

func (panicDeliveryService) Issue(_ context.Context, _ string, subjectID uuid.UUID, _ string) (*otp.Challenge, error) {
	return &otp.Challenge{SubjectID: subjectID, Code: "123456"}, nil
}

func (panicDeliveryService) Verify(context.Context, string, uuid.UUID, string, string) error {
	return nil
}

func (panicDeliveryService) Invalidate(context.Context, string, uuid.UUID, string) error {
	return nil
}

// TestIssueHandler_SurvivesPanickingDelivery pins the panic containment of the off-response-path
// delivery goroutine (finding identity/TEN-7, same defect in this handler family): a panic in the
// consumer's deliver callback must not take the process down — the request has already left, so no
// http.Server recovery covers that goroutine.
func TestIssueHandler_SurvivesPanickingDelivery(t *testing.T) {
	delivered := make(chan struct{}, 1)
	subject := uuid.Must(uuid.NewV7())
	h := otp.IssueHandler(
		panicDeliveryService{},
		func(context.Context, *otp.Challenge) error {
			delivered <- struct{}{}
			panic("consumer otp delivery exploded")
		},
		otp.WithSubjectResolver(func(*http.Request) (uuid.UUID, bool) { return subject, true }),
	)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, issuePost())
	assert.Equal(t, http.StatusNoContent, rec.Code)

	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "the delivery callback was never invoked")
	}

	// The process is still alive: a later request keeps working.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, issuePost())
	assert.Equal(t, http.StatusNoContent, rec.Code)
}
