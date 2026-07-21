package otp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth/otp"
	"github.com/JLugagne/egauth/otp/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

type blockingIssueService struct {
	started chan struct{}
	release chan struct{}
}

func (s *blockingIssueService) Issue(_ context.Context, _ string, subjectID uuid.UUID, _ string) (*otp.Challenge, error) {
	close(s.started)
	<-s.release
	return &otp.Challenge{SubjectID: subjectID, Code: "123456"}, nil
}

func (s *blockingIssueService) Verify(context.Context, string, uuid.UUID, string, string) error {
	return nil
}

func (s *blockingIssueService) Invalidate(context.Context, string, uuid.UUID, string) error {
	return nil
}

// TestIssueHandler_MintOffResponsePath proves svc.Issue runs OFF the response path: ServeHTTP must
// return the uniform 204 without waiting for the mint (svc.Issue) to complete. On the buggy code
// svc.Issue was called synchronously on the request goroutine, so ServeHTTP blocked until Issue
// returned and this test timed out.
func TestIssueHandler_MintOffResponsePath(t *testing.T) {
	svc := &blockingIssueService{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	defer close(svc.release)

	subject := uuid.Must(uuid.NewV7())
	h := otp.IssueHandler(
		svc,
		func(context.Context, *otp.Challenge) error { return nil },
		otp.WithSubjectResolver(func(*http.Request) (uuid.UUID, bool) { return subject, true }),
	)

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(rec, issuePost())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("response path blocked on Issue: ServeHTTP did not return before the mint completed")
	}
	assert.Equal(t, http.StatusNoContent, rec.Code)

	select {
	case <-svc.started:
	case <-time.After(2 * time.Second):
		t.Fatal("svc.Issue was never invoked off the response path")
	}
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
