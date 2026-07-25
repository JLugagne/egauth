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
	"github.com/stretchr/testify/require"
)

func TestVerifyHandler_UnresolvedTenantFailsClosed(t *testing.T) {
	svc := otp.NewService(memory.NewStore())
	subject := uuid.Must(uuid.NewV7())
	// A challenge exists in the single-tenant ("") partition — where a bootstrap/operator
	// account lives. A request whose tenant cannot be resolved must not be able to burn it.
	ch, err := svc.Issue(context.Background(), "", subject, "login")
	require.NoError(t, err)

	h := otp.VerifyHandler(svc,
		otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) { return subject, true }),
		otp.WithTenantResolver(func(*http.Request) string { return "" }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, codeForm(ch.Code))

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"a configured resolver returning \"\" must not verify against the \"\" partition")
}

func TestIssueHandler_UnresolvedTenantFailsClosed(t *testing.T) {
	svc := otp.NewService(memory.NewStore())
	subject := uuid.Must(uuid.NewV7())

	delivered := make(chan *otp.Challenge, 1)
	h := otp.IssueHandler(svc, func(ctx context.Context, ch *otp.Challenge) error {
		delivered <- ch
		return nil
	},
		otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) { return subject, true }),
		otp.WithTenantResolver(func(*http.Request) string { return "" }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, issuePost())

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Empty(t, delivered, "an unresolved tenant must not mint an OTP in the \"\" partition")
}

func TestVerifyHandler_SingleTenantWithoutResolverStillWorks(t *testing.T) {
	svc := otp.NewService(memory.NewStore())
	subject := uuid.Must(uuid.NewV7())
	ch, err := svc.Issue(context.Background(), "", subject, "login")
	require.NoError(t, err)

	h := otp.VerifyHandler(svc,
		otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) { return subject, true }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, codeForm(ch.Code))
	assert.Equal(t, http.StatusNoContent, rec.Code)
}
