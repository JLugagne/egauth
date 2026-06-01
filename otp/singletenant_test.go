package otp_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/otp"
	"github.com/JLugagne/egauth/otp/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SingleTenant.Issue/Verify must round-trip on the empty tenant.
func TestSingleTenant_IssueVerify_UsesEmptyTenant(t *testing.T) {
	ctx := context.Background()
	svc := otp.NewService(memory.NewStore())
	st := otp.NewSingleTenant(svc)
	subject := uuid.New()

	ch, err := st.Issue(ctx, subject, "login")
	require.NoError(t, err)
	require.NotEmpty(t, ch.Code)

	// The wrapper verifies on the same empty partition it issued to.
	require.NoError(t, st.Verify(ctx, subject, "login", ch.Code))
}

// IDOR guard: a code issued via SingleTenant ("" tenant) must not verify under a non-empty
// tenant on the same Service.
func TestSingleTenant_Issue_NotVisibleToOtherTenant(t *testing.T) {
	ctx := context.Background()
	svc := otp.NewService(memory.NewStore())
	st := otp.NewSingleTenant(svc)
	subject := uuid.New()

	ch, err := st.Issue(ctx, subject, "login")
	require.NoError(t, err)

	err = svc.Verify(ctx, "tenant-acme", subject, "login", ch.Code)
	assert.Error(t, err, "empty-tenant code must not verify under tenant-acme")
}
