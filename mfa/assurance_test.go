// Regression tests for F-COMP-001 on the mfa enrollment handlers: enrolling or confirming a
// second factor is a credential-management action and must not accept an interim (pre-MFA)
// session. The handlers fail closed by default; an explicit gate decides per request; the
// WithInsecureNoAssuranceCheck opt-out preserves the old behavior for apps without a second
// factor.
package mfa_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/JLugagne/egauth/mfa"
	"github.com/JLugagne/egauth/mfa/memory"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestMFAEnrollmentHandlers_FailClosedWithoutAssurance is the default-composition invariant:
// with neither a gate nor an opt-out, Enroll and Confirm refuse before doing any work.
func TestMFAEnrollmentHandlers_FailClosedWithoutAssurance(t *testing.T) {
	svc := mfa.NewService(memory.NewStore())
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })

	for name, h := range map[string]http.HandlerFunc{
		"enroll":  mfa.EnrollHandler(svc, resolver),
		"confirm": mfa.ConfirmHandler(svc, resolver),
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h(rec, mfaPost(url.Values{"account": {"u"}, "code": {"123456"}}))
			require.Equal(t, http.StatusForbidden, rec.Code,
				"an un-gated enrollment handler must fail closed")
			require.Contains(t, rec.Body.String(), "assurance_required")
		})
	}
}

// TestMFAEnrollmentHandlers_DenyingGateRefused proves a wired gate is authoritative: when it
// reports an interim session, both halves refuse with 403.
func TestMFAEnrollmentHandlers_DenyingGateRefused(t *testing.T) {
	svc := mfa.NewService(memory.NewStore())
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })
	gate := mfa.WithCredentialAssurance(func(*http.Request) error { return errors.New("interim session") })

	for name, h := range map[string]http.HandlerFunc{
		"enroll":  mfa.EnrollHandler(svc, resolver, gate),
		"confirm": mfa.ConfirmHandler(svc, resolver, gate),
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h(rec, mfaPost(url.Values{"account": {"u"}, "code": {"123456"}}))
			require.Equal(t, http.StatusForbidden, rec.Code)
			require.Contains(t, rec.Body.String(), "assurance_required")
		})
	}
}

// TestMFAEnrollmentHandlers_PermissiveGateProceeds proves a gate that allows the session does
// not break enrollment.
func TestMFAEnrollmentHandlers_PermissiveGateProceeds(t *testing.T) {
	svc := mfa.NewService(memory.NewStore())
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })
	gate := mfa.WithCredentialAssurance(func(*http.Request) error { return nil })

	rec := httptest.NewRecorder()
	mfa.EnrollHandler(svc, resolver, gate)(rec, mfaPost(url.Values{"account": {"u"}}))
	require.Equal(t, http.StatusOK, rec.Code)
}

// TestMFAEnrollmentHandlers_InsecureNoAssuranceCheckProceeds pins the documented opt-out.
func TestMFAEnrollmentHandlers_InsecureNoAssuranceCheckProceeds(t *testing.T) {
	svc := mfa.NewService(memory.NewStore())
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })

	rec := httptest.NewRecorder()
	mfa.EnrollHandler(svc, resolver, mfa.WithInsecureNoAssuranceCheck())(rec, mfaPost(url.Values{"account": {"u"}}))
	require.Equal(t, http.StatusOK, rec.Code)
}

// TestMFAEnrollmentHandlers_CanonicalDenyInterimGate proves the canonical gate value
// (tokens.DenyInterim) is structurally accepted by WithCredentialAssurance and allows a
// request that carries no interim token context.
func TestMFAEnrollmentHandlers_CanonicalDenyInterimGate(t *testing.T) {
	svc := mfa.NewService(memory.NewStore())
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })

	rec := httptest.NewRecorder()
	mfa.EnrollHandler(svc, resolver, mfa.WithCredentialAssurance(tokens.DenyInterim))(rec, mfaPost(url.Values{"account": {"u"}}))
	require.Equal(t, http.StatusOK, rec.Code,
		"a request without an interim context must pass the canonical gate")
}
