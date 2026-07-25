package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRequestEmailChangeHandler_EnforcesStepUp proves finding identity/TEN-2: a session alone must
// not be able to move the account's login identifier to an attacker-controlled address. The handler
// now enforces the same bar as DeleteAccountHandler — fail closed on an unresolvable assurance,
// refuse a pre-step-up interim credential, and (with WithMFAGate) demand that an MFA-enrolled user
// actually present the second factor.
func TestRequestEmailChangeHandler_EnforcesStepUp(t *testing.T) {
	user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "victim@example.com"}
	cases := []struct {
		name     string
		opts     []identity.HandlerOption
		wantCode int
	}{
		{"unresolvable assurance -> fails closed", nil, http.StatusForbidden},
		{"interim credential -> refused", []identity.HandlerOption{interimAssurance()}, http.StatusForbidden},
		{"full session, no MFA gate -> allowed", []identity.HandlerOption{fullSessionAssurance()}, http.StatusNoContent},
		{
			"enrolled user, password-only session -> refused",
			[]identity.HandlerOption{fullSessionAssurance(), identity.WithMFAGate(stubMFAGate{enrolled: true})},
			http.StatusForbidden,
		},
		{
			"enrolled user, stepped-up session -> allowed",
			[]identity.HandlerOption{steppedUpAssurance(), identity.WithMFAGate(stubMFAGate{enrolled: true})},
			http.StatusNoContent,
		},
		{"explicit opt-out -> allowed", []identity.HandlerOption{identity.WithInsecureNoStepUpCheck()}, http.StatusNoContent},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var requested bool
			svc := &servicetest.MockService{
				RequestEmailChangeFunc: func(context.Context, string, uuid.UUID, string) (string, error) {
					requested = true
					return "sel.ver", nil
				},
			}
			mailer := newMockMailer()
			opts := append([]identity.HandlerOption{
				identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true }),
			}, tc.opts...)

			rec := httptest.NewRecorder()
			identity.RequestEmailChangeHandler(svc, mailer.asMailer(), opts...)(rec, postForm(url.Values{"new_email": {"attacker@evil.test"}}))

			require.Equal(t, tc.wantCode, rec.Code)
			if tc.wantCode == http.StatusForbidden {
				assert.Contains(t, rec.Body.String(), "step_up_required")
				assert.False(t, requested, "a refused request must not mint a change-email token")
				requireNoMail(t, mailer.changeCh)
			} else {
				assert.True(t, requested)
			}
		})
	}
}

// TestRequestRecoveryEmailHandler_EnforcesStepUp covers the sibling surface: a verified recovery
// address drives RequestPasswordResetViaRecovery, so enrolling one is exactly as takeover-relevant
// as changing the login email and gets the same bar.
func TestRequestRecoveryEmailHandler_EnforcesStepUp(t *testing.T) {
	user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "victim@example.com"}
	cases := []struct {
		name     string
		opts     []identity.HandlerOption
		wantCode int
	}{
		{"unresolvable assurance -> fails closed", nil, http.StatusForbidden},
		{"interim credential -> refused", []identity.HandlerOption{interimAssurance()}, http.StatusForbidden},
		{"full session, no MFA gate -> allowed", []identity.HandlerOption{fullSessionAssurance()}, http.StatusNoContent},
		{
			"enrolled user, password-only session -> refused",
			[]identity.HandlerOption{fullSessionAssurance(), identity.WithMFAGate(stubMFAGate{enrolled: true})},
			http.StatusForbidden,
		},
		{"explicit opt-out -> allowed", []identity.HandlerOption{identity.WithInsecureNoStepUpCheck()}, http.StatusNoContent},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var requested bool
			svc := &servicetest.MockService{
				RequestRecoveryEmailFunc: func(context.Context, string, uuid.UUID, string) (string, error) {
					requested = true
					return "sel.ver", nil
				},
			}
			mailer := newMockMailer()
			opts := append([]identity.HandlerOption{
				identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true }),
			}, tc.opts...)

			rec := httptest.NewRecorder()
			identity.RequestRecoveryEmailHandler(svc, mailer.asMailer(), opts...)(rec, postForm(url.Values{"recovery_email": {"attacker@evil.test"}}))

			require.Equal(t, tc.wantCode, rec.Code)
			if tc.wantCode == http.StatusForbidden {
				assert.Contains(t, rec.Body.String(), "step_up_required")
				assert.False(t, requested, "a refused request must not mint a recovery-email token")
				requireNoMail(t, mailer.recoveryCh)
			} else {
				assert.True(t, requested)
			}
		})
	}
}
