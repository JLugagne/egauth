package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChangePasswordWithReissueHandler_RefusesInterimCredential proves finding mfa/SF-2: the
// re-issuing handler must not turn a pre-step-up interim credential into a full renewable pair.
// Otherwise anyone who knows the password holds an interim credential and can upgrade it, bypassing
// the account's second factor entirely.
func TestChangePasswordWithReissueHandler_RefusesInterimCredential(t *testing.T) {
	var changed bool
	svc := &servicetest.MockService{
		ChangePasswordFunc: func(context.Context, string, uuid.UUID, string, string) error {
			changed = true
			return nil
		},
	}
	withUser := identity.WithUserResolver(func(*http.Request) (*identity.User, bool) {
		return &identity.User{ID: uuid.Must(uuid.NewV7())}, true
	})
	h := identity.ChangePasswordWithReissueHandler[struct{}](svc, okIssuer(), testClaimsBuilder(),
		withUser, interimAssurance())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, changePwForm(t, "old-pass", "NewValidPass123!"))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "step_up_required")
	assert.Nil(t, cookieByName(rec, tokens.DefaultRefreshCookieName),
		"no renewable session may be minted for a pre-step-up request")
	assert.Nil(t, cookieByName(rec, tokens.DefaultAccessCookieName))
	assert.False(t, changed, "the password must not even be changed on a refused request")
}

// TestChangePasswordWithReissueHandler_UnresolvableAssuranceFailsClosed proves the default wiring is
// safe: without a resolvable assurance (no tokens.ContextMiddleware in front) the handler refuses
// rather than assuming the request came from a full session.
func TestChangePasswordWithReissueHandler_UnresolvableAssuranceFailsClosed(t *testing.T) {
	svc := &servicetest.MockService{
		ChangePasswordFunc: func(context.Context, string, uuid.UUID, string, string) error { return nil },
	}
	withUser := identity.WithUserResolver(func(*http.Request) (*identity.User, bool) {
		return &identity.User{ID: uuid.Must(uuid.NewV7())}, true
	})

	h := identity.ChangePasswordWithReissueHandler[struct{}](svc, okIssuer(), testClaimsBuilder(), withUser)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, changePwForm(t, "old-pass", "NewValidPass123!"))
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// The loud opt-out restores the pre-v1 behaviour for deployments that mint no interim credentials.
	h = identity.ChangePasswordWithReissueHandler[struct{}](svc, okIssuer(), testClaimsBuilder(),
		withUser, identity.WithInsecureNoStepUpCheck())
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, changePwForm(t, "old-pass", "NewValidPass123!"))
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.NotNil(t, cookieByName(rec, tokens.DefaultRefreshCookieName))
}

// TestDeleteAccountHandler_RefusesInterimCredential proves the refuter-found MEDIUM: account
// deletion is irreversible, so a pre-step-up interim credential must never reach it.
func TestDeleteAccountHandler_RefusesInterimCredential(t *testing.T) {
	var deleted bool
	svc := &servicetest.MockService{
		DeleteAccountFunc: func(context.Context, string, uuid.UUID) error {
			deleted = true
			return nil
		},
	}
	h := identity.DeleteAccountHandler(svc,
		identity.WithUserResolver(func(*http.Request) (*identity.User, bool) {
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, true
		}),
		interimAssurance())

	rec := httptest.NewRecorder()
	h(rec, postForm(url.Values{}))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "step_up_required")
	assert.False(t, deleted, "the account must not be deleted from a pre-step-up request")
}

// TestDeleteAccountHandler_UnresolvableAssuranceFailsClosed proves the destructive route fails closed
// when it cannot tell what kind of credential is driving it.
func TestDeleteAccountHandler_UnresolvableAssuranceFailsClosed(t *testing.T) {
	svc := &servicetest.MockService{
		DeleteAccountFunc: func(context.Context, string, uuid.UUID) error { return nil },
	}
	withUser := identity.WithUserResolver(func(*http.Request) (*identity.User, bool) {
		return &identity.User{ID: uuid.Must(uuid.NewV7())}, true
	})

	rec := httptest.NewRecorder()
	identity.DeleteAccountHandler(svc, withUser)(rec, postForm(url.Values{}))
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = httptest.NewRecorder()
	identity.DeleteAccountHandler(svc, withUser, identity.WithInsecureNoStepUpCheck())(rec, postForm(url.Values{}))
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

// TestDeleteAccountHandler_EnrolledUserMustPresentSecondFactor proves the stronger bar available with
// WithMFAGate: a user who HAS a confirmed second factor cannot delete their account from a session
// that never presented it (a stolen password-only session), while a user with no factor is
// unaffected.
func TestDeleteAccountHandler_EnrolledUserMustPresentSecondFactor(t *testing.T) {
	cases := []struct {
		name      string
		gate      identity.MFAEnrollmentChecker
		assurance identity.HandlerOption
		wantCode  int
	}{
		{
			name:      "enrolled + password-only session -> refused",
			gate:      stubMFAGate{enrolled: true},
			assurance: fullSessionAssurance(),
			wantCode:  http.StatusForbidden,
		},
		{
			name:      "enrolled + stepped-up session -> allowed",
			gate:      stubMFAGate{enrolled: true},
			assurance: steppedUpAssurance(),
			wantCode:  http.StatusNoContent,
		},
		{
			name:      "not enrolled -> unaffected",
			gate:      stubMFAGate{enrolled: false},
			assurance: fullSessionAssurance(),
			wantCode:  http.StatusNoContent,
		},
		{
			name:      "enrollment check error -> fails closed with 500",
			gate:      stubMFAGate{err: assert.AnError},
			assurance: fullSessionAssurance(),
			wantCode:  http.StatusInternalServerError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var deleted bool
			svc := &servicetest.MockService{
				DeleteAccountFunc: func(context.Context, string, uuid.UUID) error {
					deleted = true
					return nil
				},
			}
			h := identity.DeleteAccountHandler(svc,
				identity.WithUserResolver(func(*http.Request) (*identity.User, bool) {
					return &identity.User{ID: uuid.Must(uuid.NewV7())}, true
				}),
				identity.WithMFAGate(tc.gate), tc.assurance)

			rec := httptest.NewRecorder()
			h(rec, postForm(url.Values{}))

			require.Equal(t, tc.wantCode, rec.Code)
			assert.Equal(t, tc.wantCode == http.StatusNoContent, deleted)
		})
	}
}
