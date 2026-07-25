package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChangePasswordWithReissueHandler_MustChangeUser_ReceivesFreshPair proves SC-5/SC-6: an
// authenticated user whose credential the rotation policy had flagged POSTs a valid password
// change and receives a FRESH FULL ACCESS+REFRESH pair whose access token has
// MustChangePassword=false — so the user is immediately re-authenticated without another login.
func TestChangePasswordWithReissueHandler_MustChangeUser_ReceivesFreshPair(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	svc := &servicetest.MockService{
		ChangePasswordFunc: func(ctx context.Context, tenantID string, userID uuid.UUID, current, newPw string) error {
			assert.Equal(t, uid, userID)
			assert.Equal(t, "old-pass", current)
			assert.Equal(t, "NewValidPass123!", newPw)
			return nil
		},
	}

	withUser := identity.WithUserResolver(func(r *http.Request) (*identity.User, bool) {
		// Simulate a user who was previously flagged; the flag is now cleared by ChangePassword.
		return &identity.User{ID: uid}, true
	})

	var captured tokens.Claims[struct{}]
	h := identity.ChangePasswordWithReissueHandler[struct{}](svc, capturingIssuer(&captured), testClaimsBuilder(), withUser, fullSessionAssurance())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, changePwForm(t, "old-pass", "NewValidPass123!"))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName),
		"re-issue handler must write an access cookie on success")
	require.NotNil(t, cookieByName(rec, tokens.DefaultRefreshCookieName),
		"re-issue handler must write a refresh cookie on success (full pair)")
	assert.False(t, captured.MustChangePassword,
		"the fresh token must NOT carry must_change_password — the flag was cleared")
}

// TestChangePasswordWithReissueHandler_NormalUser_ReceivesFreshPair confirms a non-flagged user
// also gets the full pair on a successful change (the handler is not restricted to flagged users).
func TestChangePasswordWithReissueHandler_NormalUser_ReceivesFreshPair(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	svc := &servicetest.MockService{
		ChangePasswordFunc: func(ctx context.Context, tenantID string, userID uuid.UUID, current, newPw string) error {
			return nil
		},
	}

	withUser := identity.WithUserResolver(func(r *http.Request) (*identity.User, bool) {
		return &identity.User{ID: uid}, true
	})

	var captured tokens.Claims[struct{}]
	h := identity.ChangePasswordWithReissueHandler[struct{}](svc, capturingIssuer(&captured), testClaimsBuilder(), withUser, fullSessionAssurance())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, changePwForm(t, "old-pass", "NewValidPass123!"))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName))
	require.NotNil(t, cookieByName(rec, tokens.DefaultRefreshCookieName))
	assert.False(t, captured.MustChangePassword)
}

// TestChangePasswordWithReissueHandler_WrongPassword_Returns401 confirms that a bad current
// password still returns 401 and no cookies are written (the re-issue path is never reached).
func TestChangePasswordWithReissueHandler_WrongPassword_Returns401(t *testing.T) {
	svc := &servicetest.MockService{
		ChangePasswordFunc: func(ctx context.Context, tenantID string, userID uuid.UUID, current, newPw string) error {
			return identity.ErrInvalidCredentials
		},
	}

	withUser := identity.WithUserResolver(func(r *http.Request) (*identity.User, bool) {
		return &identity.User{ID: uuid.Must(uuid.NewV7())}, true
	})

	h := identity.ChangePasswordWithReissueHandler[struct{}](svc, okIssuer(), testClaimsBuilder(), withUser, fullSessionAssurance())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, changePwForm(t, "wrong", "NewValidPass123!"))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_credentials")
	assert.Nil(t, cookieByName(rec, tokens.DefaultAccessCookieName),
		"no cookies must be written when the change fails")
	assert.Nil(t, cookieByName(rec, tokens.DefaultRefreshCookieName))
}

// TestChangePasswordWithReissueHandler_PolicyRejection_Returns400 confirms that a new password
// rejected by the policy returns 400 and no cookies are written.
func TestChangePasswordWithReissueHandler_PolicyRejection_Returns400(t *testing.T) {
	svc := &servicetest.MockService{
		ChangePasswordFunc: func(ctx context.Context, tenantID string, userID uuid.UUID, current, newPw string) error {
			return passwords.ErrPasswordTooShort
		},
	}

	withUser := identity.WithUserResolver(func(r *http.Request) (*identity.User, bool) {
		return &identity.User{ID: uuid.Must(uuid.NewV7())}, true
	})

	h := identity.ChangePasswordWithReissueHandler[struct{}](svc, okIssuer(), testClaimsBuilder(), withUser, fullSessionAssurance())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, changePwForm(t, "old-pass", "x"))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "password_rejected")
	assert.Nil(t, cookieByName(rec, tokens.DefaultAccessCookieName))
	assert.Nil(t, cookieByName(rec, tokens.DefaultRefreshCookieName))
}

// TestChangePasswordWithReissueHandler_NoResolver_Returns401 confirms that omitting
// WithUserResolver returns 401 — same guard as the plain ChangePasswordHandler.
func TestChangePasswordWithReissueHandler_NoResolver_Returns401(t *testing.T) {
	h := identity.ChangePasswordWithReissueHandler[struct{}](&servicetest.MockService{}, okIssuer(), testClaimsBuilder())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, changePwForm(t, "old-pass", "NewValidPass123!"))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
