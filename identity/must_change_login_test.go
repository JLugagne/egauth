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

// TestLoginHandler_MustChange_AccessOnlyFlagged proves SC-5 for the password login path: a user
// whose credential the rotation policy flags is still authenticated (login succeeds) but receives
// an ACCESS-ONLY token carrying MustChangePassword=true and NO refresh cookie, so a silent refresh
// cannot drop the flag and slip past the gate.
func TestLoginHandler_MustChange_AccessOnlyFlagged(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return &identity.User{ID: uid}, nil
		},
		PasswordChangeRequiredFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
			assert.Equal(t, uid, userID)
			return true, nil
		},
	}
	var captured tokens.Claims[struct{}]
	h := identity.LoginHandler[struct{}](svc, capturingIssuer(&captured), testClaimsBuilder())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "secret", ""))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName), "flagged login must still issue an access cookie")
	assert.Nil(t, cookieByName(rec, tokens.DefaultRefreshCookieName),
		"a must-change login must NOT receive a refresh cookie")
	assert.True(t, captured.MustChangePassword, "the access token must carry must_change_password=true")
	assert.False(t, captured.ExpiresAt.IsZero(), "the flagged token must carry a short explicit expiry")
}

// TestLoginHandler_MustChange_NormalUserFullPair confirms the gate is transparent for an unflagged
// user: they still receive the full access+refresh pair.
func TestLoginHandler_MustChange_NormalUserFullPair(t *testing.T) {
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
		PasswordChangeRequiredFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
			return false, nil
		},
	}
	var captured tokens.Claims[struct{}]
	h := identity.LoginHandler[struct{}](svc, capturingIssuer(&captured), testClaimsBuilder())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "secret", ""))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName))
	require.NotNil(t, cookieByName(rec, tokens.DefaultRefreshCookieName),
		"an unflagged user keeps the full refreshable pair")
	assert.False(t, captured.MustChangePassword, "an unflagged token must not carry must_change_password")
}

// TestLoginHandler_MustChange_MFAEnrolledCarriesFlag proves the MFA + must-change interaction: an
// enrolled user who is also flagged must still take the interim path FIRST (AMR=[pwd], no refresh),
// but the interim token must carry must_change_password=true so the step-up re-issuance (TASK-065)
// can preserve it — the user cannot escape the gate by completing the second factor.
func TestLoginHandler_MustChange_MFAEnrolledCarriesFlag(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return &identity.User{ID: uid}, nil
		},
		PasswordChangeRequiredFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
			return true, nil
		},
	}
	var captured tokens.Claims[struct{}]
	h := identity.LoginHandler[struct{}](svc, capturingIssuer(&captured), testClaimsBuilder(),
		identity.WithMFAGate(stubMFAGate{enrolled: true}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "secret", ""))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName), "interim access cookie expected")
	assert.Nil(t, cookieByName(rec, tokens.DefaultRefreshCookieName),
		"MFA-gated pre-step-up login must NOT receive a refresh cookie")
	assert.Equal(t, []string{tokens.AMRPassword}, captured.AMR, "interim AMR must be [pwd]")
	assert.True(t, captured.MustChangePassword,
		"an MFA-enrolled must-change user's interim token must carry the flag for step-up to preserve")
}

// TestMagicLinkLoginHandler_MustChange_AccessOnlyFlagged proves SC-5 for the passwordless path: a
// must-change user completing a magic-link login receives an access-only flagged token, no refresh.
func TestMagicLinkLoginHandler_MustChange_AccessOnlyFlagged(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	svc := &servicetest.MockService{
		LoginWithMagicLinkFunc: func(ctx context.Context, tenantID string, token string) (*identity.User, error) {
			return &identity.User{ID: uid}, nil
		},
		PasswordChangeRequiredFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
			assert.Equal(t, uid, userID)
			return true, nil
		},
	}
	var captured tokens.Claims[struct{}]
	h := identity.MagicLinkLoginHandler[struct{}](svc, capturingIssuer(&captured), testClaimsBuilder())

	rec := httptest.NewRecorder()
	h(rec, postForm(url.Values{"token": {"sel.ver"}}))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName), "flagged magic-link login must still issue an access cookie")
	assert.Nil(t, cookieByName(rec, tokens.DefaultRefreshCookieName),
		"a must-change magic-link login must NOT receive a refresh cookie")
	assert.True(t, captured.MustChangePassword, "the access token must carry must_change_password=true")
	assert.False(t, captured.ExpiresAt.IsZero(), "the flagged token must carry a short explicit expiry")
}

// TestMagicLinkLoginHandler_MustChange_NormalUserFullPair confirms an unflagged magic-link login
// still yields the full access+refresh pair.
func TestMagicLinkLoginHandler_MustChange_NormalUserFullPair(t *testing.T) {
	svc := &servicetest.MockService{
		LoginWithMagicLinkFunc: func(ctx context.Context, tenantID string, token string) (*identity.User, error) {
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
		PasswordChangeRequiredFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
			return false, nil
		},
	}
	var captured tokens.Claims[struct{}]
	h := identity.MagicLinkLoginHandler[struct{}](svc, capturingIssuer(&captured), testClaimsBuilder())

	rec := httptest.NewRecorder()
	h(rec, postForm(url.Values{"token": {"sel.ver"}}))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName))
	require.NotNil(t, cookieByName(rec, tokens.DefaultRefreshCookieName),
		"an unflagged magic-link login keeps the full refreshable pair")
	assert.False(t, captured.MustChangePassword)
}
