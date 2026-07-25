package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoginHandler_MustChange_RenewableFlagged proves SC-5 for the password login path: a user
// whose credential is flagged is authenticated and receives a full, RENEWABLE pair (access AND
// refresh) carrying MustChangePassword=true. The refresh family persists the flag (Rotate replays
// it), so the renewable session stays gated until the password is changed — the user cannot escape
// by waiting for the access token to expire.
func TestLoginHandler_MustChange_RenewableFlagged(t *testing.T) {
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
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName), "flagged login must issue an access cookie")
	require.NotNil(t, cookieByName(rec, tokens.DefaultRefreshCookieName),
		"a flagged login is renewable: it MUST receive a refresh cookie (the flag is carried across refresh, not dropped)")
	assert.True(t, captured.MustChangePassword, "the access token must carry must_change_password=true")
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

	// The MFA-gated pre-step-up response is distinguishable from a full login's 204.
	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName), "interim access cookie expected")
	requireNoRenewableRefresh(t, rec)
	assert.Equal(t, []string{tokens.AMRPassword}, captured.AMR, "interim AMR must be [pwd]")
	assert.True(t, captured.MustChangePassword,
		"an MFA-enrolled must-change user's interim token must carry the flag for step-up to preserve")
}

// TestMagicLinkLoginHandler_MustChange_RenewableFlagged proves SC-5 for the passwordless path: a
// must-change user completing a magic-link login receives a full, renewable pair carrying the flag.
func TestMagicLinkLoginHandler_MustChange_RenewableFlagged(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	svc := &servicetest.MockService{
		LoginWithMagicLinkFunc: func(ctx context.Context, tenantID string, token string, _ ...event.RequestContext) (*identity.User, error) {
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
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName), "flagged magic-link login must issue an access cookie")
	require.NotNil(t, cookieByName(rec, tokens.DefaultRefreshCookieName),
		"a flagged magic-link login is renewable: it MUST receive a refresh cookie")
	assert.True(t, captured.MustChangePassword, "the access token must carry must_change_password=true")
}

// TestMagicLinkLoginHandler_MustChange_NormalUserFullPair confirms an unflagged magic-link login
// still yields the full access+refresh pair.
func TestMagicLinkLoginHandler_MustChange_NormalUserFullPair(t *testing.T) {
	svc := &servicetest.MockService{
		LoginWithMagicLinkFunc: func(ctx context.Context, tenantID string, token string, _ ...event.RequestContext) (*identity.User, error) {
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
