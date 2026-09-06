package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubMFAGate is a minimal MFA enrollment checker for the gate tests.
type stubMFAGate struct {
	enrolled bool
	err      error
}

func (s stubMFAGate) IsEnrolled(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
	return s.enrolled, s.err
}

// capturingIssuer records the claims it is asked to issue so the test can assert on the AMR.
func capturingIssuer(captured *tokens.Claims[struct{}]) *issuertest.MockIssuer[struct{}] {
	return &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(ctx context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			*captured = claims
			return &tokens.TokenPair[struct{}]{
				AccessToken:           "access-jwt",
				RefreshToken:          "refresh-opaque",
				RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
				Claims:                claims,
			}, nil
		},
	}
}

// TestLoginHandler_MFAGate_EnrolledGetsInterimNoRefresh proves the producing half of the
// documented AMR/step-up model: under WithMFAGate, a password-only login by an MFA-enrolled
// user must NOT receive a full refreshable pair. It must receive a short-lived INTERIM access
// token stamped AMR=[pwd] (never AMRMFA) and NO refresh cookie.
func TestLoginHandler_MFAGate_EnrolledGetsInterimNoRefresh(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return &identity.User{ID: uid}, nil
		},
	}
	var captured tokens.Claims[struct{}]
	h := identity.LoginHandler[struct{}](svc, capturingIssuer(&captured), testClaimsBuilder(),
		identity.WithMFAGate(stubMFAGate{enrolled: true}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "secret", ""))

	assert.Equal(t, http.StatusNoContent, rec.Code)

	// An enrolled user gets the interim access cookie but NO refresh cookie: the pre-MFA state
	// must not be an indefinitely renewable full session.
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName), "interim access cookie expected")
	assert.Nil(t, cookieByName(rec, tokens.DefaultRefreshCookieName),
		"MFA-gated pre-step-up login must NOT receive a refresh cookie")

	// The interim token carries only the password factor — never the MFA marker.
	assert.Equal(t, []string{tokens.AMRPassword}, captured.AMR, "interim AMR must be [pwd]")
	assert.NotContains(t, captured.AMR, tokens.AMRMFA, "interim token must not carry the MFA factor")
	assert.False(t, captured.ExpiresAt.IsZero(), "interim token must carry a short explicit expiry")
}

// TestLoginHandler_MFAGate_NotEnrolledGetsFullPair confirms the gate is transparent for users
// without MFA: they still receive the full access+refresh pair.
func TestLoginHandler_MFAGate_NotEnrolledGetsFullPair(t *testing.T) {
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	var captured tokens.Claims[struct{}]
	h := identity.LoginHandler[struct{}](svc, capturingIssuer(&captured), testClaimsBuilder(),
		identity.WithMFAGate(stubMFAGate{enrolled: false}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "secret", ""))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName))
	require.NotNil(t, cookieByName(rec, tokens.DefaultRefreshCookieName),
		"a non-enrolled user keeps the full refreshable pair")
}

// TestMagicLinkLoginHandler_MFAGate_EnrolledGetsInterimNoRefresh proves the need for issue #71
// (SEC-ID-03): MagicLinkLoginHandler currently ignores WithMFAGate entirely, so an MFA-enrolled
// user receives a full refreshable pair from an emailed link alone — a complete second-factor
// bypass for anyone who compromises the mailbox. The magic-link path must follow the same
// contract as the password path: enrolled users get a short-lived INTERIM access token (no
// refresh cookie, no AMRMFA) and must complete mfa.StepUpHandler for the full session.
func TestMagicLinkLoginHandler_MFAGate_EnrolledGetsInterimNoRefresh(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	svc := &servicetest.MockService{
		LoginWithMagicLinkFunc: func(ctx context.Context, tenantID string, token string, _ ...event.RequestContext) (*identity.User, error) {
			return &identity.User{ID: uid}, nil
		},
		PasswordChangeRequiredFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
			return false, nil
		},
	}
	var captured tokens.Claims[struct{}]
	h := identity.MagicLinkLoginHandler[struct{}](svc, capturingIssuer(&captured), testClaimsBuilder(),
		identity.WithMFAGate(stubMFAGate{enrolled: true}))

	rec := httptest.NewRecorder()
	h(rec, postForm(url.Values{"token": {"sel.ver"}}))

	require.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName), "interim access cookie expected")
	assert.Nil(t, cookieByName(rec, tokens.DefaultRefreshCookieName),
		"SEC-ID-03: an MFA-enrolled magic-link login must NOT receive a refresh cookie before step-up")
	assert.NotContains(t, captured.AMR, tokens.AMRMFA, "interim token must not carry the MFA factor")
	assert.False(t, captured.ExpiresAt.IsZero(), "interim token must carry a short explicit expiry")
}

// TestMagicLinkLoginHandler_MFAGate_NotEnrolledGetsFullPair is the transparency guard for the
// SEC-ID-03 fix: users without an enrolled second factor keep the full refreshable pair on the
// magic-link path, exactly as on the password path.
func TestMagicLinkLoginHandler_MFAGate_NotEnrolledGetsFullPair(t *testing.T) {
	svc := &servicetest.MockService{
		LoginWithMagicLinkFunc: func(ctx context.Context, tenantID string, token string, _ ...event.RequestContext) (*identity.User, error) {
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
		PasswordChangeRequiredFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
			return false, nil
		},
	}
	var captured tokens.Claims[struct{}]
	h := identity.MagicLinkLoginHandler[struct{}](svc, capturingIssuer(&captured), testClaimsBuilder(),
		identity.WithMFAGate(stubMFAGate{enrolled: false}))

	rec := httptest.NewRecorder()
	h(rec, postForm(url.Values{"token": {"sel.ver"}}))

	require.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName))
	require.NotNil(t, cookieByName(rec, tokens.DefaultRefreshCookieName),
		"a non-enrolled user keeps the full refreshable pair on the magic-link path")
}
