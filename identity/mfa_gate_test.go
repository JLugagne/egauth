package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	uid := uuid.New()
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
			return &identity.User{ID: uuid.New()}, nil
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
