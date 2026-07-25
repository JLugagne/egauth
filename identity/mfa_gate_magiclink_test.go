package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func magicLinkForm(t *testing.T, token string) *http.Request {
	t.Helper()
	form := url.Values{}
	form.Set("token", token)
	req := httptest.NewRequest(http.MethodPost, "/login/magic", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+req.Host)
	return req
}

// TestMagicLinkLoginHandler_MFAGate_EnrolledGetsInterimNoRefresh proves finding mfa/SF-3 for the
// identity half: WithMFAGate must gate EVERY login path, not just the password form. A mailbox
// compromise must not hand an MFA-enrolled user a full, indefinitely renewable session.
func TestMagicLinkLoginHandler_MFAGate_EnrolledGetsInterimNoRefresh(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	svc := &servicetest.MockService{
		LoginWithMagicLinkFunc: func(ctx context.Context, tenantID, token string, rc ...event.RequestContext) (*identity.User, error) {
			return &identity.User{ID: uid}, nil
		},
	}
	var captured tokens.Claims[struct{}]
	h := identity.MagicLinkLoginHandler[struct{}](svc, capturingIssuer(&captured), testClaimsBuilder(),
		identity.WithMFAGate(stubMFAGate{enrolled: true}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, magicLinkForm(t, "magic-token"))

	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName),
		"the interim access cookie is expected")
	requireNoRenewableRefresh(t, rec)
	assert.NotContains(t, captured.AMR, tokens.AMRMFA,
		"the pre-step-up credential must not carry the MFA factor")
	assert.False(t, captured.ExpiresAt.IsZero(),
		"the pre-step-up credential must carry a short explicit expiry")
}

// TestMagicLinkLoginHandler_MFAGate_NotEnrolledGetsFullPair confirms the gate stays transparent for
// users with no enrolled factor: they keep the full renewable pair.
func TestMagicLinkLoginHandler_MFAGate_NotEnrolledGetsFullPair(t *testing.T) {
	svc := &servicetest.MockService{
		LoginWithMagicLinkFunc: func(ctx context.Context, tenantID, token string, rc ...event.RequestContext) (*identity.User, error) {
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	h := identity.MagicLinkLoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder(),
		identity.WithMFAGate(stubMFAGate{enrolled: false}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, magicLinkForm(t, "magic-token"))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName))
	require.NotNil(t, cookieByName(rec, tokens.DefaultRefreshCookieName),
		"a non-enrolled user keeps the full refreshable pair")
}

// TestMagicLinkLoginHandler_MFAGate_CheckErrorFailsClosed proves the gate fails closed: an
// enrollment-check error must never fall through to a full session.
func TestMagicLinkLoginHandler_MFAGate_CheckErrorFailsClosed(t *testing.T) {
	svc := &servicetest.MockService{
		LoginWithMagicLinkFunc: func(ctx context.Context, tenantID, token string, rc ...event.RequestContext) (*identity.User, error) {
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	h := identity.MagicLinkLoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder(),
		identity.WithMFAGate(stubMFAGate{err: assert.AnError}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, magicLinkForm(t, "magic-token"))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Nil(t, cookieByName(rec, tokens.DefaultRefreshCookieName))
	assert.Nil(t, cookieByName(rec, tokens.DefaultAccessCookieName))
}
