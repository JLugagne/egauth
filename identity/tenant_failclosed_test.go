package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hostTenantResolver models the natural implementation of a multi-tenant resolver: a map of
// known hosts to tenant IDs, returning "" for a Host it cannot map.
func hostTenantResolver(mapping map[string]string) func(*http.Request) string {
	return func(r *http.Request) string { return mapping[r.Host] }
}

func unmappedHost(req *http.Request) *http.Request {
	req.Host = "unmapped.example.com"
	req.Header.Set("Origin", "https://"+req.Host)
	return req
}

func TestLoginHandler_UnresolvedTenantRefusesAuthentication(t *testing.T) {
	var authenticated atomic.Bool
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			authenticated.Store(true)
			return &identity.User{ID: uuid.Must(uuid.NewV7()), TenantID: tenantID}, nil
		},
		PasswordChangeRequiredFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
			return false, nil
		},
	}
	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder(),
		identity.WithTenantResolver(hostTenantResolver(map[string]string{"acme.example.com": "acme"})))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, unmappedHost(loginForm(t, "/login", "root@example.com", "secret", "")))

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "an unmapped Host must not authenticate")
	assert.False(t, authenticated.Load(), "Authenticate must never run for an unresolved tenant")
	assert.Nil(t, cookieByName(rec, tokens.DefaultAccessCookieName))
	assert.Nil(t, cookieByName(rec, tokens.DefaultRefreshCookieName))
}

func TestRegisterHandler_UnresolvedTenantCreatesNoAccount(t *testing.T) {
	var registered atomic.Bool
	svc := &servicetest.MockService{
		RegisterFunc: func(ctx context.Context, tenantID string, email, password string) (*identity.User, error) {
			registered.Store(true)
			return &identity.User{ID: uuid.Must(uuid.NewV7()), TenantID: tenantID}, nil
		},
	}
	h := identity.RegisterHandler[struct{}](svc, okIssuer(), testClaimsBuilder(),
		identity.WithTenantResolver(hostTenantResolver(map[string]string{"acme.example.com": "acme"})))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, unmappedHost(loginForm(t, "/register", "root@example.com", "secret", "")))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, registered.Load(), "an unmapped Host must not create an account in the \"\" partition")
	assert.Nil(t, cookieByName(rec, tokens.DefaultAccessCookieName))
}

func TestLoginHandler_SingleTenantWithoutResolverStillWorks(t *testing.T) {
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			assert.Equal(t, "", tenantID)
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "secret", ""))

	assert.Equal(t, http.StatusNoContent, rec.Code, "no resolver configured is the legitimate single-tenant mode")
}

// tenantRecordingGate records every tenant the MFA gate is consulted with and reports
// enrollment only for the partition the factor actually lives in.
type tenantRecordingGate struct {
	enrolledIn string
	tenants    []string
}

func (g *tenantRecordingGate) IsEnrolled(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
	g.tenants = append(g.tenants, tenantID)
	return tenantID == g.enrolledIn, nil
}

// TestLoginHandler_ImpureResolverCannotSkipMFAGate proves the tenant is resolved ONCE per
// request. With a resolver that maps the request correctly on its first call and then goes
// blind (an expiring cache entry, a transient store error), a per-call re-resolution made the
// MFA gate look up enrollment under the wrong ("") partition, find nothing, and issue a full
// renewable session on the password alone.
func TestLoginHandler_ImpureResolverCannotSkipMFAGate(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	var authTenant string
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			authTenant = tenantID
			return &identity.User{ID: uid, TenantID: tenantID}, nil
		},
		PasswordChangeRequiredFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
			return false, nil
		},
	}
	gate := &tenantRecordingGate{enrolledIn: "acme"}

	var calls atomic.Int32
	impure := func(*http.Request) string {
		if calls.Add(1) == 1 {
			return "acme"
		}
		return ""
	}

	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder(),
		identity.WithTenantResolver(impure), identity.WithMFAGate(gate))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "secret", ""))

	// The gate fired, so the reply is the pre-step-up one (200 + mfa_required), not a full login's 204.
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "acme", authTenant)
	assert.Equal(t, []string{"acme"}, gate.tenants,
		"the MFA gate must be consulted with the tenant pinned at the start of the request")
	requireNoRenewableRefresh(t, rec)
}

func TestRequestPasswordResetHandler_UnresolvedTenantRefused(t *testing.T) {
	var called atomic.Bool
	svc := &servicetest.MockService{
		RequestPasswordResetFunc: func(ctx context.Context, tenantID string, email string) (string, *identity.User, error) {
			called.Store(true)
			return "", nil, nil
		},
	}
	h := identity.RequestPasswordResetHandler(svc, identity.Mailer{},
		identity.WithTenantResolver(hostTenantResolver(map[string]string{"acme.example.com": "acme"})))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, unmappedHost(loginForm(t, "/reset/request", "root@example.com", "", "")))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, called.Load(), "the reset flow must not run against the \"\" partition")
}

func TestVerifyEmailHandler_UnresolvedTenantRefused(t *testing.T) {
	var called atomic.Bool
	svc := &servicetest.MockService{
		VerifyEmailFunc: func(ctx context.Context, tenantID string, token string) (*identity.User, error) {
			called.Store(true)
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	h := identity.VerifyEmailHandler(svc,
		identity.WithTenantResolver(hostTenantResolver(map[string]string{"acme.example.com": "acme"})))

	form := url.Values{}
	form.Set("token", "tok")
	req := httptest.NewRequest(http.MethodPost, "/verify-email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, unmappedHost(req))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, called.Load())
}

func TestDeleteAccountHandler_UnresolvedTenantRefused(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	var called atomic.Bool
	svc := &servicetest.MockService{
		DeleteAccountFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) error {
			called.Store(true)
			return nil
		},
	}
	h := identity.DeleteAccountHandler(svc,
		identity.WithUserResolver(func(*http.Request) (*identity.User, bool) {
			return &identity.User{ID: uid}, true
		}),
		identity.WithTenantResolver(hostTenantResolver(map[string]string{"acme.example.com": "acme"})))

	req := httptest.NewRequest(http.MethodPost, "/account/delete", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, unmappedHost(req))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, called.Load(), "an unresolved tenant must not delete an account in the \"\" partition")
}
