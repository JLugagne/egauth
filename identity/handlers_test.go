package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testClaimsBuilder() identity.ClaimsBuilder[struct{}] {
	return func(u *identity.User) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: u.ID, TenantID: u.TenantID}
	}
}

func okIssuer() *issuertest.MockIssuer[struct{}] {
	return &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(ctx context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			return &tokens.TokenPair[struct{}]{
				AccessToken:           "access-jwt",
				RefreshToken:          "refresh-opaque",
				RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
				Claims:                claims,
			}, nil
		},
	}
}

func loginForm(t *testing.T, path, email, password, remember string) *http.Request {
	t.Helper()
	form := url.Values{}
	form.Set("email", email)
	form.Set("password", password)
	if remember != "" {
		form.Set("remember_me", remember)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Same-origin by default so business-logic tests pass the strict-by-default CSRF check
	// (httptest.NewRequest sets Host to "example.com"). CSRF tests override this header (or
	// delete it) to exercise the cross-origin / missing-origin paths explicitly.
	req.Header.Set("Origin", "https://"+req.Host)
	return req
}

func cookieByName(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestLoginHandler_SuccessSetsCookies(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			assert.Equal(t, "password", provider)
			assert.Equal(t, "user@example.com", providerID)
			return &identity.User{ID: uid}, nil
		},
	}
	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "secret", ""))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	access := cookieByName(rec, tokens.DefaultAccessCookieName)
	refresh := cookieByName(rec, tokens.DefaultRefreshCookieName)
	require.NotNil(t, access)
	require.NotNil(t, refresh)
	assert.Equal(t, "access-jwt", access.Value)
	assert.True(t, access.HttpOnly)
	assert.Equal(t, "refresh-opaque", refresh.Value)
	assert.Equal(t, 0, refresh.MaxAge, "without remember_me the refresh cookie is a session cookie")
}

func TestLoginHandler_RememberMePersistsRefresh(t *testing.T) {
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "secret", "on"))

	refresh := cookieByName(rec, tokens.DefaultRefreshCookieName)
	require.NotNil(t, refresh)
	assert.Greater(t, refresh.MaxAge, 0, "remember_me must make the refresh cookie persistent")
}

func changePwForm(t *testing.T, current, newPw string) *http.Request {
	t.Helper()
	form := url.Values{}
	form.Set("current_password", current)
	form.Set("new_password", newPw)
	req := httptest.NewRequest(http.MethodPost, "/account/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Same-origin by default so business-logic tests pass the strict-by-default CSRF check.
	req.Header.Set("Origin", "https://"+req.Host)
	return req
}

func TestChangePasswordHandler(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	withUser := identity.WithUserResolver(func(r *http.Request) (*identity.User, bool) {
		return &identity.User{ID: uid}, true
	})

	t.Run("no resolver returns 401", func(t *testing.T) {
		h := identity.ChangePasswordHandler(&servicetest.MockService{})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, changePwForm(t, "old", "NewValidPass123!"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("wrong current password returns 401", func(t *testing.T) {
		svc := &servicetest.MockService{
			ChangePasswordFunc: func(ctx context.Context, tenantID string, userID uuid.UUID, current, newPassword string) error {
				assert.Equal(t, uid, userID)
				return identity.ErrInvalidCredentials
			},
		}
		rec := httptest.NewRecorder()
		identity.ChangePasswordHandler(svc, withUser).ServeHTTP(rec, changePwForm(t, "wrong", "NewValidPass123!"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "invalid_credentials")
	})

	t.Run("policy rejection returns 400", func(t *testing.T) {
		svc := &servicetest.MockService{
			ChangePasswordFunc: func(ctx context.Context, tenantID string, userID uuid.UUID, current, newPassword string) error {
				return passwords.ErrPasswordTooShort
			},
		}
		rec := httptest.NewRecorder()
		identity.ChangePasswordHandler(svc, withUser).ServeHTTP(rec, changePwForm(t, "old", "x"))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "password_rejected")
	})

	t.Run("disabled account returns 403", func(t *testing.T) {
		svc := &servicetest.MockService{
			ChangePasswordFunc: func(ctx context.Context, tenantID string, userID uuid.UUID, current, newPassword string) error {
				assert.Equal(t, uid, userID)
				return identity.ErrAccountDisabled
			},
		}
		rec := httptest.NewRecorder()
		identity.ChangePasswordHandler(svc, withUser).ServeHTTP(rec, changePwForm(t, "old", "NewValidPass123!"))
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "account_disabled")
	})

	t.Run("success returns 204 and passes the fields through", func(t *testing.T) {
		called := false
		svc := &servicetest.MockService{
			ChangePasswordFunc: func(ctx context.Context, tenantID string, userID uuid.UUID, current, newPassword string) error {
				called = true
				assert.Equal(t, "old-pass", current)
				assert.Equal(t, "NewValidPass123!", newPassword)
				return nil
			},
		}
		rec := httptest.NewRecorder()
		identity.ChangePasswordHandler(svc, withUser).ServeHTTP(rec, changePwForm(t, "old-pass", "NewValidPass123!"))
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.True(t, called)
	})
}

func TestChangePasswordWithReissueHandler_DisabledAccount_Returns403(t *testing.T) {
	svc := &servicetest.MockService{
		ChangePasswordFunc: func(ctx context.Context, tenantID string, userID uuid.UUID, current, newPw string) error {
			return identity.ErrAccountDisabled
		},
	}

	withUser := identity.WithUserResolver(func(r *http.Request) (*identity.User, bool) {
		return &identity.User{ID: uuid.Must(uuid.NewV7())}, true
	})

	h := identity.ChangePasswordWithReissueHandler[struct{}](svc, okIssuer(), testClaimsBuilder(), withUser)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, changePwForm(t, "old", "NewValidPass123!"))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "account_disabled")
	assert.Nil(t, cookieByName(rec, tokens.DefaultAccessCookieName),
		"no cookies must be written when account is disabled")
	assert.Nil(t, cookieByName(rec, tokens.DefaultRefreshCookieName))
}

func TestLoginHandler_RejectsOversizedBody(t *testing.T) {
	called := false
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			called = true
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder())

	// A password far larger than the body cap must be rejected before it reaches the service
	// (and thus the expensive argon2 KDF): a pre-authentication amplification DoS guard.
	huge := strings.Repeat("a", int(identity.DefaultMaxBodyBytes)+(1<<10))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", huge, ""))

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.Contains(t, rec.Body.String(), "request_too_large")
	assert.False(t, called, "service must not be invoked for an over-limit body")
}

func TestLoginHandler_InvalidCredentials(t *testing.T) {
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return nil, identity.ErrInvalidCredentials
		},
	}
	// Issuer must never be called on the failure path.
	h := identity.LoginHandler[struct{}](svc, &issuertest.MockIssuer[struct{}]{}, testClaimsBuilder())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "wrong", ""))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_credentials")
	assert.Nil(t, cookieByName(rec, tokens.DefaultAccessCookieName), "no cookie on failed login")
}

func TestLoginHandler_AccountLocked(t *testing.T) {
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return nil, identity.ErrAccountLocked
		},
	}
	h := identity.LoginHandler[struct{}](svc, &issuertest.MockIssuer[struct{}]{}, testClaimsBuilder())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "secret", ""))

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Contains(t, rec.Body.String(), "account_locked")
}

// TestLoginHandler_AccountEnumeration_UniformResponseOnLockout confirms SEC-ID-04 (CVSS 8.2).
//
// Security invariant:
// The /login authentication endpoint MUST return a uniform response (HTTP 401 Unauthorized
// with error code "invalid_credentials") regardless of account state (non-existent,
// wrong password, or account locked/disabled after repeated failures) in order
// to formally prevent user enumeration.
//
// Current vulnerable behaviour:
// In identity/handlers.go:mapAuthError, ErrAccountLocked and ErrAccountDisabled return
// HTTP 429 Too Many Requests ("account_locked"), whereas a wrong password or a non-existent account
// returns HTTP 401 Unauthorized ("invalid_credentials").
// Although Authenticate uses decoyHash to equalise computation time, the divergence in HTTP code
// (429 vs 401) and JSON payload allows an unauthenticated attacker to enumerate with absolute
// certainty the email addresses registered in the system and remotely lock out accounts (Lockout DoS).
func TestLoginHandler_AccountEnumeration_UniformResponseOnLockout(t *testing.T) {
	// 1. Case: non-existent user (or wrong password)
	svcUnknown := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return nil, identity.ErrInvalidCredentials
		},
	}
	hUnknown := identity.LoginHandler[struct{}](svcUnknown, &issuertest.MockIssuer[struct{}]{}, testClaimsBuilder(), identity.WithUniformAuthErrors())

	recUnknown := httptest.NewRecorder()
	hUnknown.ServeHTTP(recUnknown, loginForm(t, "/login", "unknown@example.com", "wrong", ""))
	assert.Equal(t, http.StatusUnauthorized, recUnknown.Code)
	assert.Contains(t, recUnknown.Body.String(), "invalid_credentials")

	// 2. Case: existing user whose account is locked
	svcLocked := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return nil, identity.ErrAccountLocked
		},
	}
	hLocked := identity.LoginHandler[struct{}](svcLocked, &issuertest.MockIssuer[struct{}]{}, testClaimsBuilder(), identity.WithUniformAuthErrors())

	recLocked := httptest.NewRecorder()
	hLocked.ServeHTTP(recLocked, loginForm(t, "/login", "victim@example.com", "wrong", ""))

	// SECURITY INVARIANT VIOLATED:
	// To prevent user enumeration, the response for a locked account must be
	// identical to that of a non-existent account (HTTP 401 "invalid_credentials").
	assert.Equal(t, http.StatusUnauthorized, recLocked.Code,
		"SEC-ID-04: a locked account must not return HTTP 429 but HTTP 401 to prevent user enumeration")
	assert.Contains(t, recLocked.Body.String(), "invalid_credentials",
		"SEC-ID-04: the error message must not reveal the 'account_locked' state")
}

func TestLoginHandler_FailureRedirect(t *testing.T) {
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return nil, identity.ErrInvalidCredentials
		},
	}
	h := identity.LoginHandler[struct{}](svc, &issuertest.MockIssuer[struct{}]{}, testClaimsBuilder(),
		identity.WithFailureRedirect("/login"))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "wrong", ""))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Contains(t, rec.Header().Get("Location"), "error=invalid_credentials")
}

func TestLoginHandler_SuccessRedirect(t *testing.T) {
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder(),
		identity.WithSuccessRedirect("/dashboard"))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "secret", ""))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/dashboard", rec.Header().Get("Location"))
}

func TestLoginHandler_MethodNotAllowed(t *testing.T) {
	h := identity.LoginHandler[struct{}](&servicetest.MockService{}, &issuertest.MockIssuer[struct{}]{}, testClaimsBuilder())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestLoginHandler_TenantResolverPropagates(t *testing.T) {
	var capturedTenant string
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			capturedTenant = tenantID
			return &identity.User{ID: uuid.Must(uuid.NewV7()), TenantID: capturedTenant}, nil
		},
	}
	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder(),
		identity.WithTenantResolver(func(r *http.Request) string { return "tenant-42" }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "secret", ""))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "tenant-42", capturedTenant, "tenant resolver must scope authentication")
}

func TestLoginHandler_CSRFOriginBlocked(t *testing.T) {
	// Authenticate must never run when the origin check rejects the request.
	svc := &servicetest.MockService{}
	h := identity.LoginHandler[struct{}](svc, &issuertest.MockIssuer[struct{}]{}, testClaimsBuilder(),
		identity.WithTrustedOrigins("app.example.com"))

	req := loginForm(t, "/login", "user@example.com", "secret", "")
	req.Header.Set("Origin", "https://evil.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "cross_site_blocked")
}

func TestLoginHandler_CSRFOriginAllowed(t *testing.T) {
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder(),
		identity.WithTrustedOrigins("app.example.com"))

	req := loginForm(t, "/login", "user@example.com", "secret", "")
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestLoginHandler_CSRFMissingOriginRejected(t *testing.T) {
	// With the check enabled, a browser POST lacking both Origin and Referer is untrusted.
	svc := &servicetest.MockService{}
	h := identity.LoginHandler[struct{}](svc, &issuertest.MockIssuer[struct{}]{}, testClaimsBuilder(),
		identity.WithTrustedOrigins("app.example.com"))

	req := loginForm(t, "/login", "user@example.com", "secret", "")
	req.Header.Del("Origin") // a browser POST lacking both Origin and Referer must be untrusted
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRegisterHandler_SuccessAutoLogin(t *testing.T) {
	svc := &servicetest.MockService{
		RegisterFunc: func(ctx context.Context, tenantID string, email, password string) (*identity.User, error) {
			return &identity.User{ID: uuid.Must(uuid.NewV7()), Email: email}, nil
		},
	}
	h := identity.RegisterHandler[struct{}](svc, okIssuer(), testClaimsBuilder())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/register", "new@example.com", "secret", ""))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName), "register should auto-login")
}

func TestRegisterHandler_EmailTaken(t *testing.T) {
	svc := &servicetest.MockService{
		RegisterFunc: func(ctx context.Context, tenantID string, email, password string) (*identity.User, error) {
			return nil, identity.ErrEmailAlreadyExists
		},
	}
	h := identity.RegisterHandler[struct{}](svc, &issuertest.MockIssuer[struct{}]{}, testClaimsBuilder())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/register", "taken@example.com", "secret", ""))

	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Contains(t, rec.Body.String(), "email_taken")
}

// TestLoginHandler_AccountDisabled_MatchesLockedResponse is a regression test for TASK-057.
// A disabled account must NOT return 500 "login_failed" (which acts as an enumeration oracle).
// The response must be identical to ErrAccountLocked so that callers cannot distinguish
// disabled (existing, suspended) accounts from locked ones, and no account-state information leaks.
func TestLoginHandler_AccountDisabled_MatchesLockedResponse(t *testing.T) {
	svcDisabled := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return nil, identity.ErrAccountDisabled
		},
	}
	svcLocked := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return nil, identity.ErrAccountLocked
		},
	}

	hDisabled := identity.LoginHandler[struct{}](svcDisabled, &issuertest.MockIssuer[struct{}]{}, testClaimsBuilder())
	hLocked := identity.LoginHandler[struct{}](svcLocked, &issuertest.MockIssuer[struct{}]{}, testClaimsBuilder())

	recDisabled := httptest.NewRecorder()
	hDisabled.ServeHTTP(recDisabled, loginForm(t, "/login", "user@example.com", "secret", ""))

	recLocked := httptest.NewRecorder()
	hLocked.ServeHTTP(recLocked, loginForm(t, "/login", "user@example.com", "secret", ""))

	// Both must return the exact same status code and body to prevent account-state enumeration.
	assert.Equal(t, recLocked.Code, recDisabled.Code,
		"disabled account must return the same HTTP status as a locked account (not 500)")
	assert.Equal(t, recLocked.Body.String(), recDisabled.Body.String(),
		"disabled account response body must be identical to locked account response")
	assert.Nil(t, cookieByName(recDisabled, tokens.DefaultAccessCookieName), "no cookie on disabled login")
}

// TestLoginHandler_CSRFBlocksCrossOriginByDefault proves the secure-by-default CSRF behavior:
// with NO WithTrustedOrigins configured, a cross-origin POST must still be rejected, matching
// the tokens handlers. Authenticate must never run for a blocked request.
func TestLoginHandler_CSRFBlocksCrossOriginByDefault(t *testing.T) {
	called := false
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			called = true
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder())

	req := loginForm(t, "/login", "user@example.com", "secret", "")
	req.Host = "app.example.com"
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "cross_site_blocked")
	assert.False(t, called, "Authenticate must not run for a cross-site request with default config")
}

// TestLoginHandler_CSRFAllowsSameOriginByDefault proves the secure default is not a false
// positive: a same-origin POST with no WithTrustedOrigins still succeeds.
func TestLoginHandler_CSRFAllowsSameOriginByDefault(t *testing.T) {
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder())

	req := loginForm(t, "/login", "user@example.com", "secret", "")
	req.Host = "app.example.com"
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
}

// TestLoginHandler_WithInsecureNoOriginCheck proves the loud opt-out restores the pre-v1
// accept-all behavior: a cross-origin POST is accepted and reaches Authenticate.
func TestLoginHandler_WithInsecureNoOriginCheck(t *testing.T) {
	called := false
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			called = true
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder(),
		identity.WithInsecureNoOriginCheck())

	req := loginForm(t, "/login", "user@example.com", "secret", "")
	req.Host = "app.example.com"
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.True(t, called, "Authenticate must run when the origin check is disabled")
}

func TestRequestPasswordResetHandler_DeliverySaturation_BoundedWaitAndFailure(t *testing.T) {
	resetReq := func(email string) *http.Request {
		body := url.Values{"email": {email}}.Encode()
		req := httptest.NewRequest(http.MethodPost, "/auth/reset", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://"+req.Host)
		return req
	}

	user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "user@example.com"}

	t.Run("immediate drop without queue timeout returns 429 service_busy", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestPasswordResetFunc: func(_ context.Context, _ string, email string) (string, *identity.User, error) {
				return "token-123", user, nil
			},
		}
		slotHeld := make(chan struct{})
		releaseSlot := make(chan struct{})
		defer close(releaseSlot)

		mailer := identity.Mailer{
			PasswordReset: func(_ context.Context, _ identity.PasswordResetMail) error {
				close(slotHeld)
				<-releaseSlot
				return nil
			},
		}

		h := identity.RequestPasswordResetHandler(svc, mailer, identity.WithDeliveryConcurrency(1))

		// First request occupies the single delivery slot.
		rec1 := httptest.NewRecorder()
		go h.ServeHTTP(rec1, resetReq("user@example.com"))

		select {
		case <-slotHeld:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for first delivery to hold slot")
		}

		// Second request finds slot full; queue timeout is 0 so it must drop immediately and return 429.
		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, resetReq("user@example.com"))

		assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
		assert.Contains(t, rec2.Body.String(), "service_busy")
	})

	t.Run("bounded wait succeeds when slot becomes available", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestPasswordResetFunc: func(_ context.Context, _ string, email string) (string, *identity.User, error) {
				return "token-123", user, nil
			},
		}
		slot1Held := make(chan struct{})
		releaseSlot1 := make(chan struct{})

		slot2Delivered := make(chan struct{})

		mailer := identity.Mailer{
			PasswordReset: func(_ context.Context, mail identity.PasswordResetMail) error {
				select {
				case <-slot1Held:
					// Second delivery
					close(slot2Delivered)
				default:
					close(slot1Held)
					<-releaseSlot1
				}
				return nil
			},
		}

		h := identity.RequestPasswordResetHandler(svc, mailer,
			identity.WithDeliveryConcurrency(1),
			identity.WithDeliveryQueueTimeout(200*time.Millisecond),
		)

		// First request takes slot 1.
		go h.ServeHTTP(httptest.NewRecorder(), resetReq("user@example.com"))

		select {
		case <-slot1Held:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for slot 1")
		}

		// Release slot 1 after 20ms while second request is waiting.
		go func() {
			time.Sleep(20 * time.Millisecond)
			close(releaseSlot1)
		}()

		// Second request should wait, acquire slot when released, and succeed with 204.
		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, resetReq("user@example.com"))

		assert.Equal(t, http.StatusNoContent, rec2.Code)
		select {
		case <-slot2Delivered:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for slot 2 delivery")
		}
	})

	t.Run("bounded wait times out and returns 429 service_busy", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestPasswordResetFunc: func(_ context.Context, _ string, email string) (string, *identity.User, error) {
				return "token-123", user, nil
			},
		}
		slotHeld := make(chan struct{})
		releaseSlot := make(chan struct{})
		defer close(releaseSlot)

		mailer := identity.Mailer{
			PasswordReset: func(_ context.Context, _ identity.PasswordResetMail) error {
				close(slotHeld)
				<-releaseSlot
				return nil
			},
		}

		h := identity.RequestPasswordResetHandler(svc, mailer,
			identity.WithDeliveryConcurrency(1),
			identity.WithDeliveryQueueTimeout(40*time.Millisecond),
		)

		go h.ServeHTTP(httptest.NewRecorder(), resetReq("user@example.com"))

		select {
		case <-slotHeld:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for slot to be held")
		}

		start := time.Now()
		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, resetReq("user@example.com"))
		elapsed := time.Since(start)

		assert.GreaterOrEqual(t, elapsed, 30*time.Millisecond, "should wait up to delivery queue timeout")
		assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
		assert.Contains(t, rec2.Body.String(), "service_busy")
	})

	t.Run("uniform handling for non-existent account on delivery queue saturation", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestPasswordResetFunc: func(_ context.Context, _ string, email string) (string, *identity.User, error) {
				if email == "user@example.com" {
					return "token-123", user, nil
				}
				return "", nil, nil
			},
		}
		slotHeld := make(chan struct{})
		releaseSlot := make(chan struct{})
		defer close(releaseSlot)

		mailer := identity.Mailer{
			PasswordReset: func(_ context.Context, _ identity.PasswordResetMail) error {
				close(slotHeld)
				<-releaseSlot
				return nil
			},
		}

		h := identity.RequestPasswordResetHandler(svc, mailer, identity.WithDeliveryConcurrency(1))

		go h.ServeHTTP(httptest.NewRecorder(), resetReq("user@example.com"))

		select {
		case <-slotHeld:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for slot to be held")
		}

		// Request for non-existent account must also return 429 to avoid enumeration oracle.
		recUnknown := httptest.NewRecorder()
		h.ServeHTTP(recUnknown, resetReq("nonexistent@example.com"))

		assert.Equal(t, http.StatusTooManyRequests, recUnknown.Code)
		assert.Contains(t, recUnknown.Body.String(), "service_busy")
	})
}
