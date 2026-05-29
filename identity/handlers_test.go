package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/libauth/identity"
	"github.com/JLugagne/libauth/identity/servicetest"
	"github.com/JLugagne/libauth/passwords"
	"github.com/JLugagne/libauth/tokens"
	"github.com/JLugagne/libauth/tokens/issuertest"
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
	uid := uuid.New()
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, provider, providerID, password string, opts ...identity.Option) (*identity.User, error) {
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
		AuthenticateFunc: func(ctx context.Context, provider, providerID, password string, opts ...identity.Option) (*identity.User, error) {
			return &identity.User{ID: uuid.New()}, nil
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
	return req
}

func TestChangePasswordHandler(t *testing.T) {
	uid := uuid.New()
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
			ChangePasswordFunc: func(ctx context.Context, userID uuid.UUID, current, newPassword string, opts ...identity.Option) error {
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
			ChangePasswordFunc: func(ctx context.Context, userID uuid.UUID, current, newPassword string, opts ...identity.Option) error {
				return passwords.ErrPasswordTooShort
			},
		}
		rec := httptest.NewRecorder()
		identity.ChangePasswordHandler(svc, withUser).ServeHTTP(rec, changePwForm(t, "old", "x"))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "password_rejected")
	})

	t.Run("success returns 204 and passes the fields through", func(t *testing.T) {
		called := false
		svc := &servicetest.MockService{
			ChangePasswordFunc: func(ctx context.Context, userID uuid.UUID, current, newPassword string, opts ...identity.Option) error {
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

func TestLoginHandler_RejectsOversizedBody(t *testing.T) {
	called := false
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, provider, providerID, password string, opts ...identity.Option) (*identity.User, error) {
			called = true
			return &identity.User{ID: uuid.New()}, nil
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
		AuthenticateFunc: func(ctx context.Context, provider, providerID, password string, opts ...identity.Option) (*identity.User, error) {
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
		AuthenticateFunc: func(ctx context.Context, provider, providerID, password string, opts ...identity.Option) (*identity.User, error) {
			return nil, identity.ErrAccountLocked
		},
	}
	h := identity.LoginHandler[struct{}](svc, &issuertest.MockIssuer[struct{}]{}, testClaimsBuilder())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "secret", ""))

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Contains(t, rec.Body.String(), "account_locked")
}

func TestLoginHandler_FailureRedirect(t *testing.T) {
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, provider, providerID, password string, opts ...identity.Option) (*identity.User, error) {
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
		AuthenticateFunc: func(ctx context.Context, provider, providerID, password string, opts ...identity.Option) (*identity.User, error) {
			return &identity.User{ID: uuid.New()}, nil
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
		AuthenticateFunc: func(ctx context.Context, provider, providerID, password string, opts ...identity.Option) (*identity.User, error) {
			o := identity.ApplyOptions(opts)
			if o.TenantID != nil {
				capturedTenant = *o.TenantID
			}
			return &identity.User{ID: uuid.New(), TenantID: capturedTenant}, nil
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
		AuthenticateFunc: func(ctx context.Context, provider, providerID, password string, opts ...identity.Option) (*identity.User, error) {
			return &identity.User{ID: uuid.New()}, nil
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

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "secret", ""))

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRegisterHandler_SuccessAutoLogin(t *testing.T) {
	svc := &servicetest.MockService{
		RegisterFunc: func(ctx context.Context, email, password string, opts ...identity.Option) (*identity.User, error) {
			return &identity.User{ID: uuid.New(), Email: email}, nil
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
		RegisterFunc: func(ctx context.Context, email, password string, opts ...identity.Option) (*identity.User, error) {
			return nil, identity.ErrEmailAlreadyExists
		},
	}
	h := identity.RegisterHandler[struct{}](svc, &issuertest.MockIssuer[struct{}]{}, testClaimsBuilder())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/register", "taken@example.com", "secret", ""))

	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Contains(t, rec.Body.String(), "email_taken")
}
