package identity_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// interimAwareVerifier maps the bearer token to claims so a request can be placed in a positively
// interim (pre-second-factor) context, exactly as tokens.ContextMiddleware records it (F-COMP-001
// identity side).
func interimAwareVerifier() tokens.Verifier[struct{}] {
	return &issuertest.MockVerifier[struct{}]{
		VerifyAccessTokenForTenantFunc: func(_ context.Context, _ string, token string) (*tokens.Claims[struct{}], error) {
			switch token {
			case "interim-token":
				return &tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7()), Interim: true}, nil
			case "full-token":
				return &tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7()), Interim: false}, nil
			default:
				return nil, tokens.ErrInvalidToken
			}
		},
	}
}

// TestEnrollmentHandlersDenyInterimByDefault pins the identity side of F-COMP-001: starting a
// recovery-channel/phone enrollment or an email change is credential management, so an interim
// (pre-MFA) access-token context must be refused by default. The default gate is
// tokens.DenyInterim, which denies only when an interim context is positively present: token-less
// (session-based) applications and fully-elevated sessions keep working.
func TestEnrollmentHandlersDenyInterimByDefault(t *testing.T) {
	user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "enroll@example.com"}
	withUser := identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true })

	cases := []struct {
		name  string
		build func(svc identity.Service, opts ...identity.HandlerOption) http.HandlerFunc
		opts  []identity.HandlerOption
		form  url.Values
		count func(*servicetest.MockService, *int)
	}{
		{
			name: "RequestRecoveryEmail",
			build: func(svc identity.Service, opts ...identity.HandlerOption) http.HandlerFunc {
				return identity.RequestRecoveryEmailHandler(svc, identity.Mailer{}, opts...)
			},
			opts: []identity.HandlerOption{withUser},
			form: url.Values{"recovery_email": {"recovery@elsewhere.example"}},
			count: func(svc *servicetest.MockService, calls *int) {
				svc.RequestRecoveryEmailFunc = func(context.Context, string, uuid.UUID, string) (string, error) {
					*calls++
					return "sel.ver", nil
				}
			},
		},
		{
			name: "RequestEmailChange",
			build: func(svc identity.Service, opts ...identity.HandlerOption) http.HandlerFunc {
				return identity.RequestEmailChangeHandler(svc, identity.Mailer{}, opts...)
			},
			opts: []identity.HandlerOption{withUser},
			form: url.Values{"new_email": {"new@example.com"}},
			count: func(svc *servicetest.MockService, calls *int) {
				svc.RequestEmailChangeFunc = func(context.Context, string, uuid.UUID, string) (string, error) {
					*calls++
					return "sel.ver", nil
				}
			},
		},
		{
			name: "RequestPhoneVerification",
			build: func(svc identity.Service, opts ...identity.HandlerOption) http.HandlerFunc {
				return identity.RequestPhoneVerificationHandler(svc, identity.SMSSender{}, opts...)
			},
			opts: []identity.HandlerOption{withUser},
			form: url.Values{"phone": {"+15550001111"}},
			count: func(svc *servicetest.MockService, calls *int) {
				svc.RequestPhoneVerificationFunc = func(context.Context, string, uuid.UUID, string) (string, error) {
					*calls++
					return "sel.ver", nil
				}
			},
		},
		{
			name: "ConfirmRecoveryEmail",
			build: func(svc identity.Service, opts ...identity.HandlerOption) http.HandlerFunc {
				return identity.ConfirmRecoveryEmailHandler(svc, opts...)
			},
			form: url.Values{"token": {"sel.ver"}},
			count: func(svc *servicetest.MockService, calls *int) {
				svc.ConfirmRecoveryEmailFunc = func(context.Context, string, string) (*identity.User, error) {
					*calls++
					return user, nil
				}
			},
		},
		{
			name: "ConfirmEmailChange",
			build: func(svc identity.Service, opts ...identity.HandlerOption) http.HandlerFunc {
				return identity.ConfirmEmailChangeHandler(svc, opts...)
			},
			form: url.Values{"token": {"sel.ver"}},
			count: func(svc *servicetest.MockService, calls *int) {
				svc.ConfirmEmailChangeFunc = func(context.Context, string, string) (*identity.User, error) {
					*calls++
					return user, nil
				}
			},
		},
		{
			name: "ConfirmPhoneVerification",
			build: func(svc identity.Service, opts ...identity.HandlerOption) http.HandlerFunc {
				return identity.ConfirmPhoneVerificationHandler(svc, opts...)
			},
			form: url.Values{"token": {"sel.ver"}},
			count: func(svc *servicetest.MockService, calls *int) {
				svc.ConfirmPhoneVerificationFunc = func(context.Context, string, string) (*identity.User, error) {
					*calls++
					return user, nil
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			call := func(t *testing.T, svc *servicetest.MockService, bearer string, throughMiddleware bool) *httptest.ResponseRecorder {
				t.Helper()
				calls := 0
				tc.count(svc, &calls)
				next := tc.build(svc, tc.opts...)
				rec := httptest.NewRecorder()
				req := postForm(tc.form)
				var h http.Handler = next
				if throughMiddleware {
					req.Header.Set("Authorization", "Bearer "+bearer)
					h = tokens.ContextMiddleware[struct{}](interimAwareVerifier(), next)
				}
				h.ServeHTTP(rec, req)
				assert.Equal(t, 1, calls, "the service must have been called exactly once")
				return rec
			}

			t.Run("interim context is refused", func(t *testing.T) {
				svc := &servicetest.MockService{}
				calls := 0
				tc.count(svc, &calls)
				next := tc.build(svc, tc.opts...)
				req := postForm(tc.form)
				req.Header.Set("Authorization", "Bearer interim-token")
				rec := httptest.NewRecorder()
				tokens.ContextMiddleware[struct{}](interimAwareVerifier(), next).ServeHTTP(rec, req)
				require.Equal(t, http.StatusForbidden, rec.Code)
				assert.Contains(t, rec.Body.String(), "assurance_required")
				assert.Zero(t, calls, "an interim session must not reach the enrollment service")
			})

			t.Run("fully elevated context proceeds", func(t *testing.T) {
				rec := call(t, &servicetest.MockService{}, "full-token", true)
				assert.Equal(t, http.StatusNoContent, rec.Code)
			})

			t.Run("token-less session context proceeds", func(t *testing.T) {
				rec := call(t, &servicetest.MockService{}, "", false)
				assert.Equal(t, http.StatusNoContent, rec.Code)
			})
		})
	}
}

// TestEnrollmentHandlersAssuranceOptions pins the two overrides: a custom gate is authoritative,
// and WithInsecureNoAssuranceCheck is the explicit opt-out that restores pre-gate behavior.
func TestEnrollmentHandlersAssuranceOptions(t *testing.T) {
	user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "enroll@example.com"}
	withUser := identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true })

	t.Run("custom gate denies a context without any token", func(t *testing.T) {
		svc := &servicetest.MockService{}
		next := identity.RequestEmailChangeHandler(svc, identity.Mailer{},
			withUser,
			identity.WithCredentialAssurance(func(*http.Request) error { return errors.New("step-up required") }))
		rec := httptest.NewRecorder()
		next(rec, postForm(url.Values{"new_email": {"new@example.com"}}))
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "assurance_required")
	})

	t.Run("insecure opt-out lets an interim context through", func(t *testing.T) {
		user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "enroll@example.com"}
		svc := &servicetest.MockService{
			RequestEmailChangeFunc: func(context.Context, string, uuid.UUID, string) (string, error) {
				return "sel.ver", nil
			},
		}
		next := identity.RequestEmailChangeHandler(svc, identity.Mailer{},
			identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true }),
			identity.WithInsecureNoAssuranceCheck())
		req := postForm(url.Values{"new_email": {"new@example.com"}})
		req.Header.Set("Authorization", "Bearer interim-token")
		rec := httptest.NewRecorder()
		tokens.ContextMiddleware[struct{}](interimAwareVerifier(), next).ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Code,
			"the explicit opt-out must restore the pre-gate behavior")
	})
}
