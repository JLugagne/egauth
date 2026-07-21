package identity_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type deliveredMail struct {
	user     *identity.User
	newEmail string // set for change-email (new address) and recovery-email (recovery address)
	token    string
}

// mockMailer captures deliveries over buffered channels so tests stay race-free even though
// delivery is dispatched on a background goroutine.
type mockMailer struct {
	resetCh    chan deliveredMail
	verifyCh   chan deliveredMail
	magicCh    chan deliveredMail
	changeCh   chan deliveredMail
	recoveryCh chan deliveredMail
}

func newMockMailer() *mockMailer {
	return &mockMailer{
		resetCh:    make(chan deliveredMail, 1),
		verifyCh:   make(chan deliveredMail, 1),
		magicCh:    make(chan deliveredMail, 1),
		changeCh:   make(chan deliveredMail, 1),
		recoveryCh: make(chan deliveredMail, 1),
	}
}

func (m *mockMailer) asMailer() identity.Mailer {
	return identity.Mailer{
		PasswordReset: func(_ context.Context, mail identity.PasswordResetMail) error {
			m.resetCh <- deliveredMail{user: mail.User, token: mail.Token}
			return nil
		},
		EmailVerification: func(_ context.Context, mail identity.EmailVerificationMail) error {
			m.verifyCh <- deliveredMail{user: mail.User, token: mail.Token}
			return nil
		},
		MagicLink: func(_ context.Context, mail identity.MagicLinkMail) error {
			m.magicCh <- deliveredMail{user: mail.User, token: mail.Token}
			return nil
		},
		EmailChange: func(_ context.Context, mail identity.EmailChangeMail) error {
			m.changeCh <- deliveredMail{user: mail.User, newEmail: mail.NewEmail, token: mail.Token}
			return nil
		},
		RecoveryEmailVerification: func(_ context.Context, mail identity.RecoveryEmailMail) error {
			m.recoveryCh <- deliveredMail{user: mail.User, newEmail: mail.RecoveryEmail, token: mail.Token}
			return nil
		},
	}
}

func requireMail(t *testing.T, ch chan deliveredMail) deliveredMail {
	t.Helper()
	select {
	case d := <-ch:
		return d
	case <-time.After(2 * time.Second):
		t.Fatal("expected a mail delivery but none arrived")
		return deliveredMail{}
	}
}

func requireNoMail(t *testing.T, ch chan deliveredMail) {
	t.Helper()
	select {
	case <-ch:
		t.Fatal("a mail was delivered but none was expected")
	case <-time.After(100 * time.Millisecond):
	}
}

func postForm(values url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Stamp a same-origin Origin so the now-strict-by-default CSRF check passes; these tests
	// exercise handler business logic, not the origin path (httptest.NewRequest sets Host to
	// "example.com"). CSRF behavior itself is covered by the dedicated *CSRF* tests.
	req.Header.Set("Origin", "https://"+req.Host)
	return req
}

func TestRequestPasswordResetHandler_DeliversAndIsUniform(t *testing.T) {
	user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}

	t.Run("known account: mailer receives the token", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestPasswordResetFunc: func(_ context.Context, _ string, email string) (string, *identity.User, error) {
				assert.Equal(t, "u@example.com", email)
				return "sel.ver", user, nil
			},
		}
		mailer := newMockMailer()
		h := identity.RequestPasswordResetHandler(svc, mailer.asMailer())

		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"email": {"u@example.com"}}))

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "sel.ver", requireMail(t, mailer.resetCh).token)
	})

	t.Run("unknown account: same response, no mail", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestPasswordResetFunc: func(_ context.Context, _ string, _ string) (string, *identity.User, error) {
				return "", nil, nil // service hides non-existence
			},
		}
		mailer := newMockMailer()
		h := identity.RequestPasswordResetHandler(svc, mailer.asMailer())

		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"email": {"ghost@example.com"}}))

		assert.Equal(t, http.StatusNoContent, rec.Code, "must be indistinguishable from the known-account case")
		requireNoMail(t, mailer.resetCh)
	})

	t.Run("backend error: still uniform success, no enumeration via status", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestPasswordResetFunc: func(_ context.Context, _ string, _ string) (string, *identity.User, error) {
				return "", nil, errors.New("database is down")
			},
		}
		mailer := newMockMailer()
		h := identity.RequestPasswordResetHandler(svc, mailer.asMailer())

		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"email": {"u@example.com"}}))

		// A backend failure must NOT surface as a distinct 500 (that would be reachable only
		// for existing accounts and so leak existence).
		assert.Equal(t, http.StatusNoContent, rec.Code)
		requireNoMail(t, mailer.resetCh)
	})
}

func TestResetPasswordHandler_ErrorMapping(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"success", nil, http.StatusNoContent},
		{"expired", identity.ErrVerificationTokenExpired, http.StatusGone},
		{"invalid", identity.ErrVerificationTokenNotFound, http.StatusBadRequest},
		{"weak password -> 400", passwords.ErrPasswordTooShort, http.StatusBadRequest},
		{"transient backend error -> 500", errors.New("connection reset"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &servicetest.MockService{
				ResetPasswordFunc: func(_ context.Context, _ string, token, pw string) error {
					assert.Equal(t, "sel.ver", token)
					assert.Equal(t, "NewPassw0rd!", pw)
					return tc.err
				},
			}
			h := identity.ResetPasswordHandler(svc)
			rec := httptest.NewRecorder()
			h(rec, postForm(url.Values{"token": {"sel.ver"}, "password": {"NewPassw0rd!"}}))
			assert.Equal(t, tc.wantCode, rec.Code)
		})
	}
}

func TestVerifyEmailHandler(t *testing.T) {
	t.Run("rejects GET", func(t *testing.T) {
		h := identity.VerifyEmailHandler(&servicetest.MockService{})
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("success", func(t *testing.T) {
		svc := &servicetest.MockService{
			VerifyEmailFunc: func(_ context.Context, _ string, token string) (*identity.User, error) {
				assert.Equal(t, "sel.ver", token)
				return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
			},
		}
		h := identity.VerifyEmailHandler(svc)
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"token": {"sel.ver"}}))
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})
}

func TestRequestMagicLinkHandler(t *testing.T) {
	user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "ml@example.com"}

	t.Run("known account: mailer receives the link token", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestMagicLinkFunc: func(_ context.Context, _ string, email string) (string, *identity.User, error) {
				assert.Equal(t, "ml@example.com", email)
				return "sel.ver", user, nil
			},
		}
		mailer := newMockMailer()
		rec := httptest.NewRecorder()
		identity.RequestMagicLinkHandler(svc, mailer.asMailer())(rec, postForm(url.Values{"email": {"ml@example.com"}}))
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "sel.ver", requireMail(t, mailer.magicCh).token)
	})

	t.Run("unknown account: uniform, no mail", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestMagicLinkFunc: func(_ context.Context, _ string, _ string) (string, *identity.User, error) {
				return "", nil, nil
			},
		}
		mailer := newMockMailer()
		rec := httptest.NewRecorder()
		identity.RequestMagicLinkHandler(svc, mailer.asMailer())(rec, postForm(url.Values{"email": {"ghost@example.com"}}))
		assert.Equal(t, http.StatusNoContent, rec.Code)
		requireNoMail(t, mailer.magicCh)
	})
}

func TestMagicLinkLoginHandler(t *testing.T) {
	t.Run("success issues auth cookies", func(t *testing.T) {
		uid := uuid.Must(uuid.NewV7())
		svc := &servicetest.MockService{
			LoginWithMagicLinkFunc: func(_ context.Context, _ string, token string, _ ...event.RequestContext) (*identity.User, error) {
				assert.Equal(t, "sel.ver", token)
				return &identity.User{ID: uid}, nil
			},
		}
		h := identity.MagicLinkLoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder())
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"token": {"sel.ver"}}))

		require.Equal(t, http.StatusNoContent, rec.Code)
		require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName))
		require.NotNil(t, cookieByName(rec, tokens.DefaultRefreshCookieName))
	})

	t.Run("invalid token is mapped", func(t *testing.T) {
		svc := &servicetest.MockService{
			LoginWithMagicLinkFunc: func(_ context.Context, _ string, _ string, _ ...event.RequestContext) (*identity.User, error) {
				return nil, identity.ErrVerificationTokenNotFound
			},
		}
		h := identity.MagicLinkLoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder())
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"token": {"bad"}}))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestRequestEmailVerificationHandler_RequiresResolvedUser(t *testing.T) {
	user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}

	t.Run("no resolver -> 401", func(t *testing.T) {
		h := identity.RequestEmailVerificationHandler(&servicetest.MockService{}, newMockMailer().asMailer())
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{}))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("resolved user -> mail sent", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestEmailVerificationFunc: func(_ context.Context, _ string, userID uuid.UUID) (string, error) {
				assert.Equal(t, user.ID, userID)
				return "sel.ver", nil
			},
		}
		mailer := newMockMailer()
		h := identity.RequestEmailVerificationHandler(svc, mailer.asMailer(),
			identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true }))
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{}))
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "sel.ver", requireMail(t, mailer.verifyCh).token)
	})
}

// crossOriginForm builds a POST whose Origin does not match the request Host, exercising the
// strict-same-origin CSRF check that every state-changing identity handler applies by default.
func crossOriginForm(values url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example.com") // Host is example.com
	return req
}

// TestEmailVerificationHandlers_CSRFBlocksCrossOriginByDefault is a regression test: the two
// email-verification handlers must apply the same strict same-origin check as their siblings
// (SECURITY.md lists "phone/email verification" as protected by default). Before the fix both
// handlers omitted the origin gate and processed a cross-origin POST.
func TestEmailVerificationHandlers_CSRFBlocksCrossOriginByDefault(t *testing.T) {
	t.Run("VerifyEmailHandler rejects cross-origin", func(t *testing.T) {
		called := false
		svc := &servicetest.MockService{
			VerifyEmailFunc: func(_ context.Context, _ string, _ string) (*identity.User, error) {
				called = true
				return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
			},
		}
		h := identity.VerifyEmailHandler(svc)
		rec := httptest.NewRecorder()
		h(rec, crossOriginForm(url.Values{"token": {"sel.ver"}}))
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "cross_site_blocked")
		assert.False(t, called, "service must not be reached on a cross-origin request")
	})

	t.Run("RequestEmailVerificationHandler rejects cross-origin", func(t *testing.T) {
		user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}
		called := false
		svc := &servicetest.MockService{
			RequestEmailVerificationFunc: func(_ context.Context, _ string, _ uuid.UUID) (string, error) {
				called = true
				return "sel.ver", nil
			},
		}
		mailer := newMockMailer()
		h := identity.RequestEmailVerificationHandler(svc, mailer.asMailer(),
			identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true }))
		rec := httptest.NewRecorder()
		h(rec, crossOriginForm(url.Values{}))
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "cross_site_blocked")
		assert.False(t, called, "service must not be reached on a cross-origin request")
		requireNoMail(t, mailer.verifyCh)
	})
}
