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

	"github.com/JLugagne/libauth/identity"
	"github.com/JLugagne/libauth/identity/servicetest"
	"github.com/JLugagne/libauth/passwords"
	"github.com/JLugagne/libauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type deliveredMail struct {
	user     *identity.User
	newEmail string // only set for change-email deliveries (the new target address)
	token    string
}

// mockMailer captures deliveries over buffered channels so tests stay race-free even though
// delivery is dispatched on a background goroutine.
type mockMailer struct {
	resetCh  chan deliveredMail
	verifyCh chan deliveredMail
	magicCh  chan deliveredMail
	changeCh chan deliveredMail
}

func newMockMailer() *mockMailer {
	return &mockMailer{
		resetCh:  make(chan deliveredMail, 1),
		verifyCh: make(chan deliveredMail, 1),
		magicCh:  make(chan deliveredMail, 1),
		changeCh: make(chan deliveredMail, 1),
	}
}

func (m *mockMailer) SendPasswordReset(_ context.Context, user *identity.User, token string) error {
	m.resetCh <- deliveredMail{user: user, token: token}
	return nil
}

func (m *mockMailer) SendEmailVerification(_ context.Context, user *identity.User, token string) error {
	m.verifyCh <- deliveredMail{user: user, token: token}
	return nil
}

func (m *mockMailer) SendMagicLink(_ context.Context, user *identity.User, token string) error {
	m.magicCh <- deliveredMail{user: user, token: token}
	return nil
}

func (m *mockMailer) SendEmailChange(_ context.Context, user *identity.User, newEmail, token string) error {
	m.changeCh <- deliveredMail{user: user, newEmail: newEmail, token: token}
	return nil
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
	return req
}

func TestRequestPasswordResetHandler_DeliversAndIsUniform(t *testing.T) {
	user := &identity.User{ID: uuid.New(), Email: "u@example.com"}

	t.Run("known account: mailer receives the token", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestPasswordResetFunc: func(_ context.Context, email string, _ ...identity.Option) (string, *identity.User, error) {
				assert.Equal(t, "u@example.com", email)
				return "sel.ver", user, nil
			},
		}
		mailer := newMockMailer()
		h := identity.RequestPasswordResetHandler(svc, mailer)

		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"email": {"u@example.com"}}))

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "sel.ver", requireMail(t, mailer.resetCh).token)
	})

	t.Run("unknown account: same response, no mail", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestPasswordResetFunc: func(_ context.Context, _ string, _ ...identity.Option) (string, *identity.User, error) {
				return "", nil, nil // service hides non-existence
			},
		}
		mailer := newMockMailer()
		h := identity.RequestPasswordResetHandler(svc, mailer)

		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"email": {"ghost@example.com"}}))

		assert.Equal(t, http.StatusNoContent, rec.Code, "must be indistinguishable from the known-account case")
		requireNoMail(t, mailer.resetCh)
	})

	t.Run("backend error: still uniform success, no enumeration via status", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestPasswordResetFunc: func(_ context.Context, _ string, _ ...identity.Option) (string, *identity.User, error) {
				return "", nil, errors.New("database is down")
			},
		}
		mailer := newMockMailer()
		h := identity.RequestPasswordResetHandler(svc, mailer)

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
				ResetPasswordFunc: func(_ context.Context, token, pw string, _ ...identity.Option) error {
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
			VerifyEmailFunc: func(_ context.Context, token string, _ ...identity.Option) (*identity.User, error) {
				assert.Equal(t, "sel.ver", token)
				return &identity.User{ID: uuid.New()}, nil
			},
		}
		h := identity.VerifyEmailHandler(svc)
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"token": {"sel.ver"}}))
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})
}

func TestRequestMagicLinkHandler(t *testing.T) {
	user := &identity.User{ID: uuid.New(), Email: "ml@example.com"}

	t.Run("known account: mailer receives the link token", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestMagicLinkFunc: func(_ context.Context, email string, _ ...identity.Option) (string, *identity.User, error) {
				assert.Equal(t, "ml@example.com", email)
				return "sel.ver", user, nil
			},
		}
		mailer := newMockMailer()
		rec := httptest.NewRecorder()
		identity.RequestMagicLinkHandler(svc, mailer)(rec, postForm(url.Values{"email": {"ml@example.com"}}))
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "sel.ver", requireMail(t, mailer.magicCh).token)
	})

	t.Run("unknown account: uniform, no mail", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestMagicLinkFunc: func(_ context.Context, _ string, _ ...identity.Option) (string, *identity.User, error) {
				return "", nil, nil
			},
		}
		mailer := newMockMailer()
		rec := httptest.NewRecorder()
		identity.RequestMagicLinkHandler(svc, mailer)(rec, postForm(url.Values{"email": {"ghost@example.com"}}))
		assert.Equal(t, http.StatusNoContent, rec.Code)
		requireNoMail(t, mailer.magicCh)
	})
}

func TestMagicLinkLoginHandler(t *testing.T) {
	t.Run("success issues auth cookies", func(t *testing.T) {
		uid := uuid.New()
		svc := &servicetest.MockService{
			LoginWithMagicLinkFunc: func(_ context.Context, token string, _ ...identity.Option) (*identity.User, error) {
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
			LoginWithMagicLinkFunc: func(_ context.Context, _ string, _ ...identity.Option) (*identity.User, error) {
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
	user := &identity.User{ID: uuid.New(), Email: "u@example.com"}

	t.Run("no resolver -> 401", func(t *testing.T) {
		h := identity.RequestEmailVerificationHandler(&servicetest.MockService{}, newMockMailer())
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{}))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("resolved user -> mail sent", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestEmailVerificationFunc: func(_ context.Context, userID uuid.UUID, _ ...identity.Option) (string, error) {
				assert.Equal(t, user.ID, userID)
				return "sel.ver", nil
			},
		}
		mailer := newMockMailer()
		h := identity.RequestEmailVerificationHandler(svc, mailer,
			identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true }))
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{}))
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "sel.ver", requireMail(t, mailer.verifyCh).token)
	})
}
