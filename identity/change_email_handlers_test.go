package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestRequestEmailChangeHandler_RequiresResolvedUser(t *testing.T) {
	t.Run("no resolver -> 401", func(t *testing.T) {
		h := identity.RequestEmailChangeHandler(&servicetest.MockService{}, newMockMailer())
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"new_email": {"new@example.com"}}))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("resolved user -> token delivered to the new address", func(t *testing.T) {
		user := &identity.User{ID: uuid.New(), Email: "old@example.com"}
		svc := &servicetest.MockService{
			RequestEmailChangeFunc: func(_ context.Context, _ string, userID uuid.UUID, newEmail string) (string, error) {
				assert.Equal(t, user.ID, userID)
				assert.Equal(t, "new@example.com", newEmail)
				return "sel.ver", nil
			},
		}
		mailer := newMockMailer()
		h := identity.RequestEmailChangeHandler(svc, mailer,
			identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true }))
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"new_email": {"new@example.com"}}))

		assert.Equal(t, http.StatusNoContent, rec.Code)
		d := requireMail(t, mailer.changeCh)
		assert.Equal(t, "sel.ver", d.token)
		assert.Equal(t, "new@example.com", d.newEmail, "the change token must be delivered to the NEW address")
	})
}

func TestRequestEmailChangeHandler_ErrorMapping(t *testing.T) {
	user := &identity.User{ID: uuid.New(), Email: "old@example.com"}
	cases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"invalid new email -> 400", identity.ErrInvalidEmail, http.StatusBadRequest},
		{"already taken -> 409", identity.ErrEmailAlreadyExists, http.StatusConflict},
		{"transient backend error -> 500", context.DeadlineExceeded, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &servicetest.MockService{
				RequestEmailChangeFunc: func(_ context.Context, _ string, _ uuid.UUID, _ string) (string, error) {
					return "", tc.err
				},
			}
			mailer := newMockMailer()
			h := identity.RequestEmailChangeHandler(svc, mailer,
				identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true }))
			rec := httptest.NewRecorder()
			h(rec, postForm(url.Values{"new_email": {"taken@example.com"}}))
			assert.Equal(t, tc.wantCode, rec.Code)
			requireNoMail(t, mailer.changeCh)
		})
	}
}

func TestConfirmEmailChangeHandler(t *testing.T) {
	t.Run("rejects GET", func(t *testing.T) {
		h := identity.ConfirmEmailChangeHandler(&servicetest.MockService{})
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("success", func(t *testing.T) {
		svc := &servicetest.MockService{
			ConfirmEmailChangeFunc: func(_ context.Context, _ string, token string) (*identity.User, error) {
				assert.Equal(t, "sel.ver", token)
				return &identity.User{ID: uuid.New(), Email: "new@example.com"}, nil
			},
		}
		h := identity.ConfirmEmailChangeHandler(svc)
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"token": {"sel.ver"}}))
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("error mapping", func(t *testing.T) {
		cases := []struct {
			name     string
			err      error
			wantCode int
		}{
			{"expired", identity.ErrVerificationTokenExpired, http.StatusGone},
			{"invalid token", identity.ErrVerificationTokenNotFound, http.StatusBadRequest},
			{"claimed in interim -> 409", identity.ErrEmailAlreadyExists, http.StatusConflict},
			{"deactivated account -> invalid token", identity.ErrUserNotFound, http.StatusBadRequest},
			{"transient backend error -> 500", context.DeadlineExceeded, http.StatusInternalServerError},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				svc := &servicetest.MockService{
					ConfirmEmailChangeFunc: func(_ context.Context, _ string, _ string) (*identity.User, error) {
						return nil, tc.err
					},
				}
				h := identity.ConfirmEmailChangeHandler(svc)
				rec := httptest.NewRecorder()
				h(rec, postForm(url.Values{"token": {"sel.ver"}}))
				assert.Equal(t, tc.wantCode, rec.Code)
			})
		}
	})
}
