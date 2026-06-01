package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

type deliveredSMS struct {
	user  *identity.User
	phone string
	token string
}

// mockSMSSender captures phone-verification deliveries over a buffered channel so tests stay
// race-free even though delivery is dispatched on a background goroutine.
type mockSMSSender struct {
	ch chan deliveredSMS
}

func newMockSMSSender() *mockSMSSender {
	return &mockSMSSender{ch: make(chan deliveredSMS, 1)}
}

func (m *mockSMSSender) SendPhoneVerification(_ context.Context, user *identity.User, phone, token string) error {
	m.ch <- deliveredSMS{user: user, phone: phone, token: token}
	return nil
}

func requireSMS(t *testing.T, ch chan deliveredSMS) deliveredSMS {
	t.Helper()
	select {
	case d := <-ch:
		return d
	case <-time.After(2 * time.Second):
		t.Fatal("expected an SMS delivery but none arrived")
		return deliveredSMS{}
	}
}

func requireNoSMS(t *testing.T, ch chan deliveredSMS) {
	t.Helper()
	select {
	case <-ch:
		t.Fatal("an SMS was delivered but none was expected")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestRequestPhoneVerificationHandler_RequiresResolvedUser(t *testing.T) {
	t.Run("no resolver -> 401", func(t *testing.T) {
		h := identity.RequestPhoneVerificationHandler(&servicetest.MockService{}, newMockSMSSender())
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"phone": {"+15551234567"}}))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("resolved user -> token delivered by SMS to the number", func(t *testing.T) {
		user := &identity.User{ID: uuid.New(), Email: "u@example.com"}
		svc := &servicetest.MockService{
			RequestPhoneVerificationFunc: func(_ context.Context, _ string, userID uuid.UUID, phone string) (string, error) {
				assert.Equal(t, user.ID, userID)
				assert.Equal(t, "+15551234567", phone)
				return "sel.ver", nil
			},
		}
		sender := newMockSMSSender()
		h := identity.RequestPhoneVerificationHandler(svc, sender,
			identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true }))
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"phone": {"+15551234567"}}))

		assert.Equal(t, http.StatusNoContent, rec.Code)
		d := requireSMS(t, sender.ch)
		assert.Equal(t, "sel.ver", d.token)
		assert.Equal(t, "+15551234567", d.phone, "the token must be delivered to the requested number")
	})

	t.Run("number normalized before delivery", func(t *testing.T) {
		user := &identity.User{ID: uuid.New(), Email: "u@example.com"}
		svc := &servicetest.MockService{
			RequestPhoneVerificationFunc: func(_ context.Context, _ string, _ uuid.UUID, _ string) (string, error) {
				return "sel.ver", nil
			},
		}
		sender := newMockSMSSender()
		h := identity.RequestPhoneVerificationHandler(svc, sender,
			identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true }))
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"phone": {" +1 (555) 123-4567 "}}))

		assert.Equal(t, http.StatusNoContent, rec.Code)
		d := requireSMS(t, sender.ch)
		assert.Equal(t, "+15551234567", d.phone, "the delivery target must be the normalized E.164 form")
	})
}

func TestRequestPhoneVerificationHandler_RejectsGET(t *testing.T) {
	h := identity.RequestPhoneVerificationHandler(&servicetest.MockService{}, newMockSMSSender())
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestRequestPhoneVerificationHandler_ErrorMapping(t *testing.T) {
	user := &identity.User{ID: uuid.New(), Email: "u@example.com"}
	cases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"invalid phone -> 400", identity.ErrInvalidPhone, http.StatusBadRequest},
		{"already taken -> 409", identity.ErrPhoneAlreadyExists, http.StatusConflict},
		{"deactivated account -> 401", identity.ErrUserNotFound, http.StatusUnauthorized},
		{"transient backend error -> 500", context.DeadlineExceeded, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &servicetest.MockService{
				RequestPhoneVerificationFunc: func(_ context.Context, _ string, _ uuid.UUID, _ string) (string, error) {
					return "", tc.err
				},
			}
			sender := newMockSMSSender()
			h := identity.RequestPhoneVerificationHandler(svc, sender,
				identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true }))
			rec := httptest.NewRecorder()
			h(rec, postForm(url.Values{"phone": {"+15550000000"}}))
			assert.Equal(t, tc.wantCode, rec.Code)
			requireNoSMS(t, sender.ch)
		})
	}
}

func TestConfirmPhoneVerificationHandler(t *testing.T) {
	t.Run("rejects GET", func(t *testing.T) {
		h := identity.ConfirmPhoneVerificationHandler(&servicetest.MockService{})
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("success", func(t *testing.T) {
		phone := "+15551234567"
		svc := &servicetest.MockService{
			ConfirmPhoneVerificationFunc: func(_ context.Context, _ string, token string) (*identity.User, error) {
				assert.Equal(t, "sel.ver", token)
				return &identity.User{ID: uuid.New(), Phone: &phone}, nil
			},
		}
		h := identity.ConfirmPhoneVerificationHandler(svc)
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
			{"claimed in interim -> 409", identity.ErrPhoneAlreadyExists, http.StatusConflict},
			{"deactivated account -> invalid token", identity.ErrUserNotFound, http.StatusBadRequest},
			{"transient backend error -> 500", context.DeadlineExceeded, http.StatusInternalServerError},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				svc := &servicetest.MockService{
					ConfirmPhoneVerificationFunc: func(_ context.Context, _ string, _ string) (*identity.User, error) {
						return nil, tc.err
					},
				}
				h := identity.ConfirmPhoneVerificationHandler(svc)
				rec := httptest.NewRecorder()
				h(rec, postForm(url.Values{"token": {"sel.ver"}}))
				assert.Equal(t, tc.wantCode, rec.Code)
			})
		}
	})
}
