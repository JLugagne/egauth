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

func TestRequestRecoveryEmailHandler_RequiresResolvedUser(t *testing.T) {
	t.Run("no resolver -> 401", func(t *testing.T) {
		h := identity.RequestRecoveryEmailHandler(&servicetest.MockService{}, newMockMailer().asMailer())
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"recovery_email": {"rec@elsewhere.example"}}))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("resolved user -> token delivered to the recovery address", func(t *testing.T) {
		user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "primary@example.com"}
		svc := &servicetest.MockService{
			RequestRecoveryEmailFunc: func(_ context.Context, _ string, userID uuid.UUID, rec string) (string, error) {
				assert.Equal(t, user.ID, userID)
				assert.Equal(t, "rec@elsewhere.example", rec)
				return "sel.ver", nil
			},
		}
		mailer := newMockMailer()
		// fullSessionAssurance satisfies the handler's step-up bar (see
		// TestRequestRecoveryEmailHandler_EnforcesStepUp, which pins the bar itself).
		h := identity.RequestRecoveryEmailHandler(svc, mailer.asMailer(),
			identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true }),
			fullSessionAssurance())
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{"recovery_email": {"rec@elsewhere.example"}}))

		assert.Equal(t, http.StatusNoContent, rec.Code)
		d := requireMail(t, mailer.recoveryCh)
		assert.Equal(t, "sel.ver", d.token)
		assert.Equal(t, "rec@elsewhere.example", d.newEmail, "the token must go to the recovery address")
	})
}

func TestRequestRecoveryEmailHandler_ErrorMapping(t *testing.T) {
	user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "primary@example.com"}
	cases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"invalid -> 400", identity.ErrInvalidEmail, http.StatusBadRequest},
		{"is primary -> 409", identity.ErrRecoveryEmailIsPrimary, http.StatusConflict},
		{"deactivated -> 401", identity.ErrUserNotFound, http.StatusUnauthorized},
		{"transient -> 500", context.DeadlineExceeded, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &servicetest.MockService{
				RequestRecoveryEmailFunc: func(_ context.Context, _ string, _ uuid.UUID, _ string) (string, error) {
					return "", tc.err
				},
			}
			mailer := newMockMailer()
			h := identity.RequestRecoveryEmailHandler(svc, mailer.asMailer(),
				identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true }),
				fullSessionAssurance())
			rec := httptest.NewRecorder()
			h(rec, postForm(url.Values{"recovery_email": {"rec@elsewhere.example"}}))
			assert.Equal(t, tc.wantCode, rec.Code)
			requireNoMail(t, mailer.recoveryCh)
		})
	}
}

func TestConfirmRecoveryEmailHandler(t *testing.T) {
	t.Run("rejects GET", func(t *testing.T) {
		h := identity.ConfirmRecoveryEmailHandler(&servicetest.MockService{})
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("success", func(t *testing.T) {
		rec := "rec@elsewhere.example"
		svc := &servicetest.MockService{
			ConfirmRecoveryEmailFunc: func(_ context.Context, _ string, token string) (*identity.User, error) {
				assert.Equal(t, "sel.ver", token)
				return &identity.User{ID: uuid.Must(uuid.NewV7()), RecoveryEmail: &rec}, nil
			},
		}
		h := identity.ConfirmRecoveryEmailHandler(svc)
		w := httptest.NewRecorder()
		h(w, postForm(url.Values{"token": {"sel.ver"}}))
		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("invalid token -> 400", func(t *testing.T) {
		svc := &servicetest.MockService{
			ConfirmRecoveryEmailFunc: func(_ context.Context, _ string, _ string) (*identity.User, error) {
				return nil, identity.ErrVerificationTokenNotFound
			},
		}
		h := identity.ConfirmRecoveryEmailHandler(svc)
		w := httptest.NewRecorder()
		h(w, postForm(url.Values{"token": {"bad"}}))
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestRequestPasswordResetViaRecoveryHandler_UniformAndDelivers(t *testing.T) {
	recEmail := "rec@elsewhere.example"
	phone := "+15553334444"

	t.Run("no channel: uniform 204, no delivery", func(t *testing.T) {
		svc := &servicetest.MockService{
			RequestPasswordResetViaRecoveryFunc: func(_ context.Context, _ string, _ string) (string, *identity.User, identity.RecoveryChannels, error) {
				return "", nil, identity.RecoveryChannels{}, nil
			},
		}
		mailer := newMockMailer()
		sms := newMockSMSSender()
		h := identity.RequestPasswordResetViaRecoveryHandler(svc, mailer.asMailer(), sms.asSMSSender())
		w := httptest.NewRecorder()
		h(w, postForm(url.Values{"email": {"primary@example.com"}}))
		assert.Equal(t, http.StatusNoContent, w.Code)
		requireNoMail(t, mailer.recoveryCh)
		requireNoMail(t, mailer.resetCh)
		requireNoSMS(t, sms.ch)
	})

	t.Run("recovery email channel: delivers reset to the recovery address", func(t *testing.T) {
		user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "primary@example.com", RecoveryEmail: &recEmail}
		svc := &servicetest.MockService{
			RequestPasswordResetViaRecoveryFunc: func(_ context.Context, _ string, _ string) (string, *identity.User, identity.RecoveryChannels, error) {
				return "sel.ver", user, identity.RecoveryChannels{RecoveryEmail: true}, nil
			},
		}
		mailer := newMockMailer()
		sms := newMockSMSSender()
		h := identity.RequestPasswordResetViaRecoveryHandler(svc, mailer.asMailer(), sms.asSMSSender())
		w := httptest.NewRecorder()
		h(w, postForm(url.Values{"email": {"primary@example.com"}}))
		assert.Equal(t, http.StatusNoContent, w.Code)

		d := requireMail(t, mailer.resetCh)
		assert.Equal(t, "sel.ver", d.token)
		assert.Equal(t, recEmail, d.user.Email, "the reset is delivered to the RECOVERY address, not the primary")
		requireNoSMS(t, sms.ch)
	})

	t.Run("phone channel: delivers reset by SMS", func(t *testing.T) {
		user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "primary@example.com", Phone: &phone}
		svc := &servicetest.MockService{
			RequestPasswordResetViaRecoveryFunc: func(_ context.Context, _ string, _ string) (string, *identity.User, identity.RecoveryChannels, error) {
				return "sel.ver", user, identity.RecoveryChannels{Phone: true}, nil
			},
		}
		mailer := newMockMailer()
		sms := newMockSMSSender()
		h := identity.RequestPasswordResetViaRecoveryHandler(svc, mailer.asMailer(), sms.asSMSSender())
		w := httptest.NewRecorder()
		h(w, postForm(url.Values{"email": {"primary@example.com"}}))
		assert.Equal(t, http.StatusNoContent, w.Code)

		d := requireSMS(t, sms.ch)
		assert.Equal(t, "sel.ver", d.token)
		assert.Equal(t, phone, d.phone)
	})

	t.Run("rejects GET", func(t *testing.T) {
		h := identity.RequestPasswordResetViaRecoveryHandler(&servicetest.MockService{}, newMockMailer().asMailer(), newMockSMSSender().asSMSSender())
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// TestRequestPasswordResetViaRecoveryHandler_BackendErrorIsUniform is a regression
// test for the enumeration oracle introduced by surfacing service errors as HTTP 500.
// When the service returns an error (reachable only for existing accounts), the handler
// MUST still reply 204 — not 500 — to preserve the documented enumeration-uniform behaviour.
func TestRequestPasswordResetViaRecoveryHandler_BackendErrorIsUniform(t *testing.T) {
	svc := &servicetest.MockService{
		RequestPasswordResetViaRecoveryFunc: func(_ context.Context, _ string, _ string) (string, *identity.User, identity.RecoveryChannels, error) {
			// Simulate a transient backend error reachable only for existing accounts
			// (e.g. FindIdentitiesByUserID or CreateVerificationToken failing).
			return "", nil, identity.RecoveryChannels{}, context.DeadlineExceeded
		},
	}
	mailer := newMockMailer()
	sms := newMockSMSSender()
	h := identity.RequestPasswordResetViaRecoveryHandler(svc, mailer.asMailer(), sms.asSMSSender())
	w := httptest.NewRecorder()
	h(w, postForm(url.Values{"email": {"victim@example.com"}}))

	// Must be 204, not 500 — a 500 only reachable for existing accounts is an enumeration oracle.
	assert.Equal(t, http.StatusNoContent, w.Code,
		"backend error must not surface as 500; handler must always reply 204 to be enumeration-uniform")
	requireNoMail(t, mailer.resetCh)
	requireNoSMS(t, sms.ch)
}
