package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDispatchDelivery_SurvivesPanickingMailer is the bug-confirming test for identity/TEN-7: the
// off-response-path delivery goroutine invoked the consumer's Mailer callback with NO recover(), so
// a panic in consumer code took down the whole process — from a goroutine the request has already
// left, where no http.Server recovery can help. The panic must be contained, surfaced through the
// event sink, and the request itself must still succeed.
func TestDispatchDelivery_SurvivesPanickingMailer(t *testing.T) {
	user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "panic@example.com"}
	svc := &servicetest.MockService{
		RequestPasswordResetFunc: func(_ context.Context, _ string, _ string) (string, *identity.User, error) {
			return "sel.ver", user, nil
		},
	}
	mailer := identity.Mailer{
		PasswordReset: func(_ context.Context, _ identity.PasswordResetMail) error {
			panic("consumer mailer exploded")
		},
	}

	sink := &captureSink{}
	h := identity.RequestPasswordResetHandler(svc, mailer, identity.WithHandlerEventSink(sink))

	body := url.Values{"email": {"panic@example.com"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/reset", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+req.Host)
	rec := httptest.NewRecorder()

	h(rec, req)

	// The request is unaffected: the panic happens off the response path.
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// The recovered panic must be observable, not silently swallowed.
	require.Eventually(t, func() bool { return sink.has(event.DeliveryFailed) },
		2*time.Second, 5*time.Millisecond, "a panicking Mailer must surface a DeliveryFailed event")
	got, ok := sink.last(event.DeliveryFailed)
	require.True(t, ok)
	require.Error(t, got.Err)
	assert.ErrorIs(t, got.Err, identity.ErrDeliveryPanic)
	assert.Contains(t, got.Err.Error(), "consumer mailer exploded")
	assert.Equal(t, "delivery_panic", got.Reason)
}
