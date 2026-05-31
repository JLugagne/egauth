package delivery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/otp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spySender records the last delivery for assertions.
type spySender struct {
	recipient string
	msg       Message
	calls     int
	err       error
}

func (s *spySender) Send(_ context.Context, recipient string, msg Message) error {
	s.calls++
	s.recipient = recipient
	s.msg = msg
	return s.err
}

func resolverTo(c Contact) ContactResolver {
	return ContactResolverFunc(func(context.Context, uuid.UUID, string, string) (Contact, error) {
		return c, nil
	})
}

func testChallenge() *otp.Challenge {
	return &otp.Challenge{
		SubjectID: uuid.New(),
		TenantID:  "t1",
		Purpose:   "login",
		Code:      "123456",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
}

func TestOTPDelivery_Validation(t *testing.T) {
	t.Run("resolver required", func(t *testing.T) {
		_, err := OTPDelivery(nil, WithEmailSender(&spySender{}))
		require.Error(t, err)
	})
	t.Run("at least one sender required", func(t *testing.T) {
		_, err := OTPDelivery(resolverTo(Contact{Email: "a@x.com"}))
		require.Error(t, err)
	})
}

func TestOTPDelivery_Email(t *testing.T) {
	email := &spySender{}
	sms := &spySender{}
	deliver, err := OTPDelivery(resolverTo(Contact{Email: "user@x.com"}),
		WithEmailSender(email), WithSMSSender(sms))
	require.NoError(t, err)

	ch := testChallenge()
	require.NoError(t, deliver(context.Background(), ch))
	assert.Equal(t, 1, email.calls)
	assert.Equal(t, 0, sms.calls)
	assert.Equal(t, "user@x.com", email.recipient)
	assert.Contains(t, email.msg.Text, "123456")
}

func TestOTPDelivery_SMS(t *testing.T) {
	email := &spySender{}
	sms := &spySender{}
	deliver, err := OTPDelivery(resolverTo(Contact{Phone: "+15551234567"}),
		WithEmailSender(email), WithSMSSender(sms))
	require.NoError(t, err)

	require.NoError(t, deliver(context.Background(), testChallenge()))
	assert.Equal(t, 0, email.calls)
	assert.Equal(t, 1, sms.calls)
	assert.Equal(t, "+15551234567", sms.recipient)
}

func TestOTPDelivery_PrefersEmailWhenBothPresent(t *testing.T) {
	email := &spySender{}
	sms := &spySender{}
	deliver, err := OTPDelivery(resolverTo(Contact{Email: "user@x.com", Phone: "+15551234567"}),
		WithEmailSender(email), WithSMSSender(sms))
	require.NoError(t, err)

	require.NoError(t, deliver(context.Background(), testChallenge()))
	assert.Equal(t, 1, email.calls)
	assert.Equal(t, 0, sms.calls)
}

func TestOTPDelivery_FallsBackToSMSWhenNoEmailSender(t *testing.T) {
	sms := &spySender{}
	// Contact has an email, but only an SMS sender is wired and the contact also has a phone.
	deliver, err := OTPDelivery(resolverTo(Contact{Email: "user@x.com", Phone: "+15551234567"}),
		WithSMSSender(sms))
	require.NoError(t, err)

	require.NoError(t, deliver(context.Background(), testChallenge()))
	assert.Equal(t, 1, sms.calls)
}

func TestOTPDelivery_NoChannel(t *testing.T) {
	deliver, err := OTPDelivery(resolverTo(Contact{}), WithEmailSender(&spySender{}))
	require.NoError(t, err)
	err = deliver(context.Background(), testChallenge())
	require.Error(t, err)
}

func TestOTPDelivery_ResolverError(t *testing.T) {
	sentinel := errors.New("lookup failed")
	resolver := ContactResolverFunc(func(context.Context, uuid.UUID, string, string) (Contact, error) {
		return Contact{}, sentinel
	})
	deliver, err := OTPDelivery(resolver, WithEmailSender(&spySender{}))
	require.NoError(t, err)
	err = deliver(context.Background(), testChallenge())
	require.ErrorIs(t, err, sentinel)
}

func TestOTPDelivery_SenderErrorPropagates(t *testing.T) {
	sentinel := errors.New("smtp down")
	email := &spySender{err: sentinel}
	deliver, err := OTPDelivery(resolverTo(Contact{Email: "a@x.com"}), WithEmailSender(email))
	require.NoError(t, err)
	require.ErrorIs(t, deliver(context.Background(), testChallenge()), sentinel)
}

func TestOTPDelivery_CustomMessage(t *testing.T) {
	email := &spySender{}
	deliver, err := OTPDelivery(resolverTo(Contact{Email: "a@x.com"}),
		WithEmailSender(email),
		WithOTPMessage(func(ch *otp.Challenge) Message {
			return Message{Subject: "Code", Text: "code:" + ch.Code}
		}))
	require.NoError(t, err)

	require.NoError(t, deliver(context.Background(), testChallenge()))
	assert.Equal(t, "code:123456", email.msg.Text)
}

func TestDefaultOTPMessage(t *testing.T) {
	msg := DefaultOTPMessage(testChallenge())
	assert.Contains(t, msg.Text, "123456")
	assert.NotEmpty(t, msg.Subject)
}
