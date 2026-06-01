package delivery

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPhoneVerifier_RejectsNilSender(t *testing.T) {
	_, err := NewPhoneVerifier(nil)
	require.Error(t, err)
}

func TestPhoneVerifier_SendsTokenAsCode(t *testing.T) {
	spy := &spySender{}
	pv, err := NewPhoneVerifier(spy)
	require.NoError(t, err)

	err = pv.SendPhoneVerification(context.Background(), nil, "+15551234567", "sel.ver")
	require.NoError(t, err)

	assert.Equal(t, 1, spy.calls)
	assert.Equal(t, "+15551234567", spy.recipient, "the SMS must go to the requested number")
	assert.Contains(t, spy.msg.Text, "sel.ver", "without a link the bare token is sent as the code")
}

func TestPhoneVerifier_BuildsLinkWhenConfigured(t *testing.T) {
	spy := &spySender{}
	pv, err := NewPhoneVerifier(spy, WithPhoneLink("https://app.example.com/verify-phone?token="))
	require.NoError(t, err)

	err = pv.SendPhoneVerification(context.Background(), nil, "+15551234567", "sel.ver")
	require.NoError(t, err)

	assert.Contains(t, spy.msg.Text, "https://app.example.com/verify-phone?token=sel.ver",
		"the configured link template must carry the token")
}

func TestPhoneVerifier_CustomMessage(t *testing.T) {
	spy := &spySender{}
	pv, err := NewPhoneVerifier(spy, WithPhoneMessage(func(token, link string) Message {
		return Message{Text: "code:" + token}
	}))
	require.NoError(t, err)

	err = pv.SendPhoneVerification(context.Background(), nil, "+15551234567", "abc123")
	require.NoError(t, err)
	assert.Equal(t, "code:abc123", spy.msg.Text)
}

func TestPhoneVerifier_PropagatesSenderError(t *testing.T) {
	spy := &spySender{err: assertErr}
	pv, err := NewPhoneVerifier(spy)
	require.NoError(t, err)

	err = pv.SendPhoneVerification(context.Background(), nil, "+15551234567", "sel.ver")
	require.ErrorIs(t, err, assertErr)
}

func TestDefaultPhoneMessage_PrefersLink(t *testing.T) {
	withLink := DefaultPhoneMessage("tok", "https://x/verify?token=tok")
	assert.Contains(t, withLink.Text, "https://x/verify?token=tok")
	assert.False(t, strings.HasSuffix(withLink.Text, "tok."), "the bare token must not also be appended")

	noLink := DefaultPhoneMessage("tok", "")
	assert.Contains(t, noLink.Text, "tok")
}

var assertErr = errSentinel("delivery test sentinel")

type errSentinel string

func (e errSentinel) Error() string { return string(e) }
