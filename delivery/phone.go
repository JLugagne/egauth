package delivery

import (
	"context"
	"errors"
	"fmt"

	"github.com/JLugagne/egauth/identity"
)

// PhoneMessageFunc renders the SMS body carrying a phone-verification token. link is the action
// link built from the configured LinkBuilder (empty when none is configured), so a renderer can
// embed either the link or the raw token. Keep the body short — it is an SMS.
type PhoneMessageFunc func(token, link string) Message

// DefaultPhoneMessage renders a short, SMS-appropriate verification message. It uses the link when
// one is available (a configured LinkBuilder produced it), otherwise the bare token as a code.
func DefaultPhoneMessage(token, link string) Message {
	body := link
	if body == "" {
		body = token
	}
	return Message{Text: fmt.Sprintf("Your verification code is %s. Do not share it with anyone.", body)}
}

// PhoneVerifier adapts an SMS Sender to identity.SMSSender, so the identity phone-verification
// handlers can deliver a token over SMS. egauth ships no SMS Sender (every provider is a paid
// vendor SDK); the adopter supplies one implementing the one-method Sender seam (Twilio, SNS, …)
// and wraps it here. Phone verification is a lower-assurance contact-channel flow — NIST SP
// 800-63B excludes SMS as an authentication factor, and the mfa module still does not accept it.
type PhoneVerifier struct {
	sender  Sender
	render  PhoneMessageFunc
	linkFor func(token string) string
}

// PhoneOption configures a PhoneVerifier.
type PhoneOption func(*PhoneVerifier)

// WithPhoneMessage overrides how the verification SMS body is rendered (default
// DefaultPhoneMessage).
func WithPhoneMessage(f PhoneMessageFunc) PhoneOption {
	return func(p *PhoneVerifier) { p.render = f }
}

// WithPhoneLink configures an action-link template: the token is appended to base (e.g.
// "https://app.example.com/verify-phone?token="), and the resulting link is passed to the message
// renderer. Without it the message carries the bare token as a code.
func WithPhoneLink(base string) PhoneOption {
	return func(p *PhoneVerifier) {
		p.linkFor = func(token string) string { return base + token }
	}
}

// NewPhoneVerifier builds a PhoneVerifier over the given SMS Sender. It returns an error for a nil
// sender so misconfiguration fails fast at construction rather than per request.
func NewPhoneVerifier(sender Sender, opts ...PhoneOption) (*PhoneVerifier, error) {
	if sender == nil {
		return nil, errors.New("delivery: NewPhoneVerifier requires a non-nil SMS Sender")
	}
	p := &PhoneVerifier{sender: sender, render: DefaultPhoneMessage}
	for _, opt := range opts {
		opt(p)
	}
	if p.render == nil {
		p.render = DefaultPhoneMessage
	}
	return p, nil
}

// SendPhoneVerification implements identity.SMSSender: it renders the verification message and
// sends it to the requested number via the wrapped SMS Sender.
func (p *PhoneVerifier) SendPhoneVerification(ctx context.Context, _ *identity.User, phone, token string) error {
	var link string
	if p.linkFor != nil {
		link = p.linkFor(token)
	}
	return p.sender.Send(ctx, phone, p.render(token, link))
}

// Compile-time check that PhoneVerifier satisfies the identity SMS-delivery seam.
var _ identity.SMSSender = (*PhoneVerifier)(nil)
