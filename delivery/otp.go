package delivery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/JLugagne/egauth/otp"
	"github.com/google/uuid"
)

// Sender delivers a rendered Message to a single recipient over one channel. SMTPMailer is the
// built-in email Sender; an SMS Sender is the adopter's to provide by wrapping their provider
// (see the package documentation for the SMS story). recipient is an email address for an email
// Sender and an E.164 phone number for an SMS Sender.
type Sender interface {
	Send(ctx context.Context, recipient string, msg Message) error
}

// Contact is a resolved delivery destination for an OTP code. An otp.Challenge carries only an
// opaque subject UUID; the application resolves it to an address with a ContactResolver. At
// least one of Email or Phone must be set for delivery to be possible.
type Contact struct {
	Email string
	Phone string
}

// ContactResolver maps an OTP subject (with its tenant and purpose) to a delivery Contact. It is
// the application's seam: egauth stores only the opaque subject UUID for a challenge, so the
// app must look up where the code should go. Returning an error aborts delivery; returning an
// empty Contact means "no reachable address", which is also treated as an error.
type ContactResolver interface {
	ResolveContact(ctx context.Context, subjectID uuid.UUID, tenantID, purpose string) (Contact, error)
}

// ContactResolverFunc adapts a function to the ContactResolver interface.
type ContactResolverFunc func(ctx context.Context, subjectID uuid.UUID, tenantID, purpose string) (Contact, error)

// ResolveContact implements ContactResolver.
func (f ContactResolverFunc) ResolveContact(ctx context.Context, subjectID uuid.UUID, tenantID, purpose string) (Contact, error) {
	return f(ctx, subjectID, tenantID, purpose)
}

// OTPMessageFunc renders the Message carrying an OTP challenge's code. The default
// (DefaultOTPMessage) produces a short, channel-neutral text body; override it to brand the
// email, localise, or shorten for SMS.
type OTPMessageFunc func(ch *otp.Challenge) Message

// DefaultOTPMessage renders a short, channel-neutral OTP message. The text body is intentionally
// concise so it is also usable as an SMS.
func DefaultOTPMessage(ch *otp.Challenge) Message {
	text := fmt.Sprintf("Your verification code is %s. It expires in %s. "+
		"Do not share it with anyone.", ch.Code, time.Until(ch.ExpiresAt).Round(time.Minute))
	return Message{
		Subject: "Your verification code",
		Text:    text,
	}
}

// otpDeliveryConfig holds the wiring for OTPDelivery.
type otpDeliveryConfig struct {
	email   Sender
	sms     Sender
	message OTPMessageFunc
}

// OTPOption configures OTPDelivery.
type OTPOption func(*otpDeliveryConfig)

// WithEmailSender sets the channel used when the resolved Contact has an Email. SMTPMailer
// satisfies Sender.
func WithEmailSender(s Sender) OTPOption {
	return func(c *otpDeliveryConfig) { c.email = s }
}

// WithSMSSender sets the channel used when the resolved Contact has a Phone (and no usable
// email path was taken). Provide your own Sender wrapping an SMS provider.
func WithSMSSender(s Sender) OTPOption {
	return func(c *otpDeliveryConfig) { c.sms = s }
}

// WithOTPMessage overrides the message renderer (default DefaultOTPMessage).
func WithOTPMessage(f OTPMessageFunc) OTPOption {
	return func(c *otpDeliveryConfig) {
		if f != nil {
			c.message = f
		}
	}
}

// OTPDelivery wires a ContactResolver and one or more channel Senders into the deliver callback
// otp.IssueHandler expects (func(ctx, *otp.Challenge) error). On each issued challenge it
// resolves the subject's Contact, renders the code message, and sends it over the matching
// channel — email when the Contact has an address and an email Sender is configured, otherwise
// SMS when it has a phone and an SMS Sender is configured.
//
// It fails fast: resolver is required and at least one Sender must be configured.
func OTPDelivery(resolver ContactResolver, opts ...OTPOption) (func(ctx context.Context, ch *otp.Challenge) error, error) {
	if resolver == nil {
		return nil, errors.New("delivery: OTPDelivery requires a ContactResolver")
	}
	cfg := otpDeliveryConfig{message: DefaultOTPMessage}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.email == nil && cfg.sms == nil {
		return nil, errors.New("delivery: OTPDelivery requires at least one Sender (WithEmailSender / WithSMSSender)")
	}

	return func(ctx context.Context, ch *otp.Challenge) error {
		contact, err := resolver.ResolveContact(ctx, ch.SubjectID, ch.TenantID, ch.Purpose)
		if err != nil {
			return fmt.Errorf("delivery: resolving OTP contact: %w", err)
		}
		msg := cfg.message(ch)

		switch {
		case contact.Email != "" && cfg.email != nil:
			return cfg.email.Send(ctx, contact.Email, msg)
		case contact.Phone != "" && cfg.sms != nil:
			return cfg.sms.Send(ctx, contact.Phone, msg)
		default:
			return errors.New("delivery: no delivery channel for resolved OTP contact")
		}
	}, nil
}
