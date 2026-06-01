// Package delivery provides reference implementations of the message-delivery seams egauth
// defines but deliberately does not fill itself: a standard-library SMTP Mailer (satisfying
// identity.Mailer), a Go-template-based message renderer you can fully override, and an OTP code
// Sender wired through an application-supplied contact-resolution seam.
//
// egauth never sends mail or SMS on its own — delivery is application infrastructure, and
// baking in a transport would force a dependency and an opinion on every adopter. Instead the
// identity flows hand a freshly minted token to identity.Mailer, and otp.IssueHandler hands a
// Challenge to a deliver callback. This package is the batteries-included answer for the common
// case (an SMTP submission relay) while staying entirely optional and dependency-free.
//
// # Email (identity flows)
//
// NewSMTPMailer returns an *SMTPMailer implementing identity.Mailer for the password-reset,
// email-verification, magic-link and change-email flows:
//
//	mailer, err := delivery.NewSMTPMailer(delivery.SMTPConfig{
//	    Host: "smtp.example.com", Port: 587,
//	    Username: "apikey", Password: secret,
//	    From: "no-reply@example.com", FromName: "Example Security",
//	}, delivery.WithLinks(delivery.LinkConfig{
//	    PasswordReset:     "https://app.example.com/reset",
//	    EmailVerification: "https://app.example.com/verify",
//	    MagicLink:         "https://app.example.com/signin",
//	    EmailChange:       "https://app.example.com/confirm-email",
//	}))
//	// ... identity.RequestPasswordResetHandler(svc, mailer, ...)
//
// The default messages are plain, provider-neutral text. Override any of them — add HTML,
// branding, or localisation — with WithTemplate on a TemplateRenderer passed via WithRenderer,
// or replace rendering wholesale by implementing Renderer.
//
// # OTP codes (email or SMS)
//
// otp.IssueHandler delivers via a callback. OTPDelivery builds that callback from a
// ContactResolver (your map from the opaque subject UUID to an email/phone) and one or more
// channel Senders:
//
//	deliver, err := delivery.OTPDelivery(resolver,
//	    delivery.WithEmailSender(mailer), // SMTPMailer is a Sender
//	    delivery.WithSMSSender(twilioSender))
//	// ... otp.IssueHandler(otpSvc, deliver, ...)
//
// # The SMS story
//
// egauth ships NO SMS Sender. Every SMS provider is a paid, account-bound third-party API
// (Twilio, AWS SNS, Vonage, MessageBird, ...); bundling one would mean a vendor dependency, an
// API key, and a billing relationship that does not belong in an auth library. Instead SMS is a
// one-method seam: implement Sender against your provider and pass it to WithSMSSender.
//
//	type twilioSender struct{ client *twilio.RestClient; from string }
//
//	func (t twilioSender) Send(ctx context.Context, phone string, msg delivery.Message) error {
//	    // POST the SMS; an SMS Sender uses msg.Text and ignores Subject/HTML.
//	    return t.client.SendSMS(ctx, t.from, phone, msg.Text)
//	}
//
// Two scope notes:
//
//   - MFA second factors. The mfa module intentionally excludes SMS as a TOTP/recovery factor:
//     SMS-delivered one-time codes are a discouraged authenticator (NIST SP 800-63B restricts
//     them due to SIM-swap and interception). Use TOTP or passkeys for MFA. The OTP-over-SMS
//     path here is for lower-assurance uses such as phone-number verification or transactional
//     codes, not for hardening a login.
//   - Phone verification. The identity module now carries an optional verified phone number
//     (identity.User.Phone) with a request/confirm flow (Service.RequestPhoneVerification /
//     ConfirmPhoneVerification and the matching handlers). This package supplies the SMS-delivery
//     half: PhoneVerifier wraps an SMS Sender to implement identity.SMSSender, so wiring the flow
//     is NewPhoneVerifier(yourSMSSender) passed to RequestPhoneVerificationHandler. It is a
//     lower-assurance contact channel, not an MFA factor (see the MFA note above).
package delivery
