---
title: "Email & OTP Delivery"
weight: 7
---

# Email and OTP Delivery

`egauth` defines "seams" for delivery but deliberately does not fill them itself. It ships with a standard-library SMTP Mailer (satisfying `identity.Mailer`) and an OTP code Sender wired through an application-supplied contact-resolution seam.

**`egauth` never sends mail or SMS on its own.** Delivery is application infrastructure. Instead, the identity flows hand a freshly minted token to the `Mailer`, and the OTP handler hands a Challenge to a deliver callback. 

## Setting up the SMTP Mailer

The `delivery.NewSMTPMailer` returns a mailer implementing `identity.Mailer` for password-reset, email-verification, magic-link, and change-email flows.

```go
import "github.com/JLugagne/egauth/delivery"

mailer, err := delivery.NewSMTPMailer(delivery.SMTPConfig{
    Host:     "smtp.example.com", 
    Port:     587,
    Username: "apikey", 
    Password: "secret_password",
    From:     "no-reply@example.com", 
    FromName: "My App Security",
}, delivery.WithLinks(delivery.LinkConfig{
    PasswordReset:     "https://app.example.com/reset",
    EmailVerification: "https://app.example.com/verify",
    MagicLink:         "https://app.example.com/signin",
    EmailChange:       "https://app.example.com/confirm-email",
}))

// You can now pass this `mailer` to Identity HTTP handlers:
// identity.RequestPasswordResetHandler(svc, mailer, ...)
```

The default messages are plain, provider-neutral text. You can override any of them by adding HTML, branding, or localization using `WithTemplate` on a `TemplateRenderer`, or replace the renderer entirely.

## OTP over SMS

`egauth` ships **NO SMS Sender**. Bundling one would mean a vendor dependency, an API key, and a billing relationship that does not belong in an auth library. 

Instead, SMS is a one-method seam. You implement the `Sender` interface against your provider (Twilio, AWS SNS, MessageBird) and pass it to `WithSMSSender`.

```go
type twilioSender struct{ 
    client *twilio.RestClient
    from   string 
}

func (t twilioSender) Send(ctx context.Context, phone string, msg delivery.Message) error {
    // POST the SMS; an SMS Sender uses msg.Text and ignores Subject/HTML.
    return t.client.SendSMS(ctx, t.from, phone, msg.Text)
}

// Wire it up to the OTP Delivery builder
deliverFunc, err := delivery.OTPDelivery(
    myContactResolver,
    delivery.WithSMSSender(twilioSender{client, "+123456789"}),
)

// Pass `deliverFunc` to `otp.IssueHandler`
```

> **Security Note:** The `mfa` module intentionally excludes SMS as a TOTP/recovery factor due to SIM-swap vulnerabilities (per NIST SP 800-63B). The OTP-over-SMS path is intended for lower-assurance uses like initial phone verification or transactional codes, not for hardening a login as a second factor.
