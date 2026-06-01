package identity

import "context"

// PasswordResetMail carries everything the application needs to craft and deliver a
// password-reset message. egauth populates it and hands it to Mailer.PasswordReset; it never
// composes subject, body, or link text itself. Token is the plaintext reset credential and MUST
// be treated as a secret (embed it in a link/code, never log it).
type PasswordResetMail struct {
	// User is the account the reset was requested for. Deliver to User.Email.
	User *User
	// Token is the plaintext password-reset credential.
	Token string
}

// EmailVerificationMail carries the details for an email-verification message. Deliver to
// User.Email. Token is the plaintext verification credential; treat it as a secret.
type EmailVerificationMail struct {
	User  *User
	Token string
}

// MagicLinkMail carries the details for a passwordless magic-link login message. Deliver to
// User.Email. Token is the plaintext login credential; treat it as a secret.
type MagicLinkMail struct {
	User  *User
	Token string
}

// EmailChangeMail carries the details for a change-email confirmation message. The message is
// delivered to NewEmail (not User.Email) because confirming control of the new address is what
// authorises the switch. The application SHOULD additionally notify User.Email so the legitimate
// owner is alerted to a pending change they did not initiate. Token is the plaintext confirmation
// credential; treat it as a secret.
type EmailChangeMail struct {
	// User is the account whose address is changing.
	User *User
	// NewEmail is the normalized address being switched to; deliver the confirmation here.
	NewEmail string
	// Token is the plaintext change-confirmation credential.
	Token string
}

// RecoveryEmailMail carries the details for a recovery-email enrollment message. It is delivered
// to RecoveryEmail (not User.Email) because confirming control of that address is what authorises
// trusting it as a recovery channel. Token is the plaintext enrollment credential; treat it as a
// secret.
type RecoveryEmailMail struct {
	// User is the account enrolling a recovery email.
	User *User
	// RecoveryEmail is the normalized candidate recovery address; deliver the confirmation here.
	RecoveryEmail string
	// Token is the plaintext recovery-email enrollment credential.
	Token string
}

// Mailer is the email-delivery seam: a set of callbacks the application supplies so egauth can
// hand off a freshly minted token without ever crafting or transporting a message itself. egauth
// never sends email (a non-objective in the PRD) and ships no templating: each callback receives
// a details struct with all the context needed to compose and send the message however the
// application sees fit (subject, body, HTML, links, localisation, transport). A nil callback means
// the application has not wired that flow; the handlers skip delivery for it. Programmatic callers
// can bypass this entirely and use the Service methods, which return the token directly.
type Mailer struct {
	// PasswordReset is invoked with a freshly minted password-reset token.
	PasswordReset func(ctx context.Context, mail PasswordResetMail) error
	// EmailVerification is invoked with a freshly minted email-verification token.
	EmailVerification func(ctx context.Context, mail EmailVerificationMail) error
	// MagicLink is invoked with a freshly minted magic-link login token.
	MagicLink func(ctx context.Context, mail MagicLinkMail) error
	// EmailChange is invoked with a freshly minted change-email confirmation token, to be
	// delivered to the new address (see EmailChangeMail).
	EmailChange func(ctx context.Context, mail EmailChangeMail) error
	// RecoveryEmailVerification is invoked with a freshly minted recovery-email enrollment token,
	// to be delivered to the candidate recovery address (see RecoveryEmailMail).
	RecoveryEmailVerification func(ctx context.Context, mail RecoveryEmailMail) error
}

// PhoneVerificationSMS carries the details for a phone-verification message. Deliver to Phone (the
// number being verified, which may differ from the account's currently-stored User.Phone). Token
// is the plaintext verification credential; treat it as a secret (embed it as a short code or a
// confirmation link, never log it).
type PhoneVerificationSMS struct {
	// User is the account the phone number is being verified for.
	User *User
	// Phone is the normalized number being verified; deliver the credential here.
	Phone string
	// Token is the plaintext phone-verification credential.
	Token string
}

// SMSSender is the SMS-delivery seam: a callback the application supplies so egauth can hand off a
// freshly minted phone-verification token without crafting or transporting a message itself. It is
// a separate seam from Mailer because SMS is a distinct channel that not every deployment uses and
// every provider is a paid third-party API (Twilio, SNS, …). egauth never sends SMS (a
// non-objective) and ships no templating: the callback receives a details struct with all the
// context needed to compose and send the message. A nil SMSSender means the application has not
// wired SMS delivery; the handlers skip it. Programmatic callers can bypass this and use the
// Service methods, which return the token directly.
type SMSSender struct {
	// PhoneVerification is invoked with a freshly minted phone-verification token.
	PhoneVerification func(ctx context.Context, sms PhoneVerificationSMS) error
}
