package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Verification-token kinds. Consumers may define their own kinds, but these two are used by
// the built-in password-reset and email-verification flows.
const (
	// KindPasswordReset identifies tokens minted for the password-reset flow.
	KindPasswordReset = "password_reset"
	// KindEmailVerification identifies tokens minted for the email-verification flow.
	KindEmailVerification = "email_verification"
	// KindMagicLink identifies tokens minted for passwordless magic-link login.
	KindMagicLink = "magic_link"
	// KindEmailChange identifies tokens minted for the authenticated change-email flow. The
	// token carries the requested new email address as its metadata and is delivered to that
	// new address, so confirming it proves control of the new address before the swap.
	KindEmailChange = "email_change"
	// KindPhoneVerification identifies tokens minted for the phone-verification flow. The token
	// carries the requested phone number as its metadata and is delivered to that number by SMS,
	// so confirming it proves control of the number before it is set on the account.
	KindPhoneVerification = "phone_verification"
	// KindRecoveryEmailVerification identifies tokens minted for the recovery-email enrollment
	// flow. The token carries the requested recovery address as its metadata and is delivered to
	// that address, so confirming it proves control of the recovery channel before it is set.
	KindRecoveryEmailVerification = "recovery_email_verification"
)

const (
	// selectorBytes is the entropy of the lookup half of a verification token.
	selectorBytes = 16
	// verifierBytes is the entropy of the secret half of a verification token.
	verifierBytes = 32
	// tokenSeparator joins the selector and verifier in the plaintext token. It is a
	// character that never appears in base64url (RawURLEncoding) output, so SplitVerification
	// Token can recover the two halves unambiguously.
	tokenSeparator = "."
)

// VerificationToken is a single-use, time-bounded credential used by the password-reset and
// email-verification flows. Per the PRD (§109) it follows a selector/verifier scheme rather
// than a single global hash:
//
//   - Selector is a random, indexable lookup key stored in clear (it is not secret on its
//     own — it only names the row).
//   - VerifierHash is the SHA-256 of the secret half; the plaintext verifier is never
//     stored. On consumption the presented verifier is hashed and compared in constant time.
//
// This dissociation gives an O(1) indexed lookup (impossible with a per-row salted hash)
// while still defeating a timing oracle on the secret. Only the plaintext token
// (selector.verifier) is ever handed to the user, exactly once.
type VerificationToken struct {
	Selector     string
	VerifierHash string
	UserID       uuid.UUID
	TenantID     string
	Kind         string
	Metadata     []byte // optional internal payload, returned verbatim on consumption
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

// GenerateVerificationToken mints a fresh selector/verifier pair. It returns the plaintext
// token to hand to the user (selector.verifier), the selector to index on, and the SHA-256
// hash of the verifier to persist. The plaintext verifier itself is never returned for
// storage. Store implementations call this so the secure-generation logic lives in one place.
func GenerateVerificationToken() (token, selector, verifierHash string, err error) {
	sel := make([]byte, selectorBytes)
	if _, err = rand.Read(sel); err != nil {
		return "", "", "", err
	}
	ver := make([]byte, verifierBytes)
	if _, err = rand.Read(ver); err != nil {
		return "", "", "", err
	}
	selector = base64.RawURLEncoding.EncodeToString(sel)
	verifier := base64.RawURLEncoding.EncodeToString(ver)
	token = selector + tokenSeparator + verifier
	return token, selector, HashVerifier(verifier), nil
}

// SplitVerificationToken splits a plaintext token into its selector and verifier halves. It
// reports ok=false for a malformed token (missing separator or empty half).
func SplitVerificationToken(token string) (selector, verifier string, ok bool) {
	sel, ver, found := strings.Cut(token, tokenSeparator)
	if !found || sel == "" || ver == "" {
		return "", "", false
	}
	return sel, ver, true
}

// HashVerifier returns the hex-encoded SHA-256 of a verifier. It is the value persisted in
// VerificationToken.VerifierHash.
func HashVerifier(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return hex.EncodeToString(sum[:])
}

// CompareVerifier reports whether the presented plaintext verifier matches the stored hash,
// comparing in constant time to avoid a timing oracle on the secret half.
func CompareVerifier(verifierHash, verifier string) bool {
	got := HashVerifier(verifier)
	return subtle.ConstantTimeCompare([]byte(got), []byte(verifierHash)) == 1
}

// Mailer delivers verification credentials to a user. egauth never sends email itself (a
// non-objective in the PRD); it only defines this interface so the HTTP request handlers can
// hand a freshly minted token to the application's delivery mechanism. Implementations
// receive the plaintext token and MUST treat it as a credential (embed it in a link/code,
// never log it). Programmatic callers can bypass this entirely and use the Service methods,
// which return the token directly.
type Mailer interface {
	// SendPasswordReset delivers a password-reset token to the user (e.g. as a reset link).
	SendPasswordReset(ctx context.Context, user *User, token string) error
	// SendEmailVerification delivers an email-verification token to the user.
	SendEmailVerification(ctx context.Context, user *User, token string) error
	// SendMagicLink delivers a passwordless magic-link login token to the user.
	SendMagicLink(ctx context.Context, user *User, token string) error
	// SendEmailChange delivers a change-email confirmation token to the account's NEW address
	// (newEmail), e.g. as a confirmation link. The token is delivered to newEmail rather than
	// the account's current address because confirming it is what proves control of the new
	// address before the email is switched. Implementations SHOULD additionally send a security
	// notification to the current address (user.Email) so the legitimate owner is alerted to a
	// pending change they did not initiate.
	SendEmailChange(ctx context.Context, user *User, newEmail, token string) error
	// SendRecoveryEmailVerification delivers a recovery-email enrollment token to the candidate
	// recovery address (recoveryEmail), e.g. as a confirmation link. It is delivered to that
	// address (not the primary) because confirming it is what proves control of the recovery
	// channel before it is trusted.
	SendRecoveryEmailVerification(ctx context.Context, user *User, recoveryEmail, token string) error
}

// SMSSender delivers a phone-verification credential to a phone number over SMS. It is a separate
// seam from Mailer because SMS is a distinct delivery channel that not every deployment uses, and
// egauth never sends SMS itself (delivery is a non-objective): the handlers hand a freshly minted
// token to the application's SMS provider via this interface. Implementations receive the plaintext
// token and MUST treat it as a credential (embed it in the message, never log it). Programmatic
// callers can bypass this and use the Service methods, which return the token directly. The
// delivery package's Sender seam (an SMS provider adapter) satisfies the spirit of this contract;
// wire a thin adapter that formats the verification message.
type SMSSender interface {
	// SendPhoneVerification delivers a phone-verification token to the requested phone number
	// (the number being verified, which may differ from the account's currently-stored Phone),
	// e.g. as a short code or a confirmation link.
	SendPhoneVerification(ctx context.Context, user *User, phone, token string) error
}
