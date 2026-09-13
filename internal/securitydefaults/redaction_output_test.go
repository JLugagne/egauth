package securitydefaults

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/authflow"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/mfa"
	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/google/uuid"
)

// The cases below render the types that hand credential material back to a caller — as opposed to
// the types that store it — through every accidental-leak path. Each one previously printed the
// secret in full while its storing counterpart was carefully redacted, so a single log line
// converted into a working credential.
//
// They are output assertions rather than reflective checks on purpose: the question is what a log
// line actually contains.

// secretLiterals are the values a rendered log line must never contain.
var secretLiterals = map[string]string{
	"mfa seed":       "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
	"flow token key": "flow-token-signing-key-0123456789",
	"cookie key":     "ceremony-cookie-key-0123456789ab",
	"reset token":    "selector0123456789abcdef.verifier0123456789abcdef",
}

func assertRedacted(t *testing.T, label, rendered string) {
	t.Helper()
	for name, secret := range secretLiterals {
		if strings.Contains(rendered, secret) {
			t.Errorf("%s leaked the %s: %q", label, name, rendered)
		}
	}
}

func TestMFAReturnedEnrollmentIsRedacted(t *testing.T) {
	enrollment := mfa.Enrollment{Secret: secretLiterals["mfa seed"], URI: "otpauth://totp/x"}

	assertRedacted(t, "fmt %v", fmt.Sprintf("%v", enrollment))
	assertRedacted(t, "fmt %+v", fmt.Sprintf("%+v", enrollment))
	assertRedacted(t, "fmt %#v", fmt.Sprintf("%#v", enrollment))

	// The pointer form leaks too, which is why the methods use value receivers.
	assertRedacted(t, "*Enrollment %v", fmt.Sprintf("%v", &enrollment))
	assertRedacted(t, "*Enrollment %#v", fmt.Sprintf("%#v", &enrollment))

	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("enroll", "enrollment", enrollment)
	assertRedacted(t, "slog.Any", buf.String())

	// The secret must still be reachable for callers that need to render the QR code.
	if enrollment.Secret != secretLiterals["mfa seed"] {
		t.Error("redaction must not mutate the value: delivery code reads the field directly")
	}
}

func TestMFARedactionDistinguishesUnsetFromSet(t *testing.T) {
	unset := fmt.Sprintf("%v", mfa.Enrollment{})
	set := fmt.Sprintf("%v", mfa.Enrollment{Secret: "x"})
	if unset == set {
		t.Error("an unset secret should render differently from a hidden one, so a missing token is debuggable")
	}
}

func TestPasskeyServiceIsRedacted(t *testing.T) {
	svc, err := passkey.NewService(passkeymemory.NewStore(), passkey.Config{
		RPID:           "example.com",
		RPDisplayName:  "Example",
		RPOrigins:      []string{"https://example.com"},
		CookieKey:      []byte(secretLiterals["cookie key"]),
		ChallengeStore: passkeymemory.NewChallengeStore(),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	assertRedacted(t, "passkey fmt %v", fmt.Sprintf("%v", svc))
	assertRedacted(t, "passkey fmt %+v", fmt.Sprintf("%+v", svc))
	assertRedacted(t, "passkey fmt %#v", fmt.Sprintf("%#v", svc))

	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("passkey", "service", svc)
	assertRedacted(t, "passkey slog.Any", buf.String())
}

func TestAuthflowEngineIsRedacted(t *testing.T) {
	engine, err := authflow.NewEngine([]byte(secretLiterals["flow token key"]))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	assertRedacted(t, "authflow fmt %v", fmt.Sprintf("%v", engine))
	assertRedacted(t, "authflow fmt %+v", fmt.Sprintf("%+v", engine))
	assertRedacted(t, "authflow fmt %#v", fmt.Sprintf("%#v", engine))

	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("flow", "engine", engine)
	assertRedacted(t, "authflow slog.Any", buf.String())
}

func TestIdentityDeliveryPayloadsAreRedacted(t *testing.T) {
	user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}
	payloads := []struct {
		name    string
		payload any
	}{
		{"PasswordResetMail", identity.PasswordResetMail{User: user, Token: secretLiterals["reset token"]}},
		{"EmailVerificationMail", identity.EmailVerificationMail{User: user, Token: secretLiterals["reset token"]}},
		{"MagicLinkMail", identity.MagicLinkMail{User: user, Token: secretLiterals["reset token"]}},
		{"EmailChangeMail", identity.EmailChangeMail{User: user, NewEmail: "new@example.com", Token: secretLiterals["reset token"]}},
		{"RecoveryEmailMail", identity.RecoveryEmailMail{User: user, RecoveryEmail: "r@example.com", Token: secretLiterals["reset token"]}},
		{"PhoneVerificationSMS", identity.PhoneVerificationSMS{User: user, Phone: "+15550001111", Token: secretLiterals["reset token"]}},
	}
	for _, p := range payloads {
		t.Run(p.name, func(t *testing.T) {
			assertRedacted(t, "fmt %v", fmt.Sprintf("%v", p.payload))
			assertRedacted(t, "fmt %+v", fmt.Sprintf("%+v", p.payload))
			assertRedacted(t, "fmt %#v", fmt.Sprintf("%#v", p.payload))

			var buf bytes.Buffer
			slog.New(slog.NewTextHandler(&buf, nil)).Info("deliver", "payload", p.payload)
			assertRedacted(t, "slog.Any", buf.String())
		})
	}
}

func TestIdentityDeliveryPayloadKeepsNonSecretContext(t *testing.T) {
	payload := identity.EmailChangeMail{
		User:     &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"},
		NewEmail: "new@example.com",
		Token:    secretLiterals["reset token"],
	}
	rendered := fmt.Sprintf("%v", payload)
	if !strings.Contains(rendered, "new@example.com") {
		t.Errorf("the recipient stays visible so the log line is still useful, got %q", rendered)
	}
}

func TestIdentityRecordIsRedacted(t *testing.T) {
	hash := "$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$aGFzaA"
	ident := identity.Identity{
		ID:           uuid.Must(uuid.NewV7()),
		UserID:       uuid.Must(uuid.NewV7()),
		Provider:     "password",
		ProviderID:   "u@example.com",
		PasswordHash: &hash,
	}
	for _, rendered := range []string{
		fmt.Sprintf("%v", ident),
		fmt.Sprintf("%+v", ident),
		fmt.Sprintf("%#v", ident),
	} {
		if strings.Contains(rendered, hash) {
			t.Errorf("identity record leaked the password hash: %q", rendered)
		}
	}
	// The binding stays visible.
	if !strings.Contains(fmt.Sprintf("%v", ident), "u@example.com") {
		t.Error("the provider binding should stay visible for debugging")
	}
}
