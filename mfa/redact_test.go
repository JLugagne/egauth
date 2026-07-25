package mfa_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/JLugagne/egauth/mfa"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// The TOTP shared secret is stored (and handled) in a recoverable form — the server recomputes the
// expected code from it — so a %v/%+v/%s of an enrollment must never render it. The provisioning
// URI embeds the same secret and is redacted with it.
func TestTOTPEnrollment_RedactsSecretWhenPrinted(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	confirmed := time.Unix(1_700_000_000, 0)
	e := &mfa.TOTPEnrollment{
		UserID:      uuid.Must(uuid.NewV7()),
		TenantID:    "acme",
		Secret:      secret,
		ConfirmedAt: &confirmed,
		CreatedAt:   confirmed,
	}

	for _, s := range []string{
		e.String(),
		fmt.Sprintf("%v", e),
		fmt.Sprintf("%+v", e),
		fmt.Sprintf("%s", e),
		fmt.Sprintf("%#v", e),
		fmt.Sprintf("%v", *e),
		fmt.Sprintf("%+v", *e),
	} {
		assert.NotContains(t, s, secret, "TOTP shared secret leaked into printed output")
		assert.Contains(t, s, "REDACTED")
	}
	assert.Contains(t, e.String(), "acme")
}

func TestEnrollment_RedactsSecretAndURIWhenPrinted(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	en := &mfa.Enrollment{
		Secret: secret,
		URI:    mfa.ProvisioningURI(secret, "Acme", "user@example.com", mfa.DefaultDigits, mfa.DefaultPeriod),
	}
	for _, s := range []string{
		en.String(),
		fmt.Sprintf("%v", en),
		fmt.Sprintf("%+v", en),
		fmt.Sprintf("%s", en),
		fmt.Sprintf("%#v", en),
		fmt.Sprintf("%+v", *en),
	} {
		assert.NotContains(t, s, secret, "the provisioning URI embeds the shared secret and must be redacted with it")
		assert.Contains(t, s, "REDACTED")
	}
}

func TestTOTPEnrollment_LogValueRedacts(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("enrolled",
		"enrollment", &mfa.TOTPEnrollment{TenantID: "acme", Secret: "LEAKMELEAKMELEAKMELEAKMELEAKMELE"},
		"minted", &mfa.Enrollment{Secret: "LEAKMELEAKMELEAKMELEAKMELEAKMELE", URI: "otpauth://totp/x?secret=LEAKMELEAKMELEAKMELEAKMELEAKMELE"},
	)
	out := buf.String()
	assert.NotContains(t, out, "LEAKMELEAKMELEAKMELEAKMELEAKMELE")
	assert.Contains(t, out, "REDACTED")
}
