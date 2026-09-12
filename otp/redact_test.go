package otp_test

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/otp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChallenge_RedactsCode pins issue #125: a one-time code must never reach logs or
// formatted output, while staying reachable through the exported Code field for delivery.
func TestChallenge_RedactsCode(t *testing.T) {
	const code = "123456"
	ch := otp.Challenge{
		SubjectID: uuid.Must(uuid.NewV7()),
		TenantID:  "tenant",
		Purpose:   "login",
		Code:      code,
	}
	require.Equal(t, code, ch.Code, "the plaintext code must remain available for delivery")

	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(format, ch)
		assert.NotContains(t, out, code, "fmt %q must not leak the one-time code", format)
	}

	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("otp issued", "challenge", ch)
	assert.NotContains(t, buf.String(), code, "slog must not leak the one-time code")
	assert.Contains(t, buf.String(), "REDACTED", "slog output should mark the code as redacted")
}

// TestOTP_RedactsCodeHash pins issue #125 for the stored record: the hash must not be
// printed by %v/%+v/%#v or structured logging.
func TestOTP_RedactsCodeHash(t *testing.T) {
	const hash = "deadbeefcafebabe0123456789abcdef"
	o := otp.OTP{
		SubjectID: uuid.Must(uuid.NewV7()),
		TenantID:  "tenant",
		Purpose:   "login",
		CodeHash:  hash,
		Attempts:  2,
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(format, o)
		assert.NotContains(t, out, hash, "fmt %q must not leak the stored code hash", format)
	}

	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("otp record", "otp", o)
	assert.NotContains(t, buf.String(), hash, "slog must not leak the stored code hash")
}
