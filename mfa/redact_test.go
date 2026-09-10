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

const leakTOTPSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

func sampleEnrollment() mfa.TOTPEnrollment {
	return mfa.TOTPEnrollment{
		UserID:         uuid.MustParse("6f9619ff-8b86-d011-b42d-00c04fc964ff"),
		TenantID:       "acme",
		Secret:         leakTOTPSecret,
		LastUsedStep:   12345,
		FailedAttempts: 2,
		CreatedAt:      time.Now(),
	}
}

func TestTOTPEnrollment_RedactsSecretWhenPrinted(t *testing.T) {
	e := sampleEnrollment()
	renderings := map[string]string{
		"String":  e.String(),
		"fmt %v":  fmt.Sprintf("%v", e),
		"fmt %+v": fmt.Sprintf("%+v", e),
		"fmt %#v": fmt.Sprintf("%#v", e),
	}
	for name, out := range renderings {
		t.Run(name, func(t *testing.T) {
			assert.NotContains(t, out, leakTOTPSecret, "Secret must be redacted")
			assert.Contains(t, out, "REDACTED")
			// Non-secret lifecycle fields stay visible to aid debugging.
			assert.Contains(t, out, "6f9619ff-8b86-d011-b42d-00c04fc964ff", "UserID is not secret and should remain")
		})
	}
}

func TestTOTPEnrollment_LogValueRedactsSecret(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("enrollment", "enrollment", sampleEnrollment())
	out := buf.String()
	assert.NotContains(t, out, leakTOTPSecret)
	assert.Contains(t, out, "REDACTED")
	assert.Contains(t, out, "6f9619ff-8b86-d011-b42d-00c04fc964ff")
}
