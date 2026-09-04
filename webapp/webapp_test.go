package webapp_test

import (
	"testing"

	"github.com/JLugagne/egauth/webapp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewWebApp_ConflictingCSRFConfig_RejectsContradiction confirms SEC-SES-11 (CVSS 8.1).
//
// Security invariant:
// The webapp.NewWebApp constructor MUST explicitly reject any contradictory configuration
// where TrustedOrigins is set AND InsecureNoOriginCheck is enabled to true.
// The presence of a trusted-origins allowlist (TrustedOrigins) implies a formal intent
// to enable and restrict CSRF protection; allowing InsecureNoOriginCheck in parallel
// constitutes a major security configuration conflict that must fail immediately at construction (fail-closed).
//
// Current vulnerable behaviour:
// In webapp.NewWebApp (webapp/webapp.go:122-124 and 169-178), the guard only checks:
//
//	len(cfg.TrustedOrigins) == 0 && !cfg.InsecureNoOriginCheck
//
// If the developer configures TrustedOrigins while keeping InsecureNoOriginCheck: true,
// NewWebApp silently accepts the configuration, and WithInsecureNoOriginCheck()
// overwrites WithTrustedOrigins(). CSRF protection is completely disabled without the administrator's knowledge.
func TestNewWebApp_ConflictingCSRFConfig_RejectsContradiction(t *testing.T) {
	cfg := baseConfig()
	cfg.TrustedOrigins = []string{"https://app.example.com"}
	cfg.InsecureNoOriginCheck = true

	// SECURITY INVARIANT VIOLATED: the constructor must reject this contradictory combination
	_, err := webapp.NewWebApp(cfg)
	require.Error(t, err,
		"SEC-SES-11: webapp.NewWebApp must reject the contradictory combination of TrustedOrigins and InsecureNoOriginCheck")
	assert.Contains(t, err.Error(), "cannot specify both TrustedOrigins and InsecureNoOriginCheck")
}
