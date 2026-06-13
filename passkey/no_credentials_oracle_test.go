package passkey_test

// Regression test for TASK-079: BeginLogin reveals whether an account has any passkey
// enrolled (no_credentials oracle).
//
// BeginLogin returns ErrNoCredentials (mapped to HTTP 400 "no_credentials") when the resolved
// user has zero registered passkeys, while a user with passkeys receives HTTP 200 plus a
// challenge.  A caller that can drive the begin-login endpoint with a chosen userID can
// therefore distinguish "account has passkeys" from "account has none" — a passkey-enrolment
// enumeration oracle.
//
// The accepted remediation (matching the audit recommendation and the threat model) is:
//  1. Document the disclosure in SECURITY.md alongside the other intentional account-existence
//     exceptions so it is a visible, auditable trade-off.
//  2. Add consumer-facing guidance that BeginLoginHandler should be rate-limited.
//
// This file contains two test functions:
//   - TestBeginLoginHandler_NoCredentialsOracleDocumented: asserts the SECURITY.md carries the
//     required disclosure text.  This is the TDD "red" test that initially fails.
//   - TestBeginLoginOracle_BehaviorBaseline: a service-level baseline that verifies the
//     observable oracle behaviour (different response for enrolled vs. unenrolled) so future
//     changes cannot silently re-introduce a regression once the behaviour is intentionally
//     altered.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// securityMDPath returns the absolute path of the repository-level SECURITY.md relative to the
// passkey package directory (one level up).
const securityMDPath = "../SECURITY.md"

// TestBeginLoginHandler_NoCredentialsOracleDocumented asserts that SECURITY.md explicitly
// documents the no_credentials oracle as an intentional disclosure.  The test fails until
// SECURITY.md is updated with the required text (TDD red phase).
func TestBeginLoginHandler_NoCredentialsOracleDocumented(t *testing.T) {
	data, err := os.ReadFile(securityMDPath)
	require.NoError(t, err, "SECURITY.md must be readable")
	content := string(data)

	// These phrases must all appear in SECURITY.md after the fix is applied.
	// If any is missing the test fails, proving the documentation gap.
	required := []string{
		"no_credentials",
		"passkey-enrolment",
		"rate",
	}
	for _, phrase := range required {
		assert.True(t, strings.Contains(content, phrase),
			"SECURITY.md must document the no_credentials oracle disclosure (missing phrase: %q)", phrase)
	}
}

// TestBeginLoginOracle_BehaviorBaseline documents the oracle's observable HTTP behaviour:
//   - A user with no passkeys → BeginLoginHandler returns 400 "no_credentials".
//   - A user with a passkey   → BeginLoginHandler returns 200 with a JSON challenge.
//
// This baseline test is intentionally kept even after the SECURITY.md fix so that a future
// change altering the observable behaviour must explicitly update this test too.
func TestBeginLoginOracle_BehaviorBaseline(t *testing.T) {
	svc, store := testService(t)

	uidNone := uuid.New()
	uidWith := uuid.New()
	saveTestCredential(t, store, uidWith, []byte{0x10, 0x20, 0x30, 0x40})

	t.Run("user_without_passkey_gets_400", func(t *testing.T) {
		h := passkey.BeginLoginHandler(svc, resolver(uidNone), passkey.WithCookieKey(testCookieKey))
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/passkey/login/begin", nil))
		assert.Equal(t, http.StatusBadRequest, rec.Code,
			"a user with no passkeys must receive 400 (intentional no_credentials oracle, documented in SECURITY.md)")
		assert.Contains(t, rec.Body.String(), "no_credentials")
	})

	t.Run("user_with_passkey_gets_200", func(t *testing.T) {
		h := passkey.BeginLoginHandler(svc, resolver(uidWith), passkey.WithCookieKey(testCookieKey))
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/passkey/login/begin", nil))
		assert.Equal(t, http.StatusOK, rec.Code,
			"a user with a passkey must receive 200 plus a challenge")
	})
}
