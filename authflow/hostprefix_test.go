package authflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// alwaysEnrolledGate forces the MFA-challenged path, which is the only place the flow-token
// cookie is written.
type alwaysEnrolledGate struct{}

func (alwaysEnrolledGate) IsEnrolled(context.Context, string, uuid.UUID) (bool, error) {
	return true, nil
}

const hostPrefixTestEngineSecret = "01234567890123456789012345678901"

// allowAllValidator is the minimal AccountValidator stub satisfying the MFA-gated
// construction guard; the host-prefix tests never exercise lifecycle semantics.
type allowAllValidator struct{}

func (allowAllValidator) ValidateAccount(context.Context, string, uuid.UUID) error { return nil }

func TestDefaultFlowCookieName_IsHostPrefixed(t *testing.T) {
	require.True(t, strings.HasPrefix(DefaultFlowCookieName, hostPrefix),
		"the default flow cookie name must carry the __Host- prefix (host-lock hardening)")
}

// TestProcessPrimaryAuth_HostLockedFlowCookieAttributes proves the emitted flow cookie satisfies
// the browser-enforced __Host- requirements the default name promises: Path=/ and no Domain.
// (The Secure attribute is owned by the request-TLS handling and is deliberately not asserted
// here.)
func TestProcessPrimaryAuth_HostLockedFlowCookieAttributes(t *testing.T) {
	engine, err := NewEngine([]byte(hostPrefixTestEngineSecret), WithMFAGate(alwaysEnrolledGate{}), WithAccountValidator(allowAllValidator{}))
	require.NoError(t, err)

	user := &identity.User{ID: uuid.Must(uuid.NewV7()), TenantID: "tenant-1", Email: "u@example.com"}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	result, err := engine.ProcessPrimaryAuth(context.Background(), rec, req, user, "password", nil, false)
	require.NoError(t, err)
	require.Equal(t, StateMFAChallenged, result.State)

	var flowCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == DefaultFlowCookieName {
			flowCookie = c
		}
	}
	require.NotNil(t, flowCookie, "the MFA-challenged primary auth must set the flow cookie")
	assert.NotEmpty(t, flowCookie.Value)
	assert.Empty(t, flowCookie.Domain, "__Host- flow cookie must be host-only (no Domain)")
	assert.Equal(t, "/", flowCookie.Path, "__Host- flow cookie must have Path=/")
	assert.True(t, flowCookie.HttpOnly)
}

// TestEngineValidate_HostPrefixMisconfigurationFailsLoudly exercises the construction-time guard
// directly: a __Host- name paired with cookie attributes browsers silently refuse to store
// (a Domain, or a non-root path) must produce a loud validation error instead of a mysteriously
// missing cookie that breaks MFA step-up at runtime.
func TestEngineValidate_HostPrefixMisconfigurationFailsLoudly(t *testing.T) {
	engine, err := NewEngine([]byte(hostPrefixTestEngineSecret))
	require.NoError(t, err)

	engine.cookieDomain = "example.com"
	err = engine.validate()
	require.Error(t, err, "a __Host- flow cookie with a Domain must fail validation loudly")
	assert.Contains(t, err.Error(), "Domain")

	engine.cookieDomain = ""
	engine.cookiePath = "/auth"
	err = engine.validate()
	require.Error(t, err, "a __Host- flow cookie with a non-root path must fail validation loudly")
	assert.Contains(t, err.Error(), "Path")
}

func TestNewEngine_CookieConfigValidation(t *testing.T) {
	_, err := NewEngine([]byte(hostPrefixTestEngineSecret))
	require.NoError(t, err, "the default __Host- name is compatible with the engine's fixed cookie attributes")

	_, err = NewEngine([]byte(hostPrefixTestEngineSecret), WithCookieName("auth_flow_token"))
	require.NoError(t, err, "an explicit plain-name opt-out must be accepted")
}
