package passkey_test

import (
	"context"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBeginRegistration_RequestsDiscoverableCredential(t *testing.T) {
	svc := newPasskeyService(t)

	cc, _, err := svc.BeginRegistration(context.Background(), "", uuid.Must(uuid.NewV7()), "user@example.com", "User")
	require.NoError(t, err)

	sel := cc.Response.AuthenticatorSelection
	assert.Equal(t, protocol.ResidentKeyRequirementRequired, sel.ResidentKey,
		"usernameless (discoverable) login can only find credentials created as discoverable")
	require.NotNil(t, sel.RequireResidentKey, "requireResidentKey must be sent for WebAuthn Level 1 clients")
	assert.True(t, *sel.RequireResidentKey)
	assert.Equal(t, protocol.VerificationRequired, sel.UserVerification)
}
