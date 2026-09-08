package identity_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/stretchr/testify/require"
)

// TestAuditPoc_DisabledAccountStillMintedTokens demonstrates that the
// unauthenticated Request* entry points mint single-use tokens for
// administratively DISABLED accounts: RequestMagicLink and RequestPasswordReset
// return a live token (and hand it to the mailer for delivery), while unknown
// identifiers yield ("", nil, nil). Disabled accounts should behave exactly
// like unknown ones at this layer — the consume-time rejection happens later,
// after the token has already been emailed.
func TestAuditPoc_DisabledAccountStillMintedTokens(t *testing.T) {
	ctx := context.Background()
	svc := identity.NewService(identitymemory.NewStore(), auditHasher(), auditPolicy())
	user, err := svc.Register(ctx, "", "suspended@example.com", "SomeStrongPassword123!")
	require.NoError(t, err)
	require.NoError(t, svc.DisableUser(ctx, "", user.ID))

	mlToken, mlUser, err := svc.RequestMagicLink(ctx, "", "suspended@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, mlToken,
		"VULNERABILITY DEMONSTRATED: magic-link token minted for a disabled account")
	require.NotNil(t, mlUser)

	mlTokenUnknown, _, err := svc.RequestMagicLink(ctx, "", "nobody@example.com")
	require.NoError(t, err)
	require.Empty(t, mlTokenUnknown, "unknown account yields no token — the gap is observable")

	rstToken, rstUser, err := svc.RequestPasswordReset(ctx, "", "suspended@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, rstToken,
		"VULNERABILITY DEMONSTRATED: password-reset token minted for a disabled account")
	require.NotNil(t, rstUser)

	// The minted tokens are at least single-use-gated at consume time: using the
	// reset token must still fail for the disabled account.
	require.Error(t, svc.ResetPassword(ctx, "", rstToken, "BrandNewPassword123!"),
		"consume-time liveness gate must keep rejecting the disabled account")
}
