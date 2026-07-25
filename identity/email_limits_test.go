package identity_test

import (
	"context"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegister_RejectsOversizedEmail is the bug-confirming test for identity/TEN-16: normalizeEmail
// enforced no maximum address length, so an address far beyond the RFC 5321 limit passed validation
// and was persisted (or failed deep inside the store, where the error is opaque). Validation must
// reject it up front with a declared sentinel.
func TestRegister_RejectsOversizedEmail(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	oversized := strings.Repeat("a", 300) + "@example.com"
	_, err := svc.Register(ctx, "", oversized, "OldPassw0rd!")
	require.Error(t, err, "an address beyond the RFC 5321 maximum must be rejected by validation")
	assert.ErrorIs(t, err, identity.ErrEmailTooLong)

	// The documented maximum is still accepted: 254 bytes total.
	local := strings.Repeat("a", identity.MaxEmailLength-len("@example.com"))
	atLimit := local + "@example.com"
	require.Len(t, atLimit, identity.MaxEmailLength)
	_, err = svc.Register(ctx, "", atLimit, "OldPassw0rd!")
	require.NoError(t, err, "an address exactly at the maximum must still be accepted")
}

// TestLinkOrCreateIdentity_SecondEmaillessAccountIsRejected pins the documented (refuter-found)
// limitation at identity/service.go: a provider account that supplies no usable email is
// provisioned with an EMPTY email, and the email slot is byte-exact unique per tenant, so a tenant
// can hold at most ONE such account. The second attempt is refused with ErrEmailAlreadyExists
// rather than silently collapsing two provider accounts into one.
func TestLinkOrCreateIdentity_SecondEmaillessAccountIsRejected(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	first, err := svc.LinkOrCreateIdentity(ctx, "", "github", "sub-no-email-1", "", false)
	require.NoError(t, err)
	require.NotNil(t, first)
	assert.Equal(t, "", first.Email)

	_, err = svc.LinkOrCreateIdentity(ctx, "", "github", "sub-no-email-2", "", false)
	assert.ErrorIs(t, err, identity.ErrEmailAlreadyExists,
		"only one email-less account can exist per tenant; the second must be refused explicitly")

	// The first account still resolves on its own provider identity.
	again, err := svc.LinkOrCreateIdentity(ctx, "", "github", "sub-no-email-1", "", false)
	require.NoError(t, err)
	assert.Equal(t, first.ID, again.ID)
}
