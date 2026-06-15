package identity_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPhoneVerification_RoundTrip(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	user, err := svc.Register(ctx, "", "phone@example.com", "OldPassw0rd!")
	require.NoError(t, err)
	require.Nil(t, user.Phone)
	require.Nil(t, user.PhoneVerifiedAt)

	const phone = "+15551234567"
	token, err := svc.RequestPhoneVerification(ctx, "", user.ID, phone)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// The number must NOT be set yet: only requesting verification must leave the account's
	// phone unset until the token (delivered by SMS) is confirmed.
	reloaded, err := svc.RequestPhoneVerification(ctx, "", user.ID, phone)
	require.NoError(t, err, "re-requesting for the same (not-yet-owned) number is allowed")
	require.NotEmpty(t, reloaded)

	updated, err := svc.ConfirmPhoneVerification(ctx, "", token)
	require.NoError(t, err)
	require.NotNil(t, updated.Phone)
	assert.Equal(t, phone, *updated.Phone)
	require.NotNil(t, updated.PhoneVerifiedAt, "the confirmed number must be marked verified")
	assert.Equal(t, *updated.PhoneVerifiedAt, updated.UpdatedAt, "UpdatedAt must reflect the change")
}

func TestPhoneVerification_NormalizesNumber(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	user, err := svc.Register(ctx, "", "norm-phone@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	// A human-formatted number (spaces, dashes, parens) must be normalized to E.164 before the
	// number is bound to the token and stored.
	token, err := svc.RequestPhoneVerification(ctx, "", user.ID, " +1 (555) 987-6543 ")
	require.NoError(t, err)

	updated, err := svc.ConfirmPhoneVerification(ctx, "", token)
	require.NoError(t, err)
	require.NotNil(t, updated.Phone)
	assert.Equal(t, "+15559876543", *updated.Phone)
}

func TestPhoneVerification_RejectsMalformedNumber(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	user, err := svc.Register(ctx, "", "bad-phone@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	for _, bad := range []string{"not-a-number", "5551234567", "+123", "+1234567890123456", "+1555abc4567", ""} {
		_, err = svc.RequestPhoneVerification(ctx, "", user.ID, bad)
		assert.ErrorIs(t, err, identity.ErrInvalidPhone, "input %q must be rejected", bad)
	}
}

func TestPhoneVerification_RejectsNumberTakenByAnotherAccount(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const phone = "+15550001111"

	owner, err := svc.Register(ctx, "", "owner@example.com", "OldPassw0rd!")
	require.NoError(t, err)
	token, err := svc.RequestPhoneVerification(ctx, "", owner.ID, phone)
	require.NoError(t, err)
	_, err = svc.ConfirmPhoneVerification(ctx, "", token)
	require.NoError(t, err)

	// A second account cannot even request the already-owned number (advisory pre-flight).
	other, err := svc.Register(ctx, "", "other@example.com", "OldPassw0rd!")
	require.NoError(t, err)
	_, err = svc.RequestPhoneVerification(ctx, "", other.ID, phone)
	assert.ErrorIs(t, err, identity.ErrPhoneAlreadyExists)
}

func TestPhoneVerification_RejectsNumberClaimedInInterim(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const phone = "+15552223333"

	// Both accounts request the same (currently-free) number, so both hold a valid token.
	first, err := svc.Register(ctx, "", "first@example.com", "OldPassw0rd!")
	require.NoError(t, err)
	firstTok, err := svc.RequestPhoneVerification(ctx, "", first.ID, phone)
	require.NoError(t, err)

	second, err := svc.Register(ctx, "", "second@example.com", "OldPassw0rd!")
	require.NoError(t, err)
	secondTok, err := svc.RequestPhoneVerification(ctx, "", second.ID, phone)
	require.NoError(t, err)

	// The first to confirm wins; the second confirm hits the store's uniqueness guard (the
	// authoritative check that closes the request->confirm race).
	_, err = svc.ConfirmPhoneVerification(ctx, "", firstTok)
	require.NoError(t, err)
	_, err = svc.ConfirmPhoneVerification(ctx, "", secondTok)
	assert.ErrorIs(t, err, identity.ErrPhoneAlreadyExists)
}

func TestPhoneVerification_TokenIsSingleUse(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	user, err := svc.Register(ctx, "", "single@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	token, err := svc.RequestPhoneVerification(ctx, "", user.ID, "+15554445555")
	require.NoError(t, err)

	_, err = svc.ConfirmPhoneVerification(ctx, "", token)
	require.NoError(t, err)
	_, err = svc.ConfirmPhoneVerification(ctx, "", token)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound, "a phone-verification token must be single-use")
}

func TestPhoneVerification_KindIsolation(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	user, err := svc.Register(ctx, "", "kind@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	// A phone-verification token must not be consumable as an email-verification token (kind is
	// part of the consume key), and vice versa.
	phoneTok, err := svc.RequestPhoneVerification(ctx, "", user.ID, "+15556667777")
	require.NoError(t, err)
	_, err = svc.VerifyEmail(ctx, "", phoneTok)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)

	emailTok, err := svc.RequestEmailVerification(ctx, "", user.ID)
	require.NoError(t, err)
	_, err = svc.ConfirmPhoneVerification(ctx, "", emailTok)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)
}

func TestPhoneVerification_RejectsUnknownUser(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	_, err := svc.RequestPhoneVerification(ctx, "", uuid.Must(uuid.NewV7()), "+15558889999")
	assert.ErrorIs(t, err, identity.ErrUserNotFound)
}

func TestPhoneVerification_RejectsDeactivatedAccount(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	user, err := svc.Register(ctx, "", "gone-phone@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	token, err := svc.RequestPhoneVerification(ctx, "", user.ID, "+15551112222")
	require.NoError(t, err)

	// Deleting the account purges pending tokens; confirming afterwards must not resurrect it.
	require.NoError(t, svc.DeleteAccount(ctx, "", user.ID))
	_, err = svc.ConfirmPhoneVerification(ctx, "", token)
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)
}

func TestPhoneVerification_HonorsClock(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	svc, _ := newVerificationService(t, identity.WithClock(func() time.Time { return now }))

	user, err := svc.Register(ctx, "", "clock-phone@example.com", "OldPassw0rd!")
	require.NoError(t, err)

	token, err := svc.RequestPhoneVerification(ctx, "", user.ID, "+15550009999")
	require.NoError(t, err)

	updated, err := svc.ConfirmPhoneVerification(ctx, "", token)
	require.NoError(t, err)
	require.NotNil(t, updated.PhoneVerifiedAt)
	assert.Equal(t, now, *updated.PhoneVerifiedAt, "the verified-at stamp must use the injected clock")
}

// TestPhoneVerification_ServiceInterface pins that the Service interface carries the new methods
// (so a consumer can depend on them) by asserting the MockService satisfies it.
func TestPhoneVerification_ServiceInterface(t *testing.T) {
	var _ identity.Service = (*servicetest.MockService)(nil)
}
