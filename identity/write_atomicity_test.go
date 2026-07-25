package identity_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hookStore wraps the in-memory store so a test can interleave a concurrent write between two
// service-level store calls, or fail one operation, without racing goroutines.
type hookStore struct {
	*memory.Store
	afterFindUserByID func(user *identity.User)
	// verifiedWriteErr fails the write that marks an address verified, whichever narrow or wide
	// store operation the service uses for it.
	verifiedWriteErr error
}

func (h *hookStore) MarkEmailVerified(ctx context.Context, tenantID string, userID uuid.UUID, verifiedAt time.Time) error {
	if h.verifiedWriteErr != nil {
		return h.verifiedWriteErr
	}
	return h.Store.MarkEmailVerified(ctx, tenantID, userID, verifiedAt)
}

func (h *hookStore) FindUserByID(ctx context.Context, tenantID string, id uuid.UUID) (*identity.User, error) {
	user, err := h.Store.FindUserByID(ctx, tenantID, id)
	if err == nil && h.afterFindUserByID != nil {
		h.afterFindUserByID(user)
	}
	return user, err
}

func (h *hookStore) UpdateUser(ctx context.Context, tenantID string, user *identity.User) error {
	if h.verifiedWriteErr != nil {
		return h.verifiedWriteErr
	}
	return h.Store.UpdateUser(ctx, tenantID, user)
}

func newHookedService(t *testing.T, store identity.Store, opts ...identity.ServiceOption) identity.Service {
	t.Helper()
	policy := &mockPolicy{VerifyFunc: func(_ context.Context, p string) error {
		if len(p) < 8 {
			return assert.AnError
		}
		return nil
	}}
	return identity.NewService(store, argon2.NewHasher(), policy, opts...)
}

// TestVerifyEmail_DoesNotClobberConcurrentEmailChange is the bug-confirming test for
// identity/TEN-5: VerifyEmail read-modify-writes the whole user row through UpdateUser, so a
// concurrent ConfirmEmailChange that lands between the read and the write is silently LOST — the
// account's login address reverts to the old one while the change token has already been consumed.
// The hook makes the interleaving deterministic: the email change is applied right after VerifyEmail
// loads the user, i.e. exactly the race window.
func TestVerifyEmail_DoesNotClobberConcurrentEmailChange(t *testing.T) {
	ctx := context.Background()
	const (
		oldEmail = "verify-race-old@example.com"
		newEmail = "verify-race-new@example.com"
	)

	base := memory.NewStore()
	store := &hookStore{Store: base}
	svc := newHookedService(t, store)

	user, err := svc.Register(ctx, "", oldEmail, "OldPassw0rd!")
	require.NoError(t, err)

	verifyToken, err := svc.RequestEmailVerification(ctx, "", user.ID)
	require.NoError(t, err)
	require.NotEmpty(t, verifyToken)

	// The concurrent operation: a change-email confirmation that lands while VerifyEmail holds a
	// stale copy of the row. It runs once, right after VerifyEmail's read.
	var swapped bool
	store.afterFindUserByID = func(*identity.User) {
		if swapped {
			return
		}
		swapped = true
		require.NoError(t, base.UpdateUserEmail(ctx, "", user.ID, newEmail, time.Now()))
	}

	verified, err := svc.VerifyEmail(ctx, "", verifyToken)
	require.NoError(t, err)
	require.NotNil(t, verified)

	// The concurrent email change must survive: VerifyEmail owns email_verified_at, NOT the address.
	got, err := base.FindUserByEmail(ctx, "", newEmail)
	require.NoError(t, err, "the concurrent email change must not be lost by VerifyEmail's write")
	assert.Equal(t, user.ID, got.ID)
	require.NotNil(t, got.EmailVerifiedAt, "the account must still be marked verified")

	_, err = base.FindUserByEmail(ctx, "", oldEmail)
	assert.ErrorIs(t, err, identity.ErrUserNotFound, "the old address must not be resurrected")
}

// TestLinkOrCreateIdentity_FailedVerifiedWriteLeavesNoOrphan is the bug-confirming test for
// identity/TEN-8: when the emailVerified write fails, the just-provisioned user is left behind as an
// ORPHAN with no identity — and because the live-row email index keeps matching it, that email
// address is permanently unusable: neither Register nor a retried social login can ever claim it.
func TestLinkOrCreateIdentity_FailedVerifiedWriteLeavesNoOrphan(t *testing.T) {
	ctx := context.Background()
	const email = "orphan-link@example.com"

	boom := errors.New("verified-flag backend down")
	base := memory.NewStore()
	store := &hookStore{Store: base, verifiedWriteErr: boom}
	svc := newHookedService(t, store)

	_, err := svc.LinkOrCreateIdentity(ctx, "", "google", "sub-orphan", email, true)
	require.ErrorIs(t, err, boom)

	// The address must still be usable afterwards: the failed provisioning left nothing behind.
	store.verifiedWriteErr = nil
	retried, err := svc.LinkOrCreateIdentity(ctx, "", "google", "sub-orphan", email, true)
	require.NoError(t, err, "a retried social login must be able to claim the email again")
	require.NotNil(t, retried)
	assert.Equal(t, email, retried.Email)
}

// TestLinkOrCreateIdentity_FailedVerifiedWriteFreesEmailForRegistration pins the other half of
// identity/TEN-8: the orphan must not block ordinary password registration of the same address
// either.
func TestLinkOrCreateIdentity_FailedVerifiedWriteFreesEmailForRegistration(t *testing.T) {
	ctx := context.Background()
	const email = "orphan-register@example.com"

	boom := errors.New("verified-flag backend down")
	base := memory.NewStore()
	store := &hookStore{Store: base, verifiedWriteErr: boom}
	svc := newHookedService(t, store)

	_, err := svc.LinkOrCreateIdentity(ctx, "", "google", "sub-orphan-2", email, true)
	require.ErrorIs(t, err, boom)

	store.verifiedWriteErr = nil
	user, err := svc.Register(ctx, "", email, "OldPassw0rd!")
	require.NoError(t, err, "the failed provisioning must not block registration of the address")
	require.NotNil(t, user)
}
