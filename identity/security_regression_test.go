package identity_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// regressionHasher is a deterministic hasher (hash = "h:"+password) so the credential
// regression tests can drive exact password matches without Argon2 cost.
func regressionHasher() *hashertest.MockHasher {
	return &hashertest.MockHasher{
		HashFunc: func(_ context.Context, p string) (string, error) { return "h:" + p, nil },
		CompareFunc: func(_ context.Context, hash, p string) error {
			if hash == "h:"+p {
				return nil
			}
			return passwords.ErrInvalidPassword
		},
	}
}

func regressionService(t *testing.T, opts ...identity.ServiceOption) identity.Service {
	t.Helper()
	policy := &mockPolicy{VerifyFunc: func(_ context.Context, _ string) error { return nil }}
	return identity.NewService(identitymemory.NewStore(), regressionHasher(), policy, opts...)
}

// TestPasswordRotationEvictsRecoveryChannels pins F-IDCRED-001. A recovery channel is a
// credential: whoever enrols one can drive RequestPasswordResetViaRecovery and receive a reset
// token on it. Enrolling needs only a live session, so every credential-rotation path (not just
// ResetPassword) must evict channels enrolled before it.
func TestPasswordRotationEvictsRecoveryChannels(t *testing.T) {
	ctx := context.Background()
	const (
		victimEmail  = "rotation-victim@example.com"
		victimPass   = "V1ctim-Passw0rd!"
		attackerChan = "rotation-attacker@evil.example"
	)

	enrolAttackerChannel := func(t *testing.T, svc identity.Service) *identity.User {
		t.Helper()
		user, err := svc.Register(ctx, "", victimEmail, victimPass)
		require.NoError(t, err)
		token, err := svc.RequestRecoveryEmail(ctx, "", user.ID, attackerChan)
		require.NoError(t, err)
		_, err = svc.ConfirmRecoveryEmail(ctx, "", token)
		require.NoError(t, err)
		return user
	}

	assertNoRecoveryReset := func(t *testing.T, svc identity.Service) {
		t.Helper()
		token, _, _, err := svc.RequestPasswordResetViaRecovery(ctx, "", victimEmail)
		require.NoError(t, err)
		assert.Empty(t, token, "a password rotation must evict a recovery channel enrolled before it")
	}

	t.Run("ChangePassword", func(t *testing.T) {
		svc := regressionService(t)
		user := enrolAttackerChannel(t, svc)
		require.NoError(t, svc.ChangePassword(ctx, "", user.ID, victimPass, "N3w-V1ctim-Passw0rd!"))
		assertNoRecoveryReset(t, svc)
	})

	t.Run("SetTemporaryPassword", func(t *testing.T) {
		svc := regressionService(t)
		user := enrolAttackerChannel(t, svc)
		require.NoError(t, svc.SetTemporaryPassword(ctx, "", user.ID, "T3mp-Admin-Passw0rd!"))
		assertNoRecoveryReset(t, svc)
	})

	t.Run("ResetPassword control", func(t *testing.T) {
		svc := regressionService(t)
		_ = enrolAttackerChannel(t, svc)
		resetToken, _, err := svc.RequestPasswordReset(ctx, "", victimEmail)
		require.NoError(t, err)
		require.NoError(t, svc.ResetPassword(ctx, "", resetToken, "N3w-V1ctim-Passw0rd!"))
		assertNoRecoveryReset(t, svc)
	})
}

// TestPasswordRotationPurgesPendingVerificationTokens pins the second half of F-IDCRED-001: an
// enrollment token minted by a hijacked session (delivered to the attacker's own address) must
// not be confirmable after the victim's password rotation.
func TestPasswordRotationPurgesPendingVerificationTokens(t *testing.T) {
	ctx := context.Background()

	run := func(t *testing.T, rotate func(t *testing.T, svc identity.Service, user *identity.User)) {
		t.Helper()
		svc := regressionService(t)
		user, err := svc.Register(ctx, "", "pending-purge@example.com", "V1ctim-Passw0rd!")
		require.NoError(t, err)
		pending, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "pending-attacker@evil.example")
		require.NoError(t, err)
		rotate(t, svc, user)
		_, err = svc.ConfirmRecoveryEmail(ctx, "", pending)
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound,
			"a password rotation must revoke pending enrollment tokens")
	}

	t.Run("ChangePassword", func(t *testing.T) {
		run(t, func(t *testing.T, svc identity.Service, user *identity.User) {
			require.NoError(t, svc.ChangePassword(ctx, "", user.ID, "V1ctim-Passw0rd!", "N3w-V1ctim-Passw0rd!"))
		})
	})

	t.Run("SetTemporaryPassword", func(t *testing.T) {
		run(t, func(t *testing.T, svc identity.Service, user *identity.User) {
			require.NoError(t, svc.SetTemporaryPassword(ctx, "", user.ID, "T3mp-Admin-Passw0rd!"))
		})
	})
}

// TestResetPasswordRevokesPendingVerificationTokens pins F-IDREC-001: ResetPassword is the
// documented compromise-recovery path, so a pre-reset session must not be able to re-enrol a
// recovery channel, enrol a phone, or move the primary email after the reset.
func TestResetPasswordRevokesPendingVerificationTokens(t *testing.T) {
	ctx := context.Background()
	const (
		victimEmail = "reset-revoke@example.com"
		victimPass  = "V1ctim-Passw0rd!"
	)

	resetWith := func(t *testing.T, svc identity.Service) {
		t.Helper()
		reset, _, err := svc.RequestPasswordReset(ctx, "", victimEmail)
		require.NoError(t, err)
		require.NoError(t, svc.ResetPassword(ctx, "", reset, "Fr3sh-V1ctim-Passw0rd!"))
	}

	t.Run("recovery-email enrollment token", func(t *testing.T) {
		svc := regressionService(t)
		user, err := svc.Register(ctx, "", victimEmail, victimPass)
		require.NoError(t, err)
		pending, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "attacker@evil.example")
		require.NoError(t, err)
		resetWith(t, svc)
		_, err = svc.ConfirmRecoveryEmail(ctx, "", pending)
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)
	})

	t.Run("phone enrollment token", func(t *testing.T) {
		svc := regressionService(t)
		user, err := svc.Register(ctx, "", victimEmail, victimPass)
		require.NoError(t, err)
		pending, err := svc.RequestPhoneVerification(ctx, "", user.ID, "+15550002222")
		require.NoError(t, err)
		resetWith(t, svc)
		_, err = svc.ConfirmPhoneVerification(ctx, "", pending)
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)
	})

	t.Run("email-change token", func(t *testing.T) {
		svc := regressionService(t)
		user, err := svc.Register(ctx, "", victimEmail, victimPass)
		require.NoError(t, err)
		pending, err := svc.RequestEmailChange(ctx, "", user.ID, "attacker-primary@evil.example")
		require.NoError(t, err)
		resetWith(t, svc)
		_, err = svc.ConfirmEmailChange(ctx, "", pending)
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)
	})
}

// TestChangePasswordEnforcesLockout pins F-IDCRED-002: ChangePassword verifies the current
// password, so it must honour the brute-force lockout and feed the failed-attempt counter exactly
// like Authenticate.
func TestChangePasswordEnforcesLockout(t *testing.T) {
	ctx := context.Background()
	const threshold = 3

	t.Run("a locked account cannot change its password", func(t *testing.T) {
		svc := regressionService(t, identity.WithLockout(threshold, time.Hour))
		user, err := svc.Register(ctx, "", "locked-change@example.com", "C0rrect-Passw0rd!")
		require.NoError(t, err)

		for i := 0; i < threshold; i++ {
			_, err = svc.Authenticate(ctx, "", "password", "locked-change@example.com", "wrong")
			require.ErrorIs(t, err, identity.ErrInvalidCredentials)
		}
		_, err = svc.Authenticate(ctx, "", "password", "locked-change@example.com", "wrong")
		require.ErrorIs(t, err, identity.ErrAccountLocked, "precondition: the account is locked")

		err = svc.ChangePassword(ctx, "", user.ID, "C0rrect-Passw0rd!", "N3w-Passw0rd!")
		assert.ErrorIs(t, err, identity.ErrAccountLocked,
			"ChangePassword must refuse a locked account, exactly like Authenticate")
	})

	t.Run("wrong current-password guesses feed the lockout", func(t *testing.T) {
		svc := regressionService(t, identity.WithLockout(threshold, time.Hour))
		user, err := svc.Register(ctx, "", "guess-change@example.com", "C0rrect-Passw0rd!")
		require.NoError(t, err)

		for i := 0; i < threshold; i++ {
			err = svc.ChangePassword(ctx, "", user.ID, "wrong-guess", "N3w-Passw0rd!")
			require.ErrorIs(t, err, identity.ErrInvalidCredentials, "a wrong current password must be rejected")
		}

		_, err = svc.Authenticate(ctx, "", "password", "guess-change@example.com", "wrong")
		assert.ErrorIs(t, err, identity.ErrAccountLocked,
			"after %d wrong current-password guesses the account must be locked", threshold)
	})

	t.Run("a correct current password clears the counter", func(t *testing.T) {
		svc := regressionService(t, identity.WithLockout(threshold, time.Hour))
		user, err := svc.Register(ctx, "", "reset-change@example.com", "C0rrect-Passw0rd!")
		require.NoError(t, err)

		for i := 0; i < threshold-1; i++ {
			err = svc.ChangePassword(ctx, "", user.ID, "wrong-guess", "N3w-Passw0rd!")
			require.ErrorIs(t, err, identity.ErrInvalidCredentials)
		}
		require.NoError(t, svc.ChangePassword(ctx, "", user.ID, "C0rrect-Passw0rd!", "N3w-Passw0rd!"))

		// The successful change cleared the prior failures, so the next wrong guess does not
		// immediately lock the account.
		err = svc.ChangePassword(ctx, "", user.ID, "wrong-guess", "N3w-Passw0rd!")
		assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
	})
}

// TestWithLockoutNegativeThresholdFallsBackToDefault pins F-IDCRED-003: the documented contract
// is that a non-positive threshold means "use the safe default", and only WithNoLockout disables
// lockout.
func TestWithLockoutNegativeThresholdFallsBackToDefault(t *testing.T) {
	ctx := context.Background()
	svc := regressionService(t, identity.WithLockout(-1, time.Hour))
	_, err := svc.Register(ctx, "", "negative-lockout@example.com", "C0rrect-Passw0rd!")
	require.NoError(t, err)

	var lastErr error
	for i := 0; i < identity.DefaultLockThreshold+1; i++ {
		_, lastErr = svc.Authenticate(ctx, "", "password", "negative-lockout@example.com", "wrong")
	}
	assert.ErrorIs(t, lastErr, identity.ErrAccountLocked,
		"a non-positive threshold passed to WithLockout must fall back to the safe default, not disable lockout")
}

// TestAuthenticateNilHasherFailsClosed pins F-IDCRED-004: a nil hasher is documented as legal for
// OAuth-only deployments, and Authenticate must fail closed with ErrInvalidCredentials even when
// the store still holds a password identity, never panic.
func TestAuthenticateNilHasherFailsClosed(t *testing.T) {
	ctx := context.Background()
	store := identitymemory.NewStore()
	policy := &mockPolicy{VerifyFunc: func(_ context.Context, _ string) error { return nil }}

	withHasher := identity.NewService(store, regressionHasher(), policy)
	_, err := withHasher.Register(ctx, "", "nil-hasher@example.com", "C0rrect-Passw0rd!")
	require.NoError(t, err)

	noHasher := identity.NewService(store, nil, policy)

	var (
		gotUser *identity.User
		gotErr  error
	)
	require.NotPanics(t, func() {
		gotUser, gotErr = noHasher.Authenticate(ctx, "", "password", "nil-hasher@example.com", "C0rrect-Passw0rd!")
	}, "Authenticate with a nil hasher must fail closed, not panic")
	assert.ErrorIs(t, gotErr, identity.ErrInvalidCredentials)
	assert.Nil(t, gotUser)
}

// roundTripCountingStore records the round-trip store operations the service performs, so the
// account-existence timing symmetry of the unauthenticated Request* flows can be pinned
// deterministically (no wall-clock measurement).
type roundTripCountingStore struct {
	identity.Store
	mu    sync.Mutex
	calls []string
}

func (c *roundTripCountingStore) record(name string) {
	c.mu.Lock()
	c.calls = append(c.calls, name)
	c.mu.Unlock()
}

func (c *roundTripCountingStore) reset() {
	c.mu.Lock()
	c.calls = nil
	c.mu.Unlock()
}

func (c *roundTripCountingStore) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.calls))
	copy(out, c.calls)
	return out
}

func (c *roundTripCountingStore) FindUserByEmail(ctx context.Context, tenantID string, email string) (*identity.User, error) {
	c.record("FindUserByEmail")
	return c.Store.FindUserByEmail(ctx, tenantID, email)
}

func (c *roundTripCountingStore) FindIdentitiesByUserID(ctx context.Context, tenantID string, userID uuid.UUID) ([]*identity.Identity, error) {
	c.record("FindIdentitiesByUserID")
	return c.Store.FindIdentitiesByUserID(ctx, tenantID, userID)
}

func (c *roundTripCountingStore) CreateVerificationToken(ctx context.Context, tenantID string, userID uuid.UUID, kind string, ttl time.Duration, metadata []byte) (string, error) {
	c.record("CreateVerificationToken")
	return c.Store.CreateVerificationToken(ctx, tenantID, userID, kind, ttl, metadata)
}

func newRoundTripCountingService(t *testing.T) (identity.Service, *roundTripCountingStore) {
	t.Helper()
	store := &roundTripCountingStore{Store: identitymemory.NewStore()}
	policy := &mockPolicy{VerifyFunc: func(_ context.Context, p string) error {
		if len(p) < 8 {
			return assert.AnError
		}
		return nil
	}}
	return identity.NewService(store, regressionHasher(), policy), store
}

// TestRequestPasswordResetPerformsAccountIndependentStoreWork pins F-IDREC-002: the
// enumeration-safe RequestPasswordReset must perform the same store round trips whether or not
// the account exists; otherwise the uniform HTTP response still leaks account existence through
// response timing (the pgx backend pays a network round trip per operation).
func TestRequestPasswordResetPerformsAccountIndependentStoreWork(t *testing.T) {
	ctx := context.Background()
	svc, store := newRoundTripCountingService(t)

	const (
		known  = "known-enum@example.com"
		locked = "disabled-enum@example.com"
		oauth  = "oauth-enum@example.com"
	)

	_, err := svc.Register(ctx, "", known, "C0rrect-Passw0rd!")
	require.NoError(t, err)

	lockedUser, err := svc.Register(ctx, "", locked, "C0rrect-Passw0rd!")
	require.NoError(t, err)
	require.NoError(t, svc.DisableUser(ctx, "", lockedUser.ID))

	_, err = svc.LinkOrCreateIdentity(ctx, "", "google", "google-sub-enum", oauth, true)
	require.NoError(t, err)

	shape := func(t *testing.T, email string) []string {
		t.Helper()
		store.reset()
		token, _, err := svc.RequestPasswordReset(ctx, "", email)
		require.NoError(t, err)
		require.Empty(t, token, "no non-minting branch may return a token")
		return store.snapshot()
	}

	store.reset()
	token, _, err := svc.RequestPasswordReset(ctx, "", known)
	require.NoError(t, err)
	require.NotEmpty(t, token, "precondition: the known account mints a reset token")
	knownShape := store.snapshot()
	require.ElementsMatch(t,
		[]string{"FindUserByEmail", "FindIdentitiesByUserID", "CreateVerificationToken"}, knownShape,
		"precondition: the known-account branch performs the full minting sequence")

	assert.ElementsMatch(t, knownShape, shape(t, "unknown-enum@example.com"),
		"an unknown account must cost the same store round trips as a known one")
	assert.ElementsMatch(t, knownShape, shape(t, locked),
		"a disabled account must cost the same store round trips as a known one")
	assert.ElementsMatch(t, knownShape, shape(t, oauth),
		"an OAuth-only account (no password identity) must cost the same store round trips")
	assert.ElementsMatch(t, knownShape, shape(t, "definitely-not-an-email"),
		"a malformed address must cost the same store round trips")
}

// TestRequestMagicLinkPerformsAccountIndependentStoreWork is the magic-link sibling of F-IDREC-002.
func TestRequestMagicLinkPerformsAccountIndependentStoreWork(t *testing.T) {
	ctx := context.Background()
	svc, store := newRoundTripCountingService(t)

	const known = "known-magic@example.com"
	_, err := svc.Register(ctx, "", known, "C0rrect-Passw0rd!")
	require.NoError(t, err)

	shape := func(t *testing.T, email string) []string {
		t.Helper()
		store.reset()
		token, _, err := svc.RequestMagicLink(ctx, "", email)
		require.NoError(t, err)
		require.Empty(t, token)
		return store.snapshot()
	}

	store.reset()
	token, _, err := svc.RequestMagicLink(ctx, "", known)
	require.NoError(t, err)
	require.NotEmpty(t, token, "precondition: the known account mints a magic link")
	knownShape := store.snapshot()
	require.ElementsMatch(t, []string{"FindUserByEmail", "CreateVerificationToken"}, knownShape)

	assert.ElementsMatch(t, knownShape, shape(t, "unknown-magic@example.com"))
	assert.ElementsMatch(t, knownShape, shape(t, "definitely-not-an-email"))
}

// TestCredentialRotationInvokesEveryAccountEraser pins the identity side of F-COMP-002: every
// registered AccountEraser (the passkey eraser is shipped by another stream) must run on every
// credential-rotation and account-deletion path, so recovery evicts the credentials those
// erasers own.
func TestCredentialRotationInvokesEveryAccountEraser(t *testing.T) {
	ctx := context.Background()

	// run rotates/deletes a fresh account through call and asserts that every one of the three
	// registered erasers observed exactly one invocation for that account.
	run := func(t *testing.T, call func(t *testing.T, svc identity.Service, user *identity.User)) {
		t.Helper()
		var (
			mu        sync.Mutex
			invokedBy = map[int]int{}
		)
		ers := make([]identity.AccountEraser, 3)
		for i := range ers {
			i := i
			ers[i] = func(_ context.Context, tenantID string, userID uuid.UUID) error {
				mu.Lock()
				defer mu.Unlock()
				invokedBy[i]++
				assert.Equal(t, "", tenantID)
				return nil
			}
		}
		svc := regressionService(t, identity.WithAccountErasers(ers...))
		user, err := svc.Register(ctx, "", "eraser-regression@example.com", "C0rrect-Passw0rd!")
		require.NoError(t, err)
		call(t, svc, user)
		mu.Lock()
		defer mu.Unlock()
		for i := range ers {
			assert.Equal(t, 1, invokedBy[i], "eraser #%d must be invoked exactly once", i)
		}
	}

	t.Run("ChangePassword", func(t *testing.T) {
		run(t, func(t *testing.T, svc identity.Service, user *identity.User) {
			require.NoError(t, svc.ChangePassword(ctx, "", user.ID, "C0rrect-Passw0rd!", "N3w-Passw0rd!"))
		})
	})
	t.Run("SetTemporaryPassword", func(t *testing.T) {
		run(t, func(t *testing.T, svc identity.Service, user *identity.User) {
			require.NoError(t, svc.SetTemporaryPassword(ctx, "", user.ID, "T3mp-Passw0rd!"))
		})
	})
	t.Run("ResetPassword", func(t *testing.T) {
		run(t, func(t *testing.T, svc identity.Service, user *identity.User) {
			token, _, err := svc.RequestPasswordReset(ctx, "", "eraser-regression@example.com")
			require.NoError(t, err)
			require.NoError(t, svc.ResetPassword(ctx, "", token, "N3w-Passw0rd!"))
		})
	})
	t.Run("DeleteAccount", func(t *testing.T) {
		run(t, func(t *testing.T, svc identity.Service, user *identity.User) {
			require.NoError(t, svc.DeleteAccount(ctx, "", user.ID))
		})
	})
}
