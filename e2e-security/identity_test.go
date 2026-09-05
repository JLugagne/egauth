package e2esecurity_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/JLugagne/egauth/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecurity_SEC_ID_01_PreAuth_Argon2id_DoS verifies that ResetPassword and Register
// do NOT execute the computationally heavy password hashing before verifying the existence
// or validity of the token or the uniqueness of the email address.
func TestSecurity_SEC_ID_01_PreAuth_Argon2id_DoS(t *testing.T) {
	ctx := context.Background()

	var hashCount int
	hasher := &hashertest.MockHasher{
		HashFunc: func(ctx context.Context, p string) (string, error) {
			hashCount++
			return "argon2_simulated_hash_" + p, nil
		},
		CompareFunc: func(ctx context.Context, hash, p string) error {
			return nil
		},
	}
	pwPolicy := policy.NewDefaultPolicy()
	store := identitymemory.NewStore()
	svc := identity.NewService(store, hasher, pwPolicy)

	t.Run("ResetPassword does not hash when token is invalid or does not exist", func(t *testing.T) {
		hashCount = 0
		invalidToken := "completely-bogus-token-123456"

		// Attacker sends a request with an invalid token and a policy-compliant password
		err := svc.ResetPassword(ctx, "", invalidToken, "ValidP@ssw0rd2026!")

		// The operation fails because the token does not exist
		assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)

		// SEC-ID-01 fixed: Hasher is not invoked on invalid tokens, preventing pre-auth DoS
		assert.Equal(t, 0, hashCount, "SEC-ID-01 fixed: expensive Hash must not be performed on invalid token")
	})

	t.Run("Register does not hash when email already exists", func(t *testing.T) {
		// First registration succeeds
		_, err := svc.Register(ctx, "", "existing@example.com", "ValidP@ssw0rd2026!")
		require.NoError(t, err)

		hashCount = 0
		// Attacker attempts to register the same email address again
		_, err = svc.Register(ctx, "", "existing@example.com", "ValidP@ssw0rd2026!")

		// Registration fails with email collision
		assert.ErrorIs(t, err, identity.ErrEmailAlreadyExists)

		// SEC-ID-01 fixed: Hasher is not invoked on duplicate email, preventing pre-auth DoS
		assert.Equal(t, 0, hashCount, "SEC-ID-01 fixed: expensive Hash must not be performed before checking email uniqueness")
	})
}

// TestSecurity_SEC_ID_06_TokenBucket_Unbounded_Memory_DoS verifies that TokenBucket
// enforces a bounded default capacity (DefaultMaxKeys) and eviction to prevent unbounded memory DoS.
func TestSecurity_SEC_ID_06_TokenBucket_Unbounded_Memory_DoS(t *testing.T) {
	ctx := context.Background()

	// Create default TokenBucket without WithMaxKeys option
	tb := ratelimit.NewTokenBucket(5, time.Minute)
	assert.Equal(t, 0, tb.KeyCount())
	assert.Equal(t, ratelimit.DefaultMaxKeys, tb.MaxKeys(), "SEC-ID-06 fixed: default TokenBucket enforces bounded DefaultMaxKeys")

	// Verify that bucket capacity is strictly capped at maxKeys and evicts excess keys
	const capLimit = 100
	tbBounded := ratelimit.NewTokenBucket(5, time.Minute, ratelimit.WithMaxKeys(capLimit))
	const floodCount = 250
	for i := 0; i < floodCount; i++ {
		key := fmt.Sprintf("spoofed-ip-10.0.%d.%d", i/256, i%256)
		allowed, _ := tbBounded.Allow(ctx, key)
		assert.True(t, allowed)
	}

	assert.Equal(t, capLimit, tbBounded.KeyCount(), "SEC-ID-06 fixed: keys do not grow unboundedly and stay capped at maxKeys")
}

// TestSecurity_SEC_ID_05_TokenBucket_Eviction_Bypass demonstrates that when WithMaxKeys
// is enabled, evictOne can evict completely exhausted (rate-limited) buckets, allowing
// the rate-limited client to immediately regain full burst capacity.
func TestSecurity_SEC_ID_05_TokenBucket_Eviction_Bypass(t *testing.T) {
	ctx := context.Background()

	// Limiter with burst 1, refill 1 hour, maxKeys 3
	tb := ratelimit.NewTokenBucket(1, time.Hour, ratelimit.WithMaxKeys(3))
	targetKey := "attacker-ip"

	// Step 1: Attacker uses their quota
	allowed, _ := tb.Allow(ctx, targetKey)
	require.True(t, allowed)

	// Step 2: Attacker is now rate-limited
	allowed, wait := tb.Allow(ctx, targetKey)
	require.False(t, allowed)
	require.Greater(t, wait, time.Minute)

	// Step 3: Attacker floods the limiter with other keys to trigger eviction
	for i := 0; i < 20; i++ {
		tb.Allow(ctx, fmt.Sprintf("flood-%d", i))
	}

	// Step 4: Because evictOne selects candidate with toks > -1, an exhausted key (tokens=0)
	// can be evicted. Once evicted, requesting targetKey again instantiates a fresh bucket!
	allowedAfterEviction, _ := tb.Allow(ctx, targetKey)
	assert.True(t, allowedAfterEviction, "SEC-ID-05 confirmed: exhausted key regained full burst tokens following eviction")
}

// TestSecurity_SEC_ID_07_Silent_Delivery_Drop_On_Semaphore_Saturation verifies that
// when the delivery semaphore is saturated, delivery is not silently dropped with a fake 204.
// Instead, the handler returns HTTP 429 Too Many Requests (service_busy) and emits a DeliveryFailed
// event, alerting callers that the delivery could not be scheduled.
func TestSecurity_SEC_ID_07_Silent_Delivery_Drop_On_Semaphore_Saturation(t *testing.T) {
	ctx := context.Background()

	var events []event.Event
	var eventsMu sync.Mutex
	sink := event.SinkFunc(func(ctx context.Context, e event.Event) {
		eventsMu.Lock()
		events = append(events, e)
		eventsMu.Unlock()
	})

	deliveryStarted := make(chan struct{}, 1)
	deliveryBlock := make(chan struct{})

	mailer := identity.Mailer{
		PasswordReset: func(ctx context.Context, mail identity.PasswordResetMail) error {
			select {
			case deliveryStarted <- struct{}{}:
			default:
			}
			<-deliveryBlock // simulate slow backend (e.g. SMTP latency)
			return nil
		},
	}

	hasher := &hashertest.MockHasher{
		HashFunc: func(ctx context.Context, p string) (string, error) { return "hash", nil },
	}
	pwPolicy := policy.NewDefaultPolicy()
	store := identitymemory.NewStore()
	svc := identity.NewService(store, hasher, pwPolicy)

	// Register valid victim account
	_, err := svc.Register(ctx, "", "victim@example.com", "ValidP@ssw0rd2026!")
	require.NoError(t, err)

	// Handler configured with semaphore capacity = 1
	handler := identity.RequestPasswordResetHandler(
		svc,
		mailer,
		identity.WithDeliveryConcurrency(1),
		identity.WithHandlerEventSink(sink),
		identity.WithInsecureNoOriginCheck(),
	)

	// Request 1: Acquires the 1 delivery slot and starts delivery
	body1 := url.Values{"email": []string{"victim@example.com"}}
	req1 := httptest.NewRequest(http.MethodPost, "/password-reset/request", strings.NewReader(body1.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusNoContent, rec1.Code)

	// Wait for the delivery worker to be holding the slot
	select {
	case <-deliveryStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for delivery worker to start")
	}

	// Request 2: Semaphore is full (1/1 in use). dispatchDelivery drops the delivery and returns 429.
	body2 := url.Values{"email": []string{"victim@example.com"}}
	req2 := httptest.NewRequest(http.MethodPost, "/password-reset/request", strings.NewReader(body2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	// SEC-ID-07 fixed: Client receives HTTP 429 Too Many Requests (service_busy), not false 204 No Content.
	assert.Equal(t, http.StatusTooManyRequests, rec2.Code, "SEC-ID-07 fixed: saturated delivery queue returns HTTP 429")
	assert.Contains(t, rec2.Body.String(), "service_busy")

	// Unblock delivery worker
	close(deliveryBlock)

	// Verify that an ErrDeliveryDropped was recorded in the event sink
	eventsMu.Lock()
	var droppedFound bool
	for _, e := range events {
		if e.Type == event.DeliveryFailed && errors.Is(e.Err, identity.ErrDeliveryDropped) {
			droppedFound = true
			break
		}
	}
	eventsMu.Unlock()
	assert.True(t, droppedFound, "SEC-ID-07 confirmed: delivery failure was recorded with ErrDeliveryDropped")
}

// TestSecurity_SEC_ID_09_ChangePassword_On_Suspended_And_Deleted_Accounts verifies that
// ChangePassword and ChangePasswordHandler reject password changes when the target account
// is administratively disabled or soft-deleted.
func TestSecurity_SEC_ID_09_ChangePassword_On_Suspended_And_Deleted_Accounts(t *testing.T) {
	ctx := context.Background()

	hasher := &hashertest.MockHasher{
		HashFunc: func(ctx context.Context, p string) (string, error) {
			return "hashed_" + p, nil
		},
		CompareFunc: func(ctx context.Context, hash, p string) error {
			if hash == "hashed_"+p {
				return nil
			}
			return passwords.ErrInvalidPassword
		},
	}
	pwPolicy := policy.NewDefaultPolicy()
	store := identitymemory.NewStore()
	svc := identity.NewService(store, hasher, pwPolicy)

	t.Run("ChangePassword fails on administratively disabled user", func(t *testing.T) {
		user, err := svc.Register(ctx, "", "suspended@example.com", "OldPassword123!")
		require.NoError(t, err)

		// Administrator suspends the user
		err = svc.DisableUser(ctx, "", user.ID)
		require.NoError(t, err)

		// Normal authentication is blocked
		_, err = svc.Authenticate(ctx, "", "password", "suspended@example.com", "OldPassword123!")
		assert.ErrorIs(t, err, identity.ErrAccountDisabled)

		// ChangePassword rejects disabled user with ErrAccountDisabled
		err = svc.ChangePassword(ctx, "", user.ID, "OldPassword123!", "NewPassword123!")
		assert.ErrorIs(t, err, identity.ErrAccountDisabled, "SEC-ID-09: ChangePassword must reject disabled user")

		// In HTTP handler: ChangePasswordHandler also fails with 403 Forbidden
		req := httptest.NewRequest(http.MethodPost, "/password/change", strings.NewReader(url.Values{
			"current_password": []string{"OldPassword123!"},
			"new_password":     []string{"BrandNewPassword123!"},
		}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		handler := identity.ChangePasswordHandler(svc,
			identity.WithUserResolver(func(r *http.Request) (*identity.User, bool) {
				return user, true
			}),
			identity.WithInsecureNoOriginCheck(),
		)
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "SEC-ID-09: HTTP handler must reject password change for disabled user")
	})

	t.Run("ChangePassword fails on soft-deleted user", func(t *testing.T) {
		user, err := svc.Register(ctx, "", "deleted@example.com", "OldPassword123!")
		require.NoError(t, err)

		// Account is soft-deleted
		err = store.DeleteUser(ctx, "", user.ID)
		require.NoError(t, err)

		// ChangePassword rejects soft-deleted user with ErrAccountDisabled
		err = svc.ChangePassword(ctx, "", user.ID, "OldPassword123!", "NewPassword123!")
		assert.ErrorIs(t, err, identity.ErrAccountDisabled, "SEC-ID-09: ChangePassword must reject soft-deleted user")
	})
}

// TestSecurity_SEC_ID_10_Persistent_Failed_Attempts_No_TTL verifies that stale failed login
// attempts decay after the sliding window (lockDuration) elapses, preventing an attacker
// from priming an account so that a subsequent single user typo triggers a lockout.
func TestSecurity_SEC_ID_10_Persistent_Failed_Attempts_No_TTL(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	store := identitymemory.NewStore(identitymemory.WithClock(func() time.Time { return now }))
	hasher := &hashertest.MockHasher{
		HashFunc: func(ctx context.Context, p string) (string, error) { return "hash_" + p, nil },
	}
	pwPolicy := policy.NewDefaultPolicy()
	svc := identity.NewService(store, hasher, pwPolicy)

	user, err := svc.Register(ctx, "", "target@example.com", "TargetPassword123!")
	require.NoError(t, err)

	idents, err := store.FindIdentitiesByUserID(ctx, "", user.ID)
	require.NoError(t, err)
	require.NotEmpty(t, idents)
	pwIdent := idents[0]

	const lockThreshold = 5
	const lockDuration = 15 * time.Minute

	// Attacker sends 4 failed attempts (just below the threshold of 5)
	for i := 0; i < 4; i++ {
		justLocked, err := store.IncrementFailedAttempts(ctx, "", pwIdent.ID, lockThreshold, lockDuration)
		require.NoError(t, err)
		assert.False(t, justLocked)
	}

	// Counter is at 4 attempts within the window
	identsAfter, err := store.FindIdentitiesByUserID(ctx, "", user.ID)
	require.NoError(t, err)
	assert.Equal(t, 4, identsAfter[0].FailedAttempts)
	assert.Nil(t, identsAfter[0].LockedUntil)

	// Long time passes (sliding window elapses)
	now = now.Add(lockDuration + time.Second)

	// Legitimate user makes a single typo:
	justLocked, err := store.IncrementFailedAttempts(ctx, "", pwIdent.ID, lockThreshold, lockDuration)
	require.NoError(t, err)

	// Stale failed attempts decayed: the single typo resets the counter to 1 and does NOT lock the account.
	assert.False(t, justLocked, "account must not be locked after sliding window has elapsed")

	identsLocked, err := store.FindIdentitiesByUserID(ctx, "", user.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, identsLocked[0].FailedAttempts, "failed attempts counter must reset to 1 after sliding window")
	assert.Nil(t, identsLocked[0].LockedUntil, "account must remain unlocked")
}

// TestSecurity_SEC_ID_11_Timing_Oracle_Discrepancy shows that RequestPasswordReset
// performs token generation and persistence for existing accounts, while returning early for non-existing accounts.
func TestSecurity_SEC_ID_11_Timing_Oracle_Discrepancy(t *testing.T) {
	ctx := context.Background()

	hasher := &hashertest.MockHasher{
		HashFunc: func(ctx context.Context, p string) (string, error) { return "hash", nil },
	}
	pwPolicy := policy.NewDefaultPolicy()
	store := identitymemory.NewStore()
	svc := identity.NewService(store, hasher, pwPolicy)

	// Register existing user
	_, err := svc.Register(ctx, "", "existing@example.com", "Password123!")
	require.NoError(t, err)

	// Request for non-existent user returns immediately without minting a token
	tokNonExistent, uNonExistent, err := svc.RequestPasswordReset(ctx, "", "does-not-exist@example.com")
	require.NoError(t, err)
	assert.Empty(t, tokNonExistent)
	assert.Nil(t, uNonExistent)

	// Request for existing user executes token generation and database writes
	tokExisting, uExisting, err := svc.RequestPasswordReset(ctx, "", "existing@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, tokExisting)
	assert.NotNil(t, uExisting)
}

// TestSecurity_SEC_ID_13_Incomplete_PII_Anonymization_On_DeleteUser demonstrates that
// DeleteUser leaves Phone and RecoveryEmail unredacted in the database record.
func TestSecurity_SEC_ID_13_Incomplete_PII_Anonymization_On_DeleteUser(t *testing.T) {
	ctx := context.Background()

	hasher := &hashertest.MockHasher{
		HashFunc: func(ctx context.Context, p string) (string, error) { return "hash", nil },
	}
	pwPolicy := policy.NewDefaultPolicy()
	store := identitymemory.NewStore()
	svc := identity.NewService(store, hasher, pwPolicy)

	user, err := svc.Register(ctx, "", "user.to.delete@example.com", "Password123!")
	require.NoError(t, err)

	phone := "+33612345678"
	recEmail := "recovery.person@example.com"
	err = store.UpdateUserPhone(ctx, "", user.ID, phone, time.Now())
	require.NoError(t, err)
	err = store.UpdateUserRecoveryEmail(ctx, "", user.ID, recEmail, time.Now())
	require.NoError(t, err)

	// User requests account deletion (GDPR right to erasure)
	err = store.DeleteUser(ctx, "", user.ID)
	require.NoError(t, err)

	// Retrieve user record directly from store
	storedUser, err := store.FindUserByID(ctx, "", user.ID)
	require.NoError(t, err)
	assert.NotNil(t, storedUser.DeletedAt)

	// Primary email was anonymized
	assert.NotEqual(t, "user.to.delete@example.com", storedUser.Email)

	// FLAW: Sensitive PII (Phone and RecoveryEmail) were NOT anonymized or cleared!
	assert.NotNil(t, storedUser.Phone, "SEC-ID-13 confirmed: Phone is retained after deletion")
	assert.Equal(t, phone, *storedUser.Phone)
	assert.NotNil(t, storedUser.RecoveryEmail, "SEC-ID-13 confirmed: RecoveryEmail is retained after deletion")
	assert.Equal(t, recEmail, *storedUser.RecoveryEmail)
}

// TestSecurity_SEC_ID_14_Default_Password_Policy_Allows_Breached_Passwords verifies that
// DefaultPolicy enforces legacy character complexity while accepting notorious dictionary passwords.
func TestSecurity_SEC_ID_14_Default_Password_Policy_Allows_Breached_Passwords(t *testing.T) {
	ctx := context.Background()
	defaultPolicy := policy.NewDefaultPolicy()

	// Well-known breached / dictionary passwords that pass composition rules:
	notoriousPasswords := []string{
		"Password123!",
		"Admin2024!",
		"Welcome1!",
		"Summer2026!",
		"P@ssword1",
	}

	for _, pass := range notoriousPasswords {
		err := defaultPolicy.Verify(ctx, pass)
		// FLAW: DefaultPolicy accepts these notorious passwords because it has no breach checker
		assert.NoError(t, err, "SEC-ID-14 confirmed: DefaultPolicy accepted known weak password %q", pass)
	}
}
