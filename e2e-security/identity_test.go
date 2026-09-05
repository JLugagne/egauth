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

// TestSecurity_SEC_ID_06_TokenBucket_Unbounded_Memory_DoS demonstrates that TokenBucket
// defaults to maxKeys=0 (unbounded), meaning every new key (e.g. forged IP or email)
// permanently grows the memory map without any automatic eviction.
func TestSecurity_SEC_ID_06_TokenBucket_Unbounded_Memory_DoS(t *testing.T) {
	ctx := context.Background()

	// Create default TokenBucket without WithMaxKeys option
	tb := ratelimit.NewTokenBucket(5, time.Minute)
	assert.Equal(t, 0, tb.KeyCount())

	// Attacker generates 500 requests with distinct spoofed keys
	const floodCount = 500
	for i := 0; i < floodCount; i++ {
		key := fmt.Sprintf("spoofed-ip-10.0.%d.%d", i/256, i%256)
		allowed, _ := tb.Allow(ctx, key)
		assert.True(t, allowed)
	}

	// Memory grows unboundedly: all 500 keys are retained
	assert.Equal(t, floodCount, tb.KeyCount(), "SEC-ID-06 confirmed: all keys are retained in memory")

	// Cleanup does not evict them because they have not fully refilled (burst is 5, consumed 1 -> tokens=4 < 5)
	cleaned := tb.Cleanup()
	assert.Equal(t, 0, cleaned)
	assert.Equal(t, floodCount, tb.KeyCount(), "SEC-ID-06 confirmed: keys remain indefinitely under attack")
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

// TestSecurity_SEC_ID_07_Silent_Delivery_Drop_On_Semaphore_Saturation confirms that
// when the delivery semaphore is saturated, delivery is dropped silently and the
// HTTP handler still returns 204 No Content to the user.
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

	// Request 2: Semaphore is full (1/1 in use). dispatchDelivery drops the delivery.
	body2 := url.Values{"email": []string{"victim@example.com"}}
	req2 := httptest.NewRequest(http.MethodPost, "/password-reset/request", strings.NewReader(body2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	// FLAW: Client receives HTTP 204 No Content (believes email was sent), but delivery was silently dropped!
	assert.Equal(t, http.StatusNoContent, rec2.Code)

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
	assert.True(t, droppedFound, "SEC-ID-07 confirmed: delivery was dropped silently with ErrDeliveryDropped")
}

// TestSecurity_SEC_ID_09_ChangePassword_On_Suspended_And_Deleted_Accounts proves that
// ChangePassword succeeds even when the target account is administratively disabled or soft-deleted.
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

	t.Run("ChangePassword succeeds on administratively disabled user", func(t *testing.T) {
		user, err := svc.Register(ctx, "", "suspended@example.com", "OldPassword123!")
		require.NoError(t, err)

		// Administrator suspends the user
		err = svc.DisableUser(ctx, "", user.ID)
		require.NoError(t, err)

		// Normal authentication is blocked
		_, err = svc.Authenticate(ctx, "", "password", "suspended@example.com", "OldPassword123!")
		assert.ErrorIs(t, err, identity.ErrAccountDisabled)

		// FLAW: ChangePassword ignores DisabledAt and succeeds!
		err = svc.ChangePassword(ctx, "", user.ID, "OldPassword123!", "NewPassword123!")
		assert.NoError(t, err, "SEC-ID-09 confirmed: ChangePassword succeeded on disabled user")

		// In HTTP handler: ChangePasswordHandler also succeeds
		req := httptest.NewRequest(http.MethodPost, "/password/change", strings.NewReader(url.Values{
			"current_password": []string{"NewPassword123!"},
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
		assert.Equal(t, http.StatusNoContent, rec.Code, "SEC-ID-09 confirmed: HTTP handler allowed password change for disabled user")
	})

	t.Run("ChangePassword succeeds on soft-deleted user", func(t *testing.T) {
		user, err := svc.Register(ctx, "", "deleted@example.com", "OldPassword123!")
		require.NoError(t, err)

		// Account is soft-deleted
		err = store.DeleteUser(ctx, "", user.ID)
		require.NoError(t, err)

		// FLAW: ChangePassword does not check DeletedAt and succeeds!
		err = svc.ChangePassword(ctx, "", user.ID, "OldPassword123!", "NewPassword123!")
		assert.NoError(t, err, "SEC-ID-09 confirmed: ChangePassword succeeded on soft-deleted user")
	})
}

// TestSecurity_SEC_ID_10_Persistent_Failed_Attempts_No_TTL verifies that failed login
// attempts persist indefinitely without any TTL or sliding window, allowing an attacker
// to prime an account so a single user typo triggers a lockout.
func TestSecurity_SEC_ID_10_Persistent_Failed_Attempts_No_TTL(t *testing.T) {
	ctx := context.Background()

	store := identitymemory.NewStore()
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

	// Counter stays permanently at 4
	identsAfter, err := store.FindIdentitiesByUserID(ctx, "", user.ID)
	require.NoError(t, err)
	assert.Equal(t, 4, identsAfter[0].FailedAttempts)
	assert.Nil(t, identsAfter[0].LockedUntil)

	// Long time passes in real life (no TTL exists on failed_attempts).
	// Legitimate user makes a single typo:
	justLocked, err := store.IncrementFailedAttempts(ctx, "", pwIdent.ID, lockThreshold, lockDuration)
	require.NoError(t, err)

	// FLAW: The account is now immediately locked because stale attempts never decayed!
	assert.True(t, justLocked, "SEC-ID-10 confirmed: account was locked on user's single attempt due to lack of failed attempts TTL")

	identsLocked, err := store.FindIdentitiesByUserID(ctx, "", user.ID)
	require.NoError(t, err)
	assert.NotNil(t, identsLocked[0].LockedUntil, "Account is locked")
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
