package e2esecurity_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	pgxpasskey "github.com/JLugagne/egauth/adapters/pgx/passkey"
	"github.com/JLugagne/egauth/mfa"
	mfamemory "github.com/JLugagne/egauth/mfa/memory"
	"github.com/JLugagne/egauth/otp"
	otpmemory "github.com/JLugagne/egauth/otp/memory"
	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/JLugagne/egauth/passkey/passkeytest"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSEC_MFA_05_SharedLockout_TOTP_Exhaustion_Blocks_RecoveryCodes confirms that an attacker
// who exhausts failed TOTP attempts on a victim's account inadvertently (or maliciously) causes a
// Denial of Service on the victim's valid, high-entropy recovery codes.
//
// Root cause: In mfa.Service.VerifyRecoveryCode, the recovery verification is gated against the TOTP
// attempt counter (s.reserveAttempt). When failed attempts >= maxAttempts, VerifyRecoveryCode returns
// ErrTooManyAttempts before even inspecting or consuming the submitted recovery code.
func TestSEC_MFA_05_SharedLockout_TOTP_Exhaustion_Blocks_RecoveryCodes(t *testing.T) {
	ctx := context.Background()
	store := mfamemory.NewStore()
	clkTime := time.Unix(1_700_000_000, 0)
	svc := mfa.NewService(store, mfa.WithClock(func() time.Time { return clkTime }), mfa.WithMaxAttempts(5))

	tenant := "tenant-sec-05"
	uid := uuid.Must(uuid.NewV7())

	// 1. Legitimate user enrolls and confirms TOTP.
	enrollment, err := svc.EnrollTOTP(ctx, tenant, uid, "victim@example.com")
	require.NoError(t, err)

	confirmCode, err := mfa.GenerateCode(enrollment.Secret, clkTime, mfa.DefaultDigits, mfa.DefaultPeriod)
	require.NoError(t, err)

	recoveryCodes, err := svc.ConfirmTOTP(ctx, tenant, uid, confirmCode)
	require.NoError(t, err)
	require.NotEmpty(t, recoveryCodes)
	validRecoveryCode := recoveryCodes[0]

	// Advance clock so the confirm code cannot be replayed.
	clkTime = clkTime.Add(mfa.DefaultPeriod)

	// 2. Attacker submits 5 wrong TOTP guesses to exhaust the attempt budget.
	for i := 0; i < 5; i++ {
		err := svc.VerifyTOTP(ctx, tenant, uid, "000000")
		if i < 4 {
			assert.ErrorIs(t, err, mfa.ErrInvalidCode)
		} else {
			assert.ErrorIs(t, err, mfa.ErrTooManyAttempts)
		}
	}

	// 3. Legitimate user (who may have lost their phone) tries to log in using their valid recovery code.
	// In the remediated implementation, recovery code verification has its own isolated attempt budget.
	// Even though TOTP attempts are exhausted, verifying a valid recovery code succeeds.
	err = svc.VerifyRecoveryCode(ctx, tenant, uid, validRecoveryCode)
	require.NoError(t, err, "valid recovery code must succeed even after TOTP attempts are exhausted")
}

// failingRecoveryStore proxies mfa.Store but injects a failure during ReplaceRecoveryCodes or ConfirmEnrollment.
type failingRecoveryStore struct {
	mfa.Store
	failReplace bool
}

func (s *failingRecoveryStore) ReplaceRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID, codeHashes []string) error {
	if s.failReplace {
		return errors.New("simulated database disconnect during recovery codes persistence")
	}
	return s.Store.ReplaceRecoveryCodes(ctx, tenantID, userID, codeHashes)
}

func (s *failingRecoveryStore) ConfirmEnrollment(ctx context.Context, tenantID string, enrollment *mfa.TOTPEnrollment, codeHashes []string) error {
	if s.failReplace {
		return errors.New("simulated database disconnect during recovery codes persistence")
	}
	return s.Store.ConfirmEnrollment(ctx, tenantID, enrollment, codeHashes)
}

// TestSEC_MFA_06_ConfirmTOTP_NonAtomic_RecoveryCodesLost verifies that ConfirmTOTP is atomic:
// if recovery codes persistence fails, TOTP must not be left confirmed, and retrying ConfirmTOTP
// succeeds once persistence is restored (SEC-MFA-06).
func TestSEC_MFA_06_ConfirmTOTP_NonAtomic_RecoveryCodesLost(t *testing.T) {
	ctx := context.Background()
	baseStore := mfamemory.NewStore()
	store := &failingRecoveryStore{Store: baseStore}
	clkTime := time.Unix(1_700_000_000, 0)
	svc := mfa.NewService(store, mfa.WithClock(func() time.Time { return clkTime }))

	tenant := "tenant-sec-06"
	uid := uuid.Must(uuid.NewV7())

	// 1. User enrolls.
	enrollment, err := svc.EnrollTOTP(ctx, tenant, uid, "user@example.com")
	require.NoError(t, err)

	confirmCode, err := mfa.GenerateCode(enrollment.Secret, clkTime, mfa.DefaultDigits, mfa.DefaultPeriod)
	require.NoError(t, err)

	// 2. Simulate database failure when persisting recovery codes.
	store.failReplace = true

	// 3. User attempts to confirm TOTP.
	codes, err := svc.ConfirmTOTP(ctx, tenant, uid, confirmCode)
	assert.Error(t, err)
	assert.Nil(t, codes)
	assert.Contains(t, err.Error(), "simulated database disconnect")

	// 4. Verify the database state: TOTP must NOT be confirmed!
	storedEnrollment, err := store.GetTOTP(ctx, tenant, uid)
	require.NoError(t, err)
	assert.False(t, storedEnrollment.Confirmed(), "SEC-MFA-06 Fixed: TOTP must not be left confirmed if recovery codes failed to persist")
	assert.Nil(t, storedEnrollment.ConfirmedAt)

	// 5. Restore database connectivity and retry ConfirmTOTP:
	store.failReplace = false

	retryCodes, err := svc.ConfirmTOTP(ctx, tenant, uid, confirmCode)
	require.NoError(t, err, "SEC-MFA-06 Fixed: Retry must succeed once persistence is restored")
	require.NotEmpty(t, retryCodes)

	// 6. Verify enrollment is now confirmed and recovery codes exist:
	storedEnrollment, err = store.GetTOTP(ctx, tenant, uid)
	require.NoError(t, err)
	assert.True(t, storedEnrollment.Confirmed(), "TOTP is confirmed after successful retry")
	assert.NotNil(t, storedEnrollment.ConfirmedAt)

	err = svc.VerifyRecoveryCode(ctx, tenant, uid, retryCodes[0])
	require.NoError(t, err, "User can authenticate with minted recovery code")
}

// TestSEC_OTP_02_AsyncIssue_RaceCondition_And_SilentDrop verifies:
//  1. Synchronous OTP issuance ensures immediate verification succeeds even while out-of-band
//     delivery is still in-flight/blocked.
//  2. When delivery concurrency semaphore is saturated, delivery is dropped but the OTP challenge
//     remains persisted in the database, so verification does not fail with ErrCodeNotFound.
func TestSEC_OTP_02_AsyncIssue_RaceCondition_And_SilentDrop(t *testing.T) {
	t.Run("RaceCondition_VerificationBeforeIssuePersists", func(t *testing.T) {
		store := otpmemory.NewStore()
		svc := otp.NewService(store)
		subject := uuid.Must(uuid.NewV7())
		purpose := "login"

		deliveryStarted := make(chan struct{})
		deliveryRelease := make(chan struct{})
		var deliveredCode string

		// Custom deliver that holds execution to demonstrate delivery is decoupled from persistence
		deliver := func(ctx context.Context, ch *otp.Challenge) error {
			deliveredCode = ch.Code
			close(deliveryStarted)
			<-deliveryRelease
			return nil
		}

		issueH := otp.IssueHandler(
			svc,
			deliver,
			otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) { return subject, true }),
			otp.WithPurpose(purpose),
		)

		verifyH := otp.VerifyHandler(
			svc,
			otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) { return subject, true }),
			otp.WithPurpose(purpose),
		)

		// Client sends POST to issue OTP.
		issueRec := httptest.NewRecorder()
		issueReq := httptest.NewRequest(http.MethodPost, "/otp/issue", nil)
		issueReq.Header.Set("Origin", "https://"+issueReq.Host)
		issueH.ServeHTTP(issueRec, issueReq)

		// IssueHandler has returned HTTP 204 No Content to the client!
		assert.Equal(t, http.StatusNoContent, issueRec.Code)

		// Synchronous persistence: the challenge MUST be in the store immediately upon 204,
		// before delivery is even dispatched/run.
		storedOTP, err := store.GetOTP(context.Background(), "", subject, purpose)
		require.NoError(t, err, "OTP challenge must be synchronously saved in the store before HTTP 204 is returned")
		require.NotNil(t, storedOTP)

		// Wait until delivery goroutine has started and received the challenge
		<-deliveryStarted

		// Delivery is still pending / in-flight!
		// Verify immediately with the issued code.
		verifyRec := httptest.NewRecorder()
		verifyForm := url.Values{"code": {deliveredCode}}
		verifyReq := httptest.NewRequest(http.MethodPost, "/otp/verify", strings.NewReader(verifyForm.Encode()))
		verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		verifyReq.Header.Set("Origin", "https://"+verifyReq.Host)

		verifyH.ServeHTTP(verifyRec, verifyReq)

		assert.Equal(t, http.StatusNoContent, verifyRec.Code,
			"Immediate verify succeeds because OTP persistence completed synchronously before HTTP response")

		// Release delivery goroutine
		close(deliveryRelease)
	})

	t.Run("SilentDrop_UnderSemaphoreSaturation", func(t *testing.T) {
		store := otpmemory.NewStore()
		svc := otp.NewService(store)
		subject1 := uuid.Must(uuid.NewV7())
		subject2 := uuid.Must(uuid.NewV7())
		purpose := "login"

		blockDelivery := make(chan struct{})
		deliveryStarted := make(chan struct{}, 1)

		deliver := func(ctx context.Context, ch *otp.Challenge) error {
			select {
			case deliveryStarted <- struct{}{}:
			default:
			}
			<-blockDelivery
			return nil
		}

		// Concurrency cap = 1
		h := otp.IssueHandler(
			svc,
			deliver,
			otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) {
				if r.Header.Get("X-Subject") == "2" {
					return subject2, true
				}
				return subject1, true
			}),
			otp.WithPurpose(purpose),
			otp.WithMaxConcurrentDeliveries(1),
		)

		// Request 1 acquires the single semaphore slot and holds it.
		req1 := httptest.NewRequest(http.MethodPost, "/otp/issue", nil)
		req1.Header.Set("Origin", "https://"+req1.Host)
		rec1 := httptest.NewRecorder()
		h.ServeHTTP(rec1, req1)
		assert.Equal(t, http.StatusNoContent, rec1.Code)

		<-deliveryStarted // ensure delivery 1 has acquired slot and is blocked

		// Request 2 arrives while delivery 1 holds the slot.
		req2 := httptest.NewRequest(http.MethodPost, "/otp/issue", nil)
		req2.Header.Set("Origin", "https://"+req2.Host)
		req2.Header.Set("X-Subject", "2")
		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, req2)

		// IssueHandler returns HTTP 204 No Content to caller 2!
		assert.Equal(t, http.StatusNoContent, rec2.Code)

		// Release blocked delivery 1
		close(blockDelivery)

		// Verify subject 2: OTP was generated and saved in the database even though delivery was dropped.
		// Verifying with any code must NOT return otp.ErrCodeNotFound.
		err := svc.Verify(context.Background(), "", subject2, purpose, "000000")
		assert.NotErrorIs(t, err, otp.ErrCodeNotFound,
			"OTP was successfully created and persisted for subject 2 despite delivery semaphore saturation")
	})
}

// TestSEC_PSK_04_CrossTenant_CeremonyCookie_AcceptedByDefault verifies that ceremony cookies
// bind the tenantID and that cross-tenant submission is rejected with session_invalid (HTTP 400).
func TestSEC_PSK_04_CrossTenant_CeremonyCookie_AcceptedByDefault(t *testing.T) {
	testCookieKey := []byte("0123456789abcdef0123456789abcdef")
	store := passkeymemory.NewStore()
	svc, err := passkey.NewService(store, passkey.Config{
		RPID:                     "example.com",
		RPDisplayName:            "Example",
		RPOrigins:                []string{"https://example.com"},
		CookieKey:                testCookieKey,
		InsecureNoChallengeStore: true, // Typical when ChallengeStore is omitted (e.g. on pgx deployments per SEC-PSK-01)
	})
	require.NoError(t, err)

	uidA := uuid.Must(uuid.NewV7())
	uidB := uuid.Must(uuid.NewV7())

	// Handler for Tenant A ("tenant-alpha")
	resolverA := passkey.WithUserResolver(func(*http.Request) (uuid.UUID, string, string, string, bool) {
		return uidA, "alice", "Alice", "tenant-alpha", true
	})
	beginA := passkey.BeginRegistrationHandler(svc, resolverA)

	// 1. Initiate ceremony on Tenant A to obtain the ceremony cookie
	beginRec := httptest.NewRecorder()
	beginReq := httptest.NewRequest(http.MethodPost, "/passkey/register/begin", nil)
	beginA(beginRec, beginReq)
	require.Equal(t, http.StatusOK, beginRec.Code)

	var ceremonyCookie *http.Cookie
	for _, c := range beginRec.Result().Cookies() {
		if c.Name == passkey.DefaultSessionCookieName {
			ceremonyCookie = c
			break
		}
	}
	require.NotNil(t, ceremonyCookie, "Ceremony cookie must be set on Begin")

	// 2. Now send Tenant A's ceremony cookie to Tenant B's ("tenant-beta") FinishRegistrationHandler.
	resolverB := passkey.WithUserResolver(func(*http.Request) (uuid.UUID, string, string, string, bool) {
		return uidB, "bob", "Bob", "tenant-beta", true
	})
	finishB := passkey.FinishRegistrationHandler(svc, resolverB)

	// Case 1: If an invalid/tampered cookie is provided to Tenant B, loadSession fails with session_invalid (HTTP 400).
	dummyReq := httptest.NewRequest(http.MethodPost, "/passkey/register/finish", strings.NewReader("{}"))
	dummyReq.Header.Set("Content-Type", "application/json")
	dummyReq.AddCookie(&http.Cookie{Name: passkey.DefaultSessionCookieName, Value: "invalid-tampered-cookie"})
	dummyRec := httptest.NewRecorder()
	finishB(dummyRec, dummyReq)
	assert.Equal(t, http.StatusBadRequest, dummyRec.Code)
	assert.Contains(t, dummyRec.Body.String(), "session_invalid")

	// Case 2: Present Tenant A's ceremony cookie to Tenant B.
	// If tenant isolation existed in the cookie, loadSession for Tenant B would reject Tenant A's cookie with session_invalid.
	// In current code: loadSession verifies HMAC with the shared cookieKey, parses SessionData (which has no tenant),
	// and accepts the session! It passes session verification and reaches WebAuthn credential parsing (rejecting the dummy body).
	crossReq := httptest.NewRequest(http.MethodPost, "/passkey/register/finish", strings.NewReader("{}"))
	crossReq.Header.Set("Content-Type", "application/json")
	crossReq.AddCookie(ceremonyCookie)
	crossRec := httptest.NewRecorder()
	finishB(crossRec, crossReq)

	assert.Equal(t, http.StatusBadRequest, crossRec.Code)
	assert.Contains(t, crossRec.Body.String(), "session_invalid")
}

// TestSEC_MFA_04_StepUp_RecoveryCodes_CannotElevateSession confirms that:
// 1. StepUpHandler accepts valid recovery codes and elevates the session.
// 2. Full token pair and cookies are issued just like with TOTP.
// 3. Single-use recovery codes are consumed and cannot be reused.
func TestSEC_MFA_04_StepUp_RecoveryCodes_CannotElevateSession(t *testing.T) {
	ctx := context.Background()
	store := mfamemory.NewStore()
	clkTime := time.Unix(1_700_000_000, 0)
	svc := mfa.NewService(store, mfa.WithClock(func() time.Time { return clkTime }))

	tenant := "tenant-sec-04"
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, tenant, true })

	// Enroll and confirm TOTP
	enrollment, err := svc.EnrollTOTP(ctx, tenant, uid, "user@example.com")
	require.NoError(t, err)
	code, err := mfa.GenerateCode(enrollment.Secret, clkTime, mfa.DefaultDigits, mfa.DefaultPeriod)
	require.NoError(t, err)
	recoveryCodes, err := svc.ConfirmTOTP(ctx, tenant, uid, code)
	require.NoError(t, err)
	require.NotEmpty(t, recoveryCodes)
	validRecoveryCode := recoveryCodes[0]

	// Setup StepUpHandler with mock issuer
	var captured tokens.Claims[struct{}]
	issuer := &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(ctx context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			captured = claims
			return &tokens.TokenPair[struct{}]{
				AccessToken:  "full-access-token",
				RefreshToken: "full-refresh-token",
				Claims:       claims,
			}, nil
		},
	}
	builder := func(ctx context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
	}

	stepUpH := mfa.StepUpHandler[struct{}](svc, issuer, builder, resolver)

	// 1. User submits valid recovery code to StepUpHandler:
	stepUpForm := url.Values{"code": {validRecoveryCode}}
	stepUpReq := httptest.NewRequest(http.MethodPost, "/mfa/step-up", strings.NewReader(stepUpForm.Encode()))
	stepUpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	stepUpReq.Header.Set("Origin", "https://"+stepUpReq.Host)
	stepUpRec := httptest.NewRecorder()

	stepUpH(stepUpRec, stepUpReq)

	assert.Equal(t, http.StatusNoContent, stepUpRec.Code,
		"SEC-MFA-04 Fixed: StepUpHandler accepts valid recovery codes and returns HTTP 204")
	cookies := stepUpRec.Result().Cookies()
	require.NotEmpty(t, cookies, "StepUpHandler must issue cookies on valid recovery code")
	var accessCookie, refreshCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == tokens.DefaultAccessCookieName {
			accessCookie = c
		}
		if c.Name == tokens.DefaultRefreshCookieName {
			refreshCookie = c
		}
	}
	require.NotNil(t, accessCookie, "access cookie must be set")
	require.NotNil(t, refreshCookie, "refresh cookie must be set")
	assert.Equal(t, "full-access-token", accessCookie.Value)
	assert.Equal(t, "full-refresh-token", refreshCookie.Value)
	assert.Equal(t, []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}, captured.AMR)

	// 2. Single-use: submitting the same recovery code again fails:
	stepUpRec2 := httptest.NewRecorder()
	stepUpReq2 := httptest.NewRequest(http.MethodPost, "/mfa/step-up", strings.NewReader(stepUpForm.Encode()))
	stepUpReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	stepUpReq2.Header.Set("Origin", "https://"+stepUpReq2.Host)
	stepUpH(stepUpRec2, stepUpReq2)

	assert.Equal(t, http.StatusUnauthorized, stepUpRec2.Code,
		"consumed recovery code cannot be reused")
	assert.Contains(t, stepUpRec2.Body.String(), "invalid_code")
}

// TestSEC_PSK_01_PostgresChallengeStore_MissingImplementation confirms that adapters/pgx/passkey
// implements passkey.ChallengeStore, enabling multi-node Postgres deployments to store challenges
// persistently without ErrChallengeStoreMissing.
func TestSEC_PSK_01_PostgresChallengeStore_MissingImplementation(t *testing.T) {
	pgxStore := pgxpasskey.NewStore(nil)

	// Confirm that pgx.Store implements passkey.Store
	var _ passkey.Store = pgxStore

	// Confirm that pgx.Store implements passkey.ChallengeStore
	_, implementsChallengeStore := any(pgxStore).(passkey.ChallengeStore)
	assert.True(t, implementsChallengeStore,
		"SEC-PSK-01 Remediated: adapters/pgx/passkey provides ChallengeStore implementation")

	// Confirm that passkey.NewService succeeds without ErrChallengeStoreMissing
	_, err := passkey.NewService(pgxStore, passkey.Config{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
		CookieKey:     []byte("0123456789abcdef0123456789abcdef"),
	})
	assert.NoError(t, err,
		"SEC-PSK-01 Remediated: passkey.NewService automatically adopts ChallengeStore from pgxStore")
}

// TestSEC_PSK_03_ClonedCredential_NotRevokedInStore confirms that when a signature counter
// regression is detected during passkey login (CloneWarning = true), the service emits an
// event, returns ErrCredentialCloned, and automatically revokes/deletes the compromised
// passkey credential from the store so it cannot be used again (SEC-PSK-03).
func TestSEC_PSK_03_ClonedCredential_NotRevokedInStore(t *testing.T) {
	ctx := context.Background()
	store := passkeymemory.NewStore()
	tenant := "tenant-sec-03"
	uid := uuid.Must(uuid.NewV7())

	cookieKey := []byte("0123456789abcdef0123456789abcdef")
	svc, err := passkey.NewService(store, passkey.Config{
		RPID:                     "example.com",
		RPDisplayName:            "Example",
		RPOrigins:                []string{"https://example.com"},
		CookieKey:                cookieKey,
		InsecureNoChallengeStore: true,
	})
	require.NoError(t, err)

	auth := passkeytest.NewSoftAuthenticator(t, "example.com", "https://example.com")

	// 1. User registers a passkey credential
	_, regSession, err := svc.BeginRegistration(ctx, tenant, uid, "alice", "Alice")
	require.NoError(t, err)
	_, err = svc.FinishRegistration(ctx, tenant, uid, "alice", "Alice", *regSession, auth.RegistrationRequest(t, regSession.Challenge))
	require.NoError(t, err)

	// 2. Legitimate login moves the stored counter to 1
	_, loginSession1, err := svc.BeginLogin(ctx, tenant, uid)
	require.NoError(t, err)
	cred1, err := svc.FinishLogin(ctx, tenant, uid, *loginSession1, auth.LoginRequest(t, loginSession1.Challenge, nil))
	require.NoError(t, err)
	assert.Equal(t, uint32(1), cred1.SignCount)

	// 3. Authenticator clone asserts with a non-advancing counter (<= stored). WebAuthn
	// clone detection flags it and FinishLogin returns ErrCredentialCloned.
	_, loginSession2, err := svc.BeginLogin(ctx, tenant, uid)
	require.NoError(t, err)
	_, err = svc.FinishLogin(ctx, tenant, uid, *loginSession2, auth.LoginRequestAtCount(t, loginSession2.Challenge, nil, 1))
	require.ErrorIs(t, err, passkey.ErrCredentialCloned, "a regressed signature counter must be flagged as a clone")

	// 4. Remediated SEC-PSK-03: Compromised cloned credential must be removed/revoked from the store!
	creds, err := store.GetCredentials(ctx, tenant, uid)
	require.NoError(t, err)
	assert.Empty(t, creds, "SEC-PSK-03 Remediated: Cloned credential must be revoked/deleted from store upon clone detection")

	// 5. Subsequent login attempts can no longer use this compromised credential
	_, _, err = svc.BeginLogin(ctx, tenant, uid)
	assert.ErrorIs(t, err, passkey.ErrNoCredentials, "user must have no credentials left after revocation")
}
