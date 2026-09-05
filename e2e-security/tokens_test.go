package e2esecurity_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKeyStore satisfies jwt.KeyStore for testing CachingKeyStore.
type mockKeyStore struct {
	activeCalls map[string]int
	verifyCalls map[string]int
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{
		activeCalls: make(map[string]int),
		verifyCalls: make(map[string]int),
	}
}

func (m *mockKeyStore) ActiveSigningKey(_ context.Context, tenantID string) (jwt.Signer, error) {
	m.activeCalls[tenantID]++
	secret := []byte("secret-key-at-least-32-bytes-long-test!")
	return jwt.NewHMACSigner("kid-"+tenantID, secret)
}

func (m *mockKeyStore) VerificationKeys(_ context.Context, tenantID string) (map[string]jwt.Signer, error) {
	m.verifyCalls[tenantID]++
	secret := []byte("secret-key-at-least-32-bytes-long-test!")
	signer, err := jwt.NewHMACSigner("kid-"+tenantID, secret)
	if err != nil {
		return nil, err
	}
	return map[string]jwt.Signer{"kid-" + tenantID: signer}, nil
}

// SEC-TOK-02: Bounded memory capacity and eviction of expired entries in CachingKeyStore.
//
// Verifies that CachingKeyStore bounds its internal memory capacity and evicts expired
// entries when capacity is reached, preventing memory exhaustion attacks from arbitrary tenant lookups.
func TestVulnerability_SECTOK02_UnboundedMemoryLeakInKeyCache(t *testing.T) {
	ctx := context.Background()
	mockKS := newMockKeyStore()

	currTime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return currTime }

	ttl := 10 * time.Millisecond
	maxTenants := 50
	cache := jwt.NewCachingKeyStore(mockKS, ttl, jwt.WithCacheClock(clock), jwt.WithCacheMaxEntries(maxTenants))

	// Simulate attacker probing 50 distinct tenant IDs.
	for i := 0; i < maxTenants; i++ {
		tenantID := uuid.New().String()
		_, err := cache.ActiveSigningKey(ctx, tenantID)
		require.NoError(t, err)
	}

	// Inspect the internal entries map via reflection and Len() method.
	entriesVal := reflect.ValueOf(cache).Elem().FieldByName("entries")
	require.True(t, entriesVal.IsValid(), "entries field must exist on CachingKeyStore")
	assert.Equal(t, maxTenants, entriesVal.Len(), "cache should hold all queried tenants up to capacity")
	assert.Equal(t, maxTenants, cache.Len(), "cache.Len() should match max capacity")

	// Advance time past the TTL by 1 hour.
	currTime = currTime.Add(1 * time.Hour)

	// Adding a new tenant when capacity is reached triggers a sweep of expired entries.
	_, err := cache.ActiveSigningKey(ctx, "new-tenant-id")
	require.NoError(t, err)
	assert.Equal(t, 1, cache.Len(),
		"remediation verified: expired tenant entries were evicted when capacity was reached")
	assert.Equal(t, 1, entriesVal.Len(),
		"internal map entries were cleaned up")

	// Verify that capacity remains bounded when filled with unexpired entries.
	for i := 0; i < maxTenants+10; i++ {
		tenantID := uuid.New().String()
		_, err := cache.ActiveSigningKey(ctx, tenantID)
		require.NoError(t, err)
	}
	assert.Equal(t, maxTenants, cache.Len(), "cache memory remains strictly bounded to maxEntries")
}

// SEC-TOK-09: Écrasement et contournement du contrôle MustChangePassword lors du rafraîchissement.
//
// Proves that in Service.Rotate, line 825 unconditionally overwrites claims.MustChangePassword
// with rt.MustChangePassword from the initial refresh token. If a user originally logged in with
// MustChangePassword=false, and an administrator subsequently flags the account (returned as
// MustChangePassword=true by ClaimsProvider), the rotation silently overwrites it back to false,
// allowing the user to bypass the forced password change gate.
func TestVulnerability_SECTOK09_MustChangePasswordOverwrittenOnRefresh(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore[struct{}]()
	userID := uuid.Must(uuid.NewV7())

	// The ClaimsProvider checks the database and discovers the user MUST change their password.
	claimsProvider := tokens.ClaimsProviderFunc[struct{}](func(_ context.Context, uid uuid.UUID, _ string) (tokens.Claims[struct{}], error) {
		return tokens.Claims[struct{}]{
			Subject:            uid,
			MustChangePassword: true, // Admin enforced password change
		}, nil
	})

	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:          store,
		SecretKey:      "secret-key-at-least-32-bytes-long-test!",
		Issuer:         "test-issuer",
		AccessTTL:      15 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		ClaimsProvider: claimsProvider,
	})

	// User logged in earlier when MustChangePassword was false.
	initialPair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{
		Subject:            userID,
		MustChangePassword: false,
	})
	require.NoError(t, err)
	require.False(t, initialPair.Claims.MustChangePassword)

	// User performs a silent refresh.
	rotatedPair, err := svc.Rotate(ctx, "", initialPair.RefreshToken)
	require.NoError(t, err)

	// Verify the access token claims.
	verifiedClaims, err := svc.VerifyAccessTokenForTenant(ctx, "", rotatedPair.AccessToken)
	require.NoError(t, err)

	// Vulnerability confirmed: MustChangePassword from the provider was OVERWRITTEN by rt.MustChangePassword (false).
	assert.False(t, verifiedClaims.MustChangePassword,
		"vulnerability confirmed: ClaimsProvider returned MustChangePassword=true, but Rotate overwrote it to false from stale rt")
	assert.False(t, rotatedPair.Claims.MustChangePassword,
		"returned pair claims also reflect the overwritten false value")
}

// SEC-TOK-10: Absence d'expiration absolue des familles de Refresh Tokens (Prolongation indéfinie).
//
// Proves that each rotation sets ExpiresAt = now.Add(RefreshTTL) with no absolute ceiling.
// A session chain can be refreshed indefinitely past any reasonable lifetime limit.
func TestVulnerability_SECTOK10_IndefiniteRefreshTokenExtension(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore[struct{}]()
	userID := uuid.Must(uuid.NewV7())

	currTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return currTime }

	refreshTTL := 30 * 24 * time.Hour // 30 days
	claimsProvider := tokens.ClaimsProviderFunc[struct{}](func(_ context.Context, uid uuid.UUID, _ string) (tokens.Claims[struct{}], error) {
		return tokens.Claims[struct{}]{Subject: uid}, nil
	})

	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:          store,
		SecretKey:      "secret-key-at-least-32-bytes-long-test!",
		Issuer:         "test-issuer",
		AccessTTL:      15 * time.Minute,
		RefreshTTL:     refreshTTL,
		ClaimsProvider: claimsProvider,
		Clock:          clock,
	})

	// Initial login on Day 0.
	initialPair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID})
	require.NoError(t, err)
	initialAuthTime := initialPair.Claims.AuthTime
	currentToken := initialPair.RefreshToken

	// Rotate every 20 days for 15 cycles (300 days total, almost 1 year).
	for day := 20; day <= 300; day += 20 {
		currTime = currTime.Add(20 * 24 * time.Hour)
		newPair, err := svc.Rotate(ctx, "", currentToken)
		require.NoError(t, err, "rotation on day %d should succeed due to lack of absolute max lifetime", day)

		// Each rotation pushes the expiry 30 days into the future relative to current time.
		assert.Equal(t, currTime.Add(refreshTTL), newPair.RefreshTokenExpiresAt)
		currentToken = newPair.RefreshToken
	}

	// Verify the final token after 300 days:
	// The original authentication happened 300 days ago, but the family is still alive and kicking.
	finalClaims, err := svc.VerifyRefreshToken(ctx, "", currentToken)
	require.NoError(t, err)
	assert.Equal(t, userID, finalClaims.Subject)
	assert.True(t, currTime.Sub(initialAuthTime) >= 300*24*time.Hour,
		"vulnerability confirmed: session family alive 300 days past initial auth without absolute cap")
}

// SEC-TOK-11: Missing family revocation when VerifyRefreshToken is called on a replayed token.
//
// Proves that when VerifyRefreshToken detects a replayed/consumed token (rt.ConsumedAt != nil),
// it returns ErrRefreshTokenReused but does NOT call RevokeFamily. The rest of the token family
// remains valid and usable by whoever possesses the latest descendant.
func TestVulnerability_SECTOK11_VerifyRefreshToken_NoFamilyRevocationOnReplay(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore[struct{}]()
	userID := uuid.Must(uuid.NewV7())

	claimsProvider := tokens.ClaimsProviderFunc[struct{}](func(_ context.Context, uid uuid.UUID, _ string) (tokens.Claims[struct{}], error) {
		return tokens.Claims[struct{}]{Subject: uid}, nil
	})

	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:          store,
		SecretKey:      "secret-key-at-least-32-bytes-long-test!",
		Issuer:         "test-issuer",
		AccessTTL:      15 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		ClaimsProvider: claimsProvider,
	})

	// 1. Issue initial pair (RT1).
	pair1, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID})
	require.NoError(t, err)

	// 2. Rotate RT1 -> yields RT2. RT1 is now consumed.
	pair2, err := svc.Rotate(ctx, "", pair1.RefreshToken)
	require.NoError(t, err)

	// 3. Call VerifyRefreshToken with the replayed RT1.
	_, err = svc.VerifyRefreshToken(ctx, "", pair1.RefreshToken)
	assert.ErrorIs(t, err, tokens.ErrRefreshTokenReused, "VerifyRefreshToken detects reuse")

	// 4. Vulnerability: RT2 was NOT revoked! VerifyRefreshToken does not invoke RevokeFamily.
	verifiedClaims, err := svc.VerifyRefreshToken(ctx, "", pair2.RefreshToken)
	require.NoError(t, err,
		"vulnerability confirmed: family was not revoked, so RT2 can still be verified")
	assert.Equal(t, userID, verifiedClaims.Subject)

	// RT2 can also still be rotated into RT3.
	pair3, err := svc.Rotate(ctx, "", pair2.RefreshToken)
	require.NoError(t, err,
		"vulnerability confirmed: descendant RT2 can still rotate after replayed token was presented to VerifyRefreshToken")
	assert.NotEmpty(t, pair3.RefreshToken)
}

// SEC-TOK-04: Session hijacking without theft detection when the attacker advances within the grace window.
//
// Proves that if an attacker intercepts an unconsumed refresh token (RT1) and rotates it,
// and the victim presents RT1 within the 10s grace window, the server classifies the victim's
// request as benign concurrency (ErrRefreshConcurrent) and DOES NOT revoke the family.
// The attacker retains the valid active session (RT2) while the victim is locked out.
func TestVulnerability_SECTOK04_SessionHijackWithinReuseGraceWindow(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore[struct{}]()
	userID := uuid.Must(uuid.NewV7())

	currTime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return currTime }

	claimsProvider := tokens.ClaimsProviderFunc[struct{}](func(_ context.Context, uid uuid.UUID, _ string) (tokens.Claims[struct{}], error) {
		return tokens.Claims[struct{}]{Subject: uid}, nil
	})

	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:            store,
		SecretKey:        "secret-key-at-least-32-bytes-long-test!",
		Issuer:           "test-issuer",
		AccessTTL:        15 * time.Minute,
		RefreshTTL:       24 * time.Hour,
		ReuseGracePeriod: 10 * time.Second, // 10s grace window
		ClaimsProvider:   claimsProvider,
		Clock:            clock,
	})

	// 1. Victim gets RT1.
	victimPair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID})
	require.NoError(t, err)
	stolenRT1 := victimPair.RefreshToken

	// 2. Attacker rotates stolen RT1 at t0 -> gets attackerRT2.
	attackerPair, err := svc.Rotate(ctx, "", stolenRT1)
	require.NoError(t, err)

	// 3. 2 seconds later (within the 10s grace period), victim attempts to rotate RT1.
	currTime = currTime.Add(2 * time.Second)
	_, victimErr := svc.Rotate(ctx, "", stolenRT1)

	// Victim gets ErrRefreshConcurrent instead of family revocation.
	assert.ErrorIs(t, victimErr, tokens.ErrRefreshConcurrent,
		"vulnerability confirmed: victim request treated as benign race instead of theft")

	// 4. Attacker rotates attackerRT2 at t0 + 3s -> gets attackerRT3.
	currTime = currTime.Add(1 * time.Second)
	attackerPair3, err := svc.Rotate(ctx, "", attackerPair.RefreshToken)
	require.NoError(t, err,
		"vulnerability confirmed: attacker session remains valid and continues advancing rotation chain")
	assert.NotEmpty(t, attackerPair3.RefreshToken)
}

// SEC-TOK-13: Incohérence et désynchronisation du type de principal pour les clés API sans type explicite.
//
// Proves that when IssueAPIKey is called with an empty keyType (""), it sets claims.Subject = createdBy
// (treating it like a PAT), but ActorFromAPIKey classifies key.Type == "" as egauth.User (human).
// In contrast, the PostgreSQL adapter's SaveAPIKey overrides keyType == "" to KeyTypeService ("service"),
// converting the actor to egauth.Service (machine).
func TestVulnerability_SECTOK13_APIKeyTypeDesynchronization(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore[struct{}]()
	creatorID := uuid.Must(uuid.NewV7())

	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:     store,
		SecretKey: "secret-key-at-least-32-bytes-long-test!",
		Issuer:    "test-issuer",
	})

	// Issue key with empty type.
	key, err := svc.IssueAPIKey(ctx, "", "", creatorID, tokens.Claims[struct{}]{})
	require.NoError(t, err)
	assert.Equal(t, tokens.KeyType(""), key.Type, "key.Type was left empty as requested")
	assert.Equal(t, creatorID, key.Claims.Subject, "IssueAPIKey treated empty type as PAT, binding subject to createdBy")

	// On in-memory store, ActorFromAPIKey falls into default branch:
	actorMem := tokens.ActorFromAPIKey(key)
	assert.Equal(t, egauth.User, actorMem.Kind, "memory store treats untyped key as human User")
	assert.Equal(t, creatorID, actorMem.UserID)

	// Simulating PostgreSQL store behavior (adapters/pgx/tokens/store.go:191):
	// if keyType == "" { keyType = tokens.KeyTypeService }
	pgKey := *key
	pgKey.Type = tokens.KeyTypeService
	actorPG := tokens.ActorFromAPIKey(&pgKey)
	assert.Equal(t, egauth.Service, actorPG.Kind, "PostgreSQL store treats untyped key as machine Service")
	assert.Equal(t, uuid.Nil, actorPG.UserID, "Service principal wipes UserID")

	assert.NotEqual(t, actorMem.Kind, actorPG.Kind,
		"vulnerability confirmed: identical API key produces different Actor kinds depending on storage adapter")
}

// mockStoreForFailure models transient store failures to exercise SEC-TOK-03.
type mockStoreForFailure struct {
	tokens.Store[struct{}]
	failSaveAfterConsume bool
	consumedTokens       map[string]*tokens.RefreshToken
	revokedFamilies      map[uuid.UUID]bool
	underlying           *memory.Store[struct{}]
}

func newMockStoreForFailure() *mockStoreForFailure {
	return &mockStoreForFailure{
		consumedTokens:  make(map[string]*tokens.RefreshToken),
		revokedFamilies: make(map[uuid.UUID]bool),
		underlying:      memory.NewStore[struct{}](),
	}
}

func (m *mockStoreForFailure) SaveRefreshToken(ctx context.Context, tenantID string, rt *tokens.RefreshToken) error {
	if m.failSaveAfterConsume {
		return errors.New("simulated database connection failure during SaveRefreshToken")
	}
	return m.underlying.SaveRefreshToken(ctx, tenantID, rt)
}

func (m *mockStoreForFailure) FindRefreshToken(ctx context.Context, tenantID string, tokenHash string) (*tokens.RefreshToken, error) {
	return m.underlying.FindRefreshToken(ctx, tenantID, tokenHash)
}

func (m *mockStoreForFailure) ConsumeRefreshToken(ctx context.Context, tenantID string, tokenHash string) error {
	return m.underlying.ConsumeRefreshToken(ctx, tenantID, tokenHash)
}

func (m *mockStoreForFailure) RevokeFamily(ctx context.Context, tenantID string, familyID uuid.UUID) error {
	m.revokedFamilies[familyID] = true
	return m.underlying.RevokeFamily(ctx, tenantID, familyID)
}

func (m *mockStoreForFailure) RevokeRefreshToken(ctx context.Context, tenantID string, tokenHash string) error {
	return m.underlying.RevokeRefreshToken(ctx, tenantID, tokenHash)
}

func (m *mockStoreForFailure) RevokeAllRefreshTokensForUser(ctx context.Context, tenantID string, userID uuid.UUID) error {
	return m.underlying.RevokeAllRefreshTokensForUser(ctx, tenantID, userID)
}

func (m *mockStoreForFailure) SaveAPIKey(ctx context.Context, tenantID string, key *tokens.APIKey[struct{}]) error {
	return m.underlying.SaveAPIKey(ctx, tenantID, key)
}

func (m *mockStoreForFailure) FindAPIKeyByHash(ctx context.Context, tenantID string, tokenHash string) (*tokens.APIKey[struct{}], error) {
	return m.underlying.FindAPIKeyByHash(ctx, tenantID, tokenHash)
}

func (m *mockStoreForFailure) DeleteExpired(ctx context.Context, tenantID string) (int64, error) {
	return m.underlying.DeleteExpired(ctx, tenantID)
}

// SEC-TOK-03: Non-atomicité de la rotation menant au DoS et à l'invalidation de session.
//
// Proves that if SaveRefreshToken fails after ConsumeRefreshToken succeeds,
// the original token is marked consumed, no new pair is issued, and a subsequent
// retry after the reuse grace period causes RevokeFamily to be called, locking out the user.
func TestVulnerability_SECTOK03_NonAtomicRotationLeadingToSessionRevocation(t *testing.T) {
	ctx := context.Background()
	mockStore := newMockStoreForFailure()
	userID := uuid.Must(uuid.NewV7())

	currTime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return currTime }

	claimsProvider := tokens.ClaimsProviderFunc[struct{}](func(_ context.Context, uid uuid.UUID, _ string) (tokens.Claims[struct{}], error) {
		return tokens.Claims[struct{}]{Subject: uid}, nil
	})

	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:            mockStore,
		SecretKey:        "secret-key-at-least-32-bytes-long-test!",
		Issuer:           "test-issuer",
		AccessTTL:        15 * time.Minute,
		RefreshTTL:       24 * time.Hour,
		ReuseGracePeriod: 10 * time.Millisecond,
		ClaimsProvider:   claimsProvider,
		Clock:            clock,
	})

	// Issue initial token.
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID})
	require.NoError(t, err)

	// Simulate transient DB failure on SaveRefreshToken during Rotate.
	mockStore.failSaveAfterConsume = true
	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	require.Error(t, err, "rotation fails during SaveRefreshToken")

	// Token was already marked consumed in store!
	rt, findErr := mockStore.FindRefreshToken(ctx, "", tokens.HashToken(pair.RefreshToken))
	require.NoError(t, findErr)
	require.NotNil(t, rt.ConsumedAt, "token was consumed despite failure to issue successor")

	// Client retries after 25 milliseconds (outside 10ms grace period).
	time.Sleep(25 * time.Millisecond)
	mockStore.failSaveAfterConsume = false
	_, retryErr := svc.Rotate(ctx, "", pair.RefreshToken)
	assert.ErrorIs(t, retryErr, tokens.ErrRefreshTokenReused)

	// Family was revoked because the non-atomic failure left the consumed token in DB!
	assert.True(t, mockStore.revokedFamilies[rt.FamilyID],
		"vulnerability confirmed: non-atomic rotation failure resulted in permanent session family revocation upon client retry")
}
