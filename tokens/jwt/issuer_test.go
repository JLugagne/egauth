package jwt_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/JLugagne/egauth/tokens/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MyCustomClaims struct {
	Plan    string `json:"plan"`
	IsAdmin bool   `json:"is_admin"`
}

func TestJWTIssuerVerifier_Contract(t *testing.T) {
	refreshTokens := make(map[string]*tokens.RefreshToken)
	apiKeys := make(map[string]*tokens.APIKey[MyCustomClaims])

	mockStore := &storetest.MockStore[MyCustomClaims]{
		SaveRefreshTokenFunc: func(ctx context.Context, tenantID string, rt *tokens.RefreshToken) error {
			rtCopy := *rt
			refreshTokens[rt.Hash] = &rtCopy
			return nil
		},
		FindRefreshTokenFunc: func(ctx context.Context, tenantID string, tokenHash string) (*tokens.RefreshToken, error) {
			rt, ok := refreshTokens[tokenHash]
			if !ok {
				return nil, tokens.ErrRefreshTokenNotFound
			}
			return rt, nil
		},
		SaveAPIKeyFunc: func(ctx context.Context, tenantID string, key *tokens.APIKey[MyCustomClaims]) error {
			apiKeys[key.Hash] = key
			return nil
		},
		FindAPIKeyByHashFunc: func(ctx context.Context, tenantID string, tokenHash string) (*tokens.APIKey[MyCustomClaims], error) {
			key, ok := apiKeys[tokenHash]
			if !ok {
				return nil, tokens.ErrAPIKeyNotFound
			}
			return key, nil
		},
	}

	cfg := jwt.Config[MyCustomClaims]{
		Store:      mockStore,
		SecretKey:  "super-secret-key-for-testing----", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	}
	svc := jwt.New[MyCustomClaims](cfg)

	issuertest.IssuerVerifierContractTesting[MyCustomClaims](t, svc, svc, MyCustomClaims{Plan: "pro", IsAdmin: true})
}

// newIssueKeyService builds a Service whose in-memory store captures every saved API key,
// keyed by its hash, so a test can both verify the returned key and inspect what was persisted.
func newIssueKeyService(t *testing.T) (*jwt.Service[MyCustomClaims], map[string]*tokens.APIKey[MyCustomClaims]) {
	t.Helper()
	saved := make(map[string]*tokens.APIKey[MyCustomClaims])
	store := &storetest.MockStore[MyCustomClaims]{
		SaveAPIKeyFunc: func(_ context.Context, _ string, key *tokens.APIKey[MyCustomClaims]) error {
			cp := *key
			saved[key.Hash] = &cp
			return nil
		},
		FindAPIKeyByHashFunc: func(_ context.Context, _ string, hash string) (*tokens.APIKey[MyCustomClaims], error) {
			key, ok := saved[hash]
			if !ok {
				return nil, tokens.ErrAPIKeyNotFound
			}
			return key, nil
		},
	}
	cfg := jwt.Config[MyCustomClaims]{
		Store:      store,
		SecretKey:  "super-secret-key-for-testing----", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	}
	return jwt.New[MyCustomClaims](cfg), saved
}

// TestIssueAPIKey covers the per-type issuance contract: a PAT's subject is the user, a
// Service token's subject is its own key ID, both record the type and the human creator, and
// the issuer uses only the caller-supplied scopes (it never copies the user's stored roles).
func TestIssueAPIKey(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-abc"

	t.Run("PAT subject is the creating user", func(t *testing.T) {
		svc, saved := newIssueKeyService(t)
		userID := uuid.Must(uuid.NewV7())

		// A PAT acts as its creator: the user issues their own token (Subject defaults to createdBy
		// when left unset), so Subject == CreatedBy == the user.
		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, userID, tokens.Claims[MyCustomClaims]{
			TenantID: tenant,
			Scopes:   []string{"repo:read"},
		})
		require.NoError(t, err)
		require.NotNil(t, key)

		assert.Equal(t, tokens.KeyTypePAT, key.Type)
		assert.Equal(t, userID, key.CreatedBy)
		assert.Equal(t, userID, key.Claims.Subject, "a PAT acts as its creator, so its subject is the creating user")

		// The persisted row mirrors the returned key.
		stored := saved[key.Hash]
		require.NotNil(t, stored)
		assert.Equal(t, tokens.KeyTypePAT, stored.Type)
		assert.Equal(t, userID, stored.CreatedBy)
		assert.Equal(t, userID, stored.Claims.Subject)
	})

	t.Run("PAT with Subject different from createdBy is rejected", func(t *testing.T) {
		svc, _ := newIssueKeyService(t)
		creatorID := uuid.Must(uuid.NewV7())
		otherUser := uuid.Must(uuid.NewV7())

		_, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[MyCustomClaims]{
			Subject:  otherUser, // names a different user than the creator
			TenantID: tenant,
			Scopes:   []string{"repo:read"},
		})
		require.ErrorIs(t, err, jwt.ErrPATSubjectMismatch,
			"a PAT naming a different user than its creator must be rejected (else it would survive that user's DisableUser)")
	})

	t.Run("Service subject is the key's own ID, distinct from the creator", func(t *testing.T) {
		svc, saved := newIssueKeyService(t)
		creatorID := uuid.Must(uuid.NewV7())

		key, err := svc.IssueAPIKey(ctx, "sk_svc_", tokens.KeyTypeService, creatorID, tokens.Claims[MyCustomClaims]{
			// A caller-supplied subject must be ignored for a Service token.
			Subject:  uuid.Must(uuid.NewV7()),
			TenantID: tenant,
			Scopes:   []string{"ingest:write"},
		})
		require.NoError(t, err)
		require.NotNil(t, key)

		assert.Equal(t, tokens.KeyTypeService, key.Type)
		assert.Equal(t, creatorID, key.CreatedBy)
		assert.Equal(t, key.ID, key.Claims.Subject, "a Service token's subject is its own key ID")
		assert.NotEqual(t, creatorID, key.Claims.Subject, "the creator is distinct from the service identity")

		stored := saved[key.Hash]
		require.NotNil(t, stored)
		assert.Equal(t, key.ID, stored.Claims.Subject)
		assert.Equal(t, creatorID, stored.CreatedBy)
	})

	t.Run("no silent role copy: only caller-supplied scopes are used", func(t *testing.T) {
		svc, _ := newIssueKeyService(t)
		userID := uuid.Must(uuid.NewV7())

		// The user is powerful (admin), but the PAT is issued with a deliberately narrow set.
		// The issuer must NOT widen the key's authority to the user's roles.
		narrow := []string{"repo:read"}
		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, userID, tokens.Claims[MyCustomClaims]{
			TenantID: tenant,
			Scopes:   narrow,
			Roles:    []string{"viewer"},
		})
		require.NoError(t, err)

		assert.Equal(t, narrow, key.Claims.Scopes, "scopes must be exactly those passed by the caller")
		assert.Equal(t, []string{"viewer"}, key.Claims.Roles, "roles must be exactly those passed by the caller")
		assert.NotContains(t, key.Claims.Roles, "admin", "the user's broader stored roles must never be copied onto the key")
	})

	t.Run("empty principal type is rejected with ErrInvalidPrincipalType", func(t *testing.T) {
		svc, _ := newIssueKeyService(t)
		userID := uuid.Must(uuid.NewV7())

		_, err := svc.IssueAPIKey(ctx, "sk_", "", userID, tokens.Claims[MyCustomClaims]{
			TenantID: tenant,
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, tokens.ErrInvalidPrincipalType)
		assert.ErrorIs(t, err, jwt.ErrInvalidPrincipalType)
	})

	t.Run("invalid principal type is rejected with ErrInvalidPrincipalType", func(t *testing.T) {
		svc, _ := newIssueKeyService(t)
		userID := uuid.Must(uuid.NewV7())

		for _, invalid := range []tokens.KeyType{"invalid", "admin", "root", "unknown"} {
			_, err := svc.IssueAPIKey(ctx, "sk_", invalid, userID, tokens.Claims[MyCustomClaims]{
				TenantID: tenant,
			})
			require.Error(t, err)
			assert.ErrorIs(t, err, tokens.ErrInvalidPrincipalType, "expected error for invalid key type %q", invalid)
		}
	})

	t.Run("valid principal type 'user' sets subject to creator", func(t *testing.T) {
		svc, saved := newIssueKeyService(t)
		userID := uuid.Must(uuid.NewV7())

		key, err := svc.IssueAPIKey(ctx, "sk_usr_", tokens.KeyTypeUser, userID, tokens.Claims[MyCustomClaims]{
			TenantID: tenant,
			Scopes:   []string{"profile:read"},
		})
		require.NoError(t, err)
		require.NotNil(t, key)

		assert.Equal(t, tokens.KeyTypeUser, key.Type)
		assert.Equal(t, userID, key.CreatedBy)
		assert.Equal(t, userID, key.Claims.Subject)

		stored := saved[key.Hash]
		require.NotNil(t, stored)
		assert.Equal(t, tokens.KeyTypeUser, stored.Type)
		assert.Equal(t, userID, stored.CreatedBy)
		assert.Equal(t, userID, stored.Claims.Subject)
	})

	t.Run("valid principal type 'system' sets subject to key ID", func(t *testing.T) {
		svc, saved := newIssueKeyService(t)
		creatorID := uuid.Must(uuid.NewV7())

		key, err := svc.IssueAPIKey(ctx, "sk_sys_", tokens.KeyTypeSystem, creatorID, tokens.Claims[MyCustomClaims]{
			TenantID: tenant,
			Scopes:   []string{"metrics:write"},
		})
		require.NoError(t, err)
		require.NotNil(t, key)

		assert.Equal(t, tokens.KeyTypeSystem, key.Type)
		assert.Equal(t, creatorID, key.CreatedBy)
		assert.Equal(t, key.ID, key.Claims.Subject)
		assert.NotEqual(t, creatorID, key.Claims.Subject)

		stored := saved[key.Hash]
		require.NotNil(t, stored)
		assert.Equal(t, tokens.KeyTypeSystem, stored.Type)
		assert.Equal(t, creatorID, stored.CreatedBy)
		assert.Equal(t, key.ID, stored.Claims.Subject)
	})
}

func TestJWTIssuerVerifier_EdgeCases(t *testing.T) {
	ctx := context.Background()
	mockStore := &storetest.MockStore[MyCustomClaims]{
		SaveRefreshTokenFunc: func(ctx context.Context, tenantID string, rt *tokens.RefreshToken) error {
			return nil
		},
	}

	// InsecureAllowWeakKey is set because this test intentionally uses a short key
	// to exercise expiry/signature-mismatch edge cases, not key-strength behaviour.
	cfg := jwt.Config[MyCustomClaims]{
		Store:                mockStore,
		SecretKey:            "secret",
		Issuer:               "test",
		AccessTTL:            -1 * time.Minute, // Expired immediately
		RefreshTTL:           24 * time.Hour,
		InsecureAllowWeakKey: true,
	}
	svc := jwt.New[MyCustomClaims](cfg)

	t.Run("Expired token returns ErrTokenExpired", func(t *testing.T) {
		claims := tokens.Claims[MyCustomClaims]{
			Subject: uuid.Must(uuid.NewV7()),
		}

		pair, err := svc.IssueTokenPair(ctx, claims)
		require.NoError(t, err)

		_, err = svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
		assert.ErrorIs(t, err, tokens.ErrTokenExpired)
	})

	t.Run("Invalid signature returns ErrInvalidToken", func(t *testing.T) {
		// Create a token with a different secret; InsecureAllowWeakKey bypasses length check.
		otherSvc := jwt.New[MyCustomClaims](jwt.Config[MyCustomClaims]{
			Store:                mockStore,
			SecretKey:            "different-secret",
			AccessTTL:            1 * time.Hour,
			InsecureAllowWeakKey: true,
		})

		pair, err := otherSvc.IssueTokenPair(ctx, tokens.Claims[MyCustomClaims]{Subject: uuid.Must(uuid.NewV7())})
		require.NoError(t, err)

		_, err = svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
		assert.ErrorIs(t, err, tokens.ErrInvalidToken)
	})
}

type mockAtomicStore struct {
	*storetest.MockStore[MyCustomClaims]
	rotateCalled bool
	rotateFunc   func(ctx context.Context, tenantID string, oldTokenHash string, newRT *tokens.RefreshToken) error
}

func (m *mockAtomicStore) RotateRefreshToken(ctx context.Context, tenantID string, oldTokenHash string, newRT *tokens.RefreshToken) error {
	m.rotateCalled = true
	if m.rotateFunc != nil {
		return m.rotateFunc(ctx, tenantID, oldTokenHash, newRT)
	}
	return nil
}

func TestRotate_AtomicStore(t *testing.T) {
	ctx := context.Background()
	userID := uuid.Must(uuid.NewV7())
	tokensMap := make(map[string]*tokens.RefreshToken)

	baseStore := &storetest.MockStore[MyCustomClaims]{
		SaveRefreshTokenFunc: func(ctx context.Context, tenantID string, rt *tokens.RefreshToken) error {
			tokensMap[rt.Hash] = rt
			return nil
		},
		FindRefreshTokenFunc: func(ctx context.Context, tenantID string, tokenHash string) (*tokens.RefreshToken, error) {
			rt, ok := tokensMap[tokenHash]
			if !ok {
				return nil, tokens.ErrRefreshTokenNotFound
			}
			return rt, nil
		},
		ConsumeRefreshTokenFunc: func(ctx context.Context, tenantID string, tokenHash string) error {
			t.Fatal("ConsumeRefreshToken should NOT be called directly when store implements AtomicRefreshTokenRotator")
			return nil
		},
	}

	atomicStore := &mockAtomicStore{
		MockStore: baseStore,
	}

	claimsProvider := tokens.ClaimsProviderFunc[MyCustomClaims](func(_ context.Context, uid uuid.UUID, _ string) (tokens.Claims[MyCustomClaims], error) {
		return tokens.Claims[MyCustomClaims]{Subject: uid}, nil
	})

	cfg := jwt.Config[MyCustomClaims]{
		Store:          atomicStore,
		SecretKey:      "super-secret-key-for-testing----",
		Issuer:         "egauth-test",
		AccessTTL:      15 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		ClaimsProvider: claimsProvider,
	}
	svc := jwt.New[MyCustomClaims](cfg)

	initialPair, err := svc.IssueTokenPair(ctx, tokens.Claims[MyCustomClaims]{Subject: userID})
	require.NoError(t, err)

	atomicStore.rotateFunc = func(ctx context.Context, tenantID string, oldTokenHash string, newRT *tokens.RefreshToken) error {
		oldRT, ok := tokensMap[oldTokenHash]
		require.True(t, ok)
		now := time.Now().UTC()
		oldRT.ConsumedAt = &now
		tokensMap[newRT.Hash] = newRT
		return nil
	}

	pair, err := svc.Rotate(ctx, "", initialPair.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, pair.RefreshToken)
	assert.True(t, atomicStore.rotateCalled, "atomic store RotateRefreshToken must be called")

	// Test race condition returning ErrRefreshTokenReused maps to ErrRefreshConcurrent
	atomicStore.rotateFunc = func(ctx context.Context, tenantID string, oldTokenHash string, newRT *tokens.RefreshToken) error {
		return tokens.ErrRefreshTokenReused
	}
	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	assert.ErrorIs(t, err, tokens.ErrRefreshConcurrent, "losing consume race during atomic rotation must return ErrRefreshConcurrent")
}

func TestRotate_NonAtomicStore_RollbackOnFailure(t *testing.T) {
	ctx := context.Background()
	userID := uuid.Must(uuid.NewV7())
	tokensMap := make(map[string]*tokens.RefreshToken)

	var initialToken string
	failSave := false
	store := &storetest.MockStore[MyCustomClaims]{
		SaveRefreshTokenFunc: func(ctx context.Context, tenantID string, rt *tokens.RefreshToken) error {
			if failSave && (initialToken == "" || rt.Hash != tokens.HashToken(initialToken)) {
				return assert.AnError
			}
			tokensMap[rt.Hash] = rt
			return nil
		},
		FindRefreshTokenFunc: func(ctx context.Context, tenantID string, tokenHash string) (*tokens.RefreshToken, error) {
			rt, ok := tokensMap[tokenHash]
			if !ok {
				return nil, tokens.ErrRefreshTokenNotFound
			}
			return rt, nil
		},
		ConsumeRefreshTokenFunc: func(ctx context.Context, tenantID string, tokenHash string) error {
			rt, ok := tokensMap[tokenHash]
			if !ok {
				return tokens.ErrRefreshTokenNotFound
			}
			if rt.ConsumedAt != nil {
				return tokens.ErrRefreshTokenReused
			}
			now := time.Now().UTC()
			rt.ConsumedAt = &now
			return nil
		},
	}

	claimsProvider := tokens.ClaimsProviderFunc[MyCustomClaims](func(_ context.Context, uid uuid.UUID, _ string) (tokens.Claims[MyCustomClaims], error) {
		return tokens.Claims[MyCustomClaims]{Subject: uid}, nil
	})

	cfg := jwt.Config[MyCustomClaims]{
		Store:          store,
		SecretKey:      "super-secret-key-for-testing----",
		Issuer:         "egauth-test",
		AccessTTL:      15 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		ClaimsProvider: claimsProvider,
	}
	svc := jwt.New[MyCustomClaims](cfg)

	initialPair, err := svc.IssueTokenPair(ctx, tokens.Claims[MyCustomClaims]{Subject: userID})
	require.NoError(t, err)
	initialToken = initialPair.RefreshToken

	// Now fail saving the new token during rotation
	failSave = true
	_, err = svc.Rotate(ctx, "", initialPair.RefreshToken)
	require.Error(t, err)

	// Verify rollback: old token must NOT remain marked as consumed
	oldRT := tokensMap[tokens.HashToken(initialPair.RefreshToken)]
	require.NotNil(t, oldRT)
	assert.Nil(t, oldRT.ConsumedAt, "old token ConsumedAt must be rolled back to nil on save failure")
}

func TestRotate_DetectSessionTheftWithinGrace(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore[MyCustomClaims]()
	userID := uuid.Must(uuid.NewV7())
	sink := &captureSink{}

	claimsProvider := tokens.ClaimsProviderFunc[MyCustomClaims](func(_ context.Context, uid uuid.UUID, _ string) (tokens.Claims[MyCustomClaims], error) {
		return tokens.Claims[MyCustomClaims]{Subject: uid}, nil
	})

	svc := jwt.New[MyCustomClaims](jwt.Config[MyCustomClaims]{
		Store:            store,
		SecretKey:        "super-secret-key-for-testing----",
		Issuer:           "egauth-test",
		AccessTTL:        15 * time.Minute,
		RefreshTTL:       24 * time.Hour,
		ReuseGracePeriod: 10 * time.Second,
		ClaimsProvider:   claimsProvider,
		EventSink:        sink,
	})

	// Issue token
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[MyCustomClaims]{Subject: userID})
	require.NoError(t, err)

	// Client A (IP "1.2.3.4") rotates the token
	ctxA := tokens.WithClientContext(ctx, tokens.ClientContext{IP: "1.2.3.4", UserAgent: "ClientA"})
	newPairA, err := svc.Rotate(ctxA, "", pair.RefreshToken)
	require.NoError(t, err)

	// Client B (IP "5.6.7.8") presents the SAME token within the grace period
	ctxB := tokens.WithClientContext(ctx, tokens.ClientContext{IP: "5.6.7.8", UserAgent: "ClientB"})
	_, theftErr := svc.Rotate(ctxB, "", pair.RefreshToken)

	// Theft MUST return ErrRefreshTokenReused and NOT ErrRefreshConcurrent
	require.ErrorIs(t, theftErr, tokens.ErrRefreshTokenReused, "theft must return ErrRefreshTokenReused")
	assert.False(t, errors.Is(theftErr, tokens.ErrRefreshConcurrent), "theft must NOT be classified as benign concurrency ErrRefreshConcurrent")

	// Verify events emitted with reason "grace_theft"
	evRevoked, okRevoked := sink.findEvent(event.TokenFamilyRevoked)
	require.True(t, okRevoked, "TokenFamilyRevoked must be emitted on grace theft")
	assert.Equal(t, "grace_theft", evRevoked.Reason)

	evReuse, okReuse := sink.findEvent(event.RefreshReuseDetected)
	require.True(t, okReuse, "RefreshReuseDetected must be emitted on grace theft")
	assert.Equal(t, "grace_theft", evReuse.Reason)

	// The family must be revoked in the store; subsequent rotation of newPairA must fail
	_, err = svc.Rotate(ctxA, "", newPairA.RefreshToken)
	assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound, "family must be revoked following theft in grace window")

	// Test benign concurrency with matching client context
	pair2, err := svc.IssueTokenPair(ctx, tokens.Claims[MyCustomClaims]{Subject: userID})
	require.NoError(t, err)

	newPair2, err := svc.Rotate(ctxA, "", pair2.RefreshToken)
	require.NoError(t, err)

	// Same client presents token again within grace -> benign concurrency
	_, benignErr := svc.Rotate(ctxA, "", pair2.RefreshToken)
	require.ErrorIs(t, benignErr, tokens.ErrRefreshConcurrent, "same client replay within grace must be treated as benign concurrency")

	// Family remains valid for same client
	_, err = svc.Rotate(ctxA, "", newPair2.RefreshToken)
	assert.NoError(t, err, "family must remain valid after benign concurrency")
}

// SEC-TOK-10: Absolute maximum lifetime ceiling on refresh token families.
func TestRotate_MaxRefreshLifetime(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore[MyCustomClaims]()
	userID := uuid.Must(uuid.NewV7())

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	currTime := now
	clock := func() time.Time { return currTime }

	claimsProvider := tokens.ClaimsProviderFunc[MyCustomClaims](func(_ context.Context, uid uuid.UUID, _ string) (tokens.Claims[MyCustomClaims], error) {
		return tokens.Claims[MyCustomClaims]{Subject: uid}, nil
	})

	maxLifetime := 2 * time.Hour
	refreshTTL := 1 * time.Hour // individual tokens valid for 1 hour

	cfg := jwt.Config[MyCustomClaims]{
		Store:              store,
		SecretKey:          "super-secret-key-for-testing----",
		Issuer:             "egauth-test",
		AccessTTL:          15 * time.Minute,
		RefreshTTL:         refreshTTL,
		MaxRefreshLifetime: maxLifetime,
		ClaimsProvider:     claimsProvider,
		Clock:              clock,
	}
	svc := jwt.New[MyCustomClaims](cfg)

	t.Run("rotated token ExpiresAt is clamped so it does not exceed AuthTime + MaxRefreshLifetime", func(t *testing.T) {
		currTime = now
		// Issue initial token pair at t=0 (valid until t=1h)
		initialPair, err := svc.IssueTokenPair(ctx, tokens.Claims[MyCustomClaims]{Subject: userID})
		require.NoError(t, err)
		initialAuthTime := initialPair.Claims.AuthTime

		// Rotate at t=40m -> yields token valid until t=1h40m (< 2h ceiling)
		currTime = now.Add(40 * time.Minute)
		pair1, err := svc.Rotate(ctx, "", initialPair.RefreshToken)
		require.NoError(t, err)
		assert.Equal(t, currTime.Add(refreshTTL), pair1.RefreshTokenExpiresAt)

		// Rotate at t=1h20m -> currTime + refreshTTL would be t=2h20m (> 2h ceiling).
		// Expiry must be clamped to initialAuthTime + 2h.
		currTime = now.Add(80 * time.Minute)
		pair2, err := svc.Rotate(ctx, "", pair1.RefreshToken)
		require.NoError(t, err)

		expectedMaxExpiry := initialAuthTime.Add(maxLifetime)
		assert.Equal(t, expectedMaxExpiry, pair2.RefreshTokenExpiresAt,
			"rotated token expiry must be clamped to AuthTime + MaxRefreshLifetime")

		storedRT, err := store.FindRefreshToken(ctx, "", pair2.RefreshTokenHash)
		require.NoError(t, err)
		assert.Equal(t, expectedMaxExpiry, storedRT.ExpiresAt,
			"stored refresh token expiry must be clamped to ceiling")

		// Advance clock past the 2h ceiling (e.g. 2h 1m)
		currTime = now.Add(2*time.Hour + time.Minute)

		_, err = svc.Rotate(ctx, "", pair2.RefreshToken)
		assert.ErrorIs(t, err, tokens.ErrTokenExpired,
			"rotating after MaxRefreshLifetime has elapsed must fail with ErrTokenExpired")
	})

	t.Run("rotation fails with ErrTokenExpired when rotating after 2 hours directly", func(t *testing.T) {
		// Fresh service with RefreshTTL=3h > MaxRefreshLifetime=2h
		currTime = now
		longTTLService := jwt.New[MyCustomClaims](jwt.Config[MyCustomClaims]{
			Store:              store,
			SecretKey:          "super-secret-key-for-testing----",
			Issuer:             "egauth-test",
			AccessTTL:          15 * time.Minute,
			RefreshTTL:         3 * time.Hour,
			MaxRefreshLifetime: maxLifetime,
			ClaimsProvider:     claimsProvider,
			Clock:              clock,
		})

		pair, err := longTTLService.IssueTokenPair(ctx, tokens.Claims[MyCustomClaims]{Subject: userID})
		require.NoError(t, err)

		// Initial token should also be clamped to 2h max lifetime
		assert.Equal(t, now.Add(maxLifetime), pair.RefreshTokenExpiresAt,
			"initial token expiry must be clamped if RefreshTTL > MaxRefreshLifetime")

		// Advance clock directly past 2 hours
		currTime = now.Add(2*time.Hour + time.Minute)

		_, err = longTTLService.Rotate(ctx, "", pair.RefreshToken)
		assert.ErrorIs(t, err, tokens.ErrTokenExpired,
			"rotating after 2 hours must fail with ErrTokenExpired")
	})

	t.Run("legacy token with zero AuthTime falls back to CreatedAt for max lifetime", func(t *testing.T) {
		currTime = now
		plaintext := "legacy-token-zero-auth-time"
		createdAt := now
		require.NoError(t, store.SaveRefreshToken(ctx, "", &tokens.RefreshToken{
			Hash:      tokens.HashToken(plaintext),
			FamilyID:  uuid.Must(uuid.NewV7()),
			UserID:    userID,
			ExpiresAt: now.Add(3 * time.Hour),
			CreatedAt: createdAt,
			// AuthTime intentionally zero
		}))

		// Advance clock past max lifetime from CreatedAt (2 hours + 1 min from t=0)
		currTime = now.Add(2*time.Hour + time.Minute)
		_, err := svc.Rotate(ctx, "", plaintext)
		assert.ErrorIs(t, err, tokens.ErrTokenExpired,
			"legacy token rotation past CreatedAt + MaxRefreshLifetime must fail with ErrTokenExpired")
	})
}

// SEC-TOK-11: Presenting a consumed refresh token to VerifyRefreshToken must revoke the entire family.
func TestVerifyRefreshToken_ReplayRevokesFamily(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore[MyCustomClaims]()
	userID := uuid.Must(uuid.NewV7())
	sink := &captureSink{}

	claimsProvider := tokens.ClaimsProviderFunc[MyCustomClaims](func(_ context.Context, uid uuid.UUID, _ string) (tokens.Claims[MyCustomClaims], error) {
		return tokens.Claims[MyCustomClaims]{Subject: uid}, nil
	})

	svc := jwt.New[MyCustomClaims](jwt.Config[MyCustomClaims]{
		Store:          store,
		SecretKey:      "super-secret-key-for-testing----",
		Issuer:         "egauth-test",
		AccessTTL:      15 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		ClaimsProvider: claimsProvider,
		EventSink:      sink,
	})

	// 1. Issue initial pair (RT1).
	pair1, err := svc.IssueTokenPair(ctx, tokens.Claims[MyCustomClaims]{Subject: userID})
	require.NoError(t, err)

	// 2. Rotate RT1 -> yields RT2. RT1 is now consumed.
	pair2, err := svc.Rotate(ctx, "", pair1.RefreshToken)
	require.NoError(t, err)

	// 3. Present replayed RT1 to VerifyRefreshToken.
	_, err = svc.VerifyRefreshToken(ctx, "", pair1.RefreshToken)
	require.ErrorIs(t, err, tokens.ErrRefreshTokenReused, "replayed token must return ErrRefreshTokenReused")

	// 4. Verify that the token family was revoked in the store.
	// Subsequent verification of active descendant RT2 must fail.
	_, err = svc.VerifyRefreshToken(ctx, "", pair2.RefreshToken)
	assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound, "descendant RT2 verification must fail after family revocation")

	// Subsequent rotation of active descendant RT2 must fail.
	_, err = svc.Rotate(ctx, "", pair2.RefreshToken)
	assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound, "descendant RT2 rotation must fail after family revocation")

	// 5. Verify audit events emitted.
	evRevoked, okRevoked := sink.findEvent(event.TokenFamilyRevoked)
	require.True(t, okRevoked, "TokenFamilyRevoked event must be emitted")
	assert.Equal(t, "refresh_reuse_verify", evRevoked.Reason)
	assert.Equal(t, userID.String(), evRevoked.UserID)

	evReuse, okReuse := sink.findEvent(event.RefreshReuseDetected)
	require.True(t, okReuse, "RefreshReuseDetected event must be emitted")
	assert.Equal(t, "verify_replay", evReuse.Reason)
	assert.Equal(t, userID.String(), evReuse.UserID)

	t.Run("returns wrapped error when store RevokeFamily fails", func(t *testing.T) {
		revokeErr := errors.New("db disconnect")
		mockStore := &storetest.MockStore[MyCustomClaims]{
			FindRefreshTokenFunc: func(ctx context.Context, tenantID string, tokenHash string) (*tokens.RefreshToken, error) {
				consumed := time.Now()
				return &tokens.RefreshToken{
					Hash:       tokenHash,
					FamilyID:   uuid.Must(uuid.NewV7()),
					UserID:     userID,
					TenantID:   tenantID,
					ExpiresAt:  time.Now().Add(time.Hour),
					ConsumedAt: &consumed,
				}, nil
			},
			RevokeFamilyFunc: func(ctx context.Context, tenantID string, familyID uuid.UUID) error {
				return revokeErr
			},
		}

		failSvc := jwt.New[MyCustomClaims](jwt.Config[MyCustomClaims]{
			Store:     mockStore,
			SecretKey: "super-secret-key-for-testing----",
			Issuer:    "egauth-test",
		})

		_, err := failSvc.VerifyRefreshToken(ctx, "", "consumed-token")
		require.ErrorIs(t, err, tokens.ErrRefreshTokenReused)
		assert.Contains(t, err.Error(), "family revocation failed")
	})
}
