package jwt_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Regression coverage for F-TOKJWT-001: Rotate's failed-save rollback must never restore
// the pre-rotation snapshot over a record that a concurrent revocation has since killed.
// SaveRefreshToken is an upsert, so writing the stale snapshot back clears a non-nil
// RevokedAt (un-revoking the family) and, on a delete-based store, resurrects a token the
// account-disable primitive removed.

// rollbackStore is a conforming non-atomic store (no RotateRefreshToken method), so Rotate
// takes its consume-then-save fallback path. FindRefreshToken mirrors memory.Store: a
// revoked record surfaces as ErrTokenFamilyRevoked, a deleted record as not-found.
type rollbackStore struct {
	*storetest.MockStore[struct{}]
	mu      *sync.Mutex
	records map[string]*tokens.RefreshToken
}

func newRollbackStore(
	records map[string]*tokens.RefreshToken,
	failNext *bool,
	oldHashes map[string]bool,
	onConsume func(hash string),
) *rollbackStore {
	mu := &sync.Mutex{}
	return &rollbackStore{
		mu:      mu,
		records: records,
		MockStore: &storetest.MockStore[struct{}]{
			SaveRefreshTokenFunc: func(_ context.Context, tenantID string, rt *tokens.RefreshToken) error {
				mu.Lock()
				defer mu.Unlock()
				if *failNext && !oldHashes[rt.Hash] {
					*failNext = false
					return errors.New("simulated transient store failure")
				}
				cp := *rt
				cp.TenantID = tenantID
				records[rt.Hash] = &cp
				return nil
			},
			FindRefreshTokenFunc: func(_ context.Context, _ string, hash string) (*tokens.RefreshToken, error) {
				mu.Lock()
				defer mu.Unlock()
				rt, ok := records[hash]
				if !ok {
					return nil, tokens.ErrRefreshTokenNotFound
				}
				if rt.RevokedAt != nil {
					return nil, tokens.ErrTokenFamilyRevoked
				}
				cp := *rt
				return &cp, nil
			},
			ConsumeRefreshTokenFunc: func(_ context.Context, _ string, hash string) error {
				mu.Lock()
				rt, ok := records[hash]
				if !ok {
					mu.Unlock()
					return tokens.ErrRefreshTokenNotFound
				}
				if rt.RevokedAt != nil {
					mu.Unlock()
					return tokens.ErrTokenFamilyRevoked
				}
				if rt.ConsumedAt != nil {
					mu.Unlock()
					return tokens.ErrRefreshTokenReused
				}
				now := time.Now()
				rt.ConsumedAt = &now
				mu.Unlock()
				if onConsume != nil {
					onConsume(hash)
				}
				return nil
			},
			RevokeFamilyFunc: func(_ context.Context, _ string, familyID uuid.UUID) error {
				mu.Lock()
				defer mu.Unlock()
				now := time.Now()
				for _, rt := range records {
					if rt.FamilyID == familyID && rt.RevokedAt == nil {
						r := now
						rt.RevokedAt = &r
					}
				}
				return nil
			},
		},
	}
}

func rollbackService(store tokens.Store[struct{}]) *jwt.Service[struct{}] {
	return jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      store,
		SecretKey:  "rollback-secret-32-bytes-aaaaaaa!",
		Issuer:     "egauth-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		ClaimsProvider: tokens.ClaimsProviderFunc[struct{}](func(_ context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
			return tokens.Claims[struct{}]{Subject: userID, TenantID: tenantID}, nil
		}),
	})
}

// TestRotate_RollbackMustNotUnrevokeFamily drives the real theft-detection path (a
// concurrent VerifyRefreshToken replay) into the window between ConsumeRefreshToken and
// the failed SaveRefreshToken, then asserts the failed rotation did not clear the
// family's RevokedAt.
func TestRotate_RollbackMustNotUnrevokeFamily(t *testing.T) {
	ctx := context.Background()
	user := uuid.Must(uuid.NewV7())
	family := uuid.Must(uuid.NewV7())

	records := map[string]*tokens.RefreshToken{}
	failNext := false
	oldHashes := map[string]bool{}
	consumed := make(chan struct{})
	revoked := make(chan struct{})

	store := newRollbackStore(records, &failNext, oldHashes, func(string) {
		// Pause while a concurrent VerifyRefreshToken observes the consumed token and
		// revokes the whole family (the real theft-detection path).
		close(consumed)
		<-revoked
	})
	svc := rollbackService(store)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: user})
	require.NoError(t, err)
	oldHash := tokens.HashToken(pair.RefreshToken)

	// Seed the family id and arm the successor-save failure.
	store.mu.Lock()
	records[oldHash].FamilyID = family
	store.mu.Unlock()
	oldHashes[oldHash] = true
	failNext = true

	go func() {
		<-consumed
		_, verr := svc.VerifyRefreshToken(ctx, "", pair.RefreshToken)
		if !errors.Is(verr, tokens.ErrRefreshTokenReused) {
			t.Errorf("expected the concurrent replay to be detected as reuse, got %v", verr)
		}
		close(revoked)
	}()

	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	require.Error(t, err, "the simulated store failure must surface")

	store.mu.Lock()
	revokedAt := records[oldHash].RevokedAt
	store.mu.Unlock()
	require.NotNil(t, revokedAt,
		"VULNERABLE: the failed-rotation rollback cleared RevokedAt; the revoked family was un-revoked")

	// Impact: a token the theft detector revoked must never verify again.
	_, err = svc.VerifyRefreshToken(ctx, "", pair.RefreshToken)
	require.Error(t, err, "VULNERABLE: the revoked refresh token verifies again after the rollback")
}

// TestRotate_RollbackMustNotResurrectDeletedToken covers the delete-based revocation
// variant: RevokeAllRefreshTokensForUser removes the record, and the rollback must not
// re-insert the stale snapshot, which would make a disabled account's session usable again.
func TestRotate_RollbackMustNotResurrectDeletedToken(t *testing.T) {
	ctx := context.Background()
	user := uuid.Must(uuid.NewV7())

	records := map[string]*tokens.RefreshToken{}
	failNext := false
	oldHashes := map[string]bool{}
	consumed := make(chan struct{})
	revoked := make(chan struct{})
	oldHash := ""

	store := newRollbackStore(records, &failNext, oldHashes, func(string) {
		close(consumed)
		<-revoked
	})
	svc := rollbackService(store)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: user})
	require.NoError(t, err)
	oldHash = tokens.HashToken(pair.RefreshToken)
	oldHashes[oldHash] = true
	failNext = true

	go func() {
		<-consumed
		store.mu.Lock()
		delete(store.records, oldHash)
		store.mu.Unlock()
		close(revoked)
	}()

	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	require.Error(t, err, "the simulated store failure must surface")

	store.mu.Lock()
	_, exists := store.records[oldHash]
	store.mu.Unlock()
	require.False(t, exists,
		"VULNERABLE: the rollback resurrected a token deleted by a concurrent account revocation")
}
