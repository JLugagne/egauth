package tokens_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/revocation"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func revocationVerifier(subject uuid.UUID, issuedAt time.Time) *issuertest.MockVerifier[struct{}] {
	return &issuertest.MockVerifier[struct{}]{
		VerifyAccessTokenForTenantFunc: func(ctx context.Context, _ string, token string) (*tokens.Claims[struct{}], error) {
			if token == "valid" {
				return &tokens.Claims[struct{}]{Subject: subject, TenantID: "t1", IssuedAt: issuedAt}, nil
			}
			return nil, tokens.ErrInvalidToken
		},
	}
}

func revocationRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer valid")
	return r
}

func revocationNext(w http.ResponseWriter, r *http.Request, actor egauth.Actor, custom struct{}) {
	w.WriteHeader(http.StatusOK)
}

// TestWithAccessTokenRevocation pins issue #126: a configured checker can reject an
// already-issued, otherwise-valid access token before its AccessTTL elapses.
func TestWithAccessTokenRevocation(t *testing.T) {
	subject := uuid.Must(uuid.NewV7())
	issuedAt := time.Now().Add(-time.Minute)
	verifier := revocationVerifier(subject, issuedAt)

	t.Run("revoked token is rejected and the handler never runs", func(t *testing.T) {
		called := false
		checker := tokens.AccessTokenRevocationCheckerFunc(func(context.Context, string, uuid.UUID, time.Time) (bool, error) {
			return true, nil
		})
		h := tokens.RequireAuth[struct{}](verifier, func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, custom struct{}) {
			called = true
			w.WriteHeader(http.StatusOK)
		}, tokens.WithAccessTokenRevocation[struct{}](checker))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, revocationRequest())
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, called, "the protected handler must not run for a revoked token")
	})

	t.Run("non-revoked token passes", func(t *testing.T) {
		checker := tokens.AccessTokenRevocationCheckerFunc(func(context.Context, string, uuid.UUID, time.Time) (bool, error) {
			return false, nil
		})
		h := tokens.RequireAuth[struct{}](verifier, revocationNext, tokens.WithAccessTokenRevocation[struct{}](checker))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, revocationRequest())
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("checker error fails closed", func(t *testing.T) {
		boom := errors.New("store down")
		checker := tokens.AccessTokenRevocationCheckerFunc(func(context.Context, string, uuid.UUID, time.Time) (bool, error) {
			return false, boom
		})
		h := tokens.RequireAuth[struct{}](verifier, revocationNext, tokens.WithAccessTokenRevocation[struct{}](checker))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, revocationRequest())
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("not configured preserves stateless acceptance", func(t *testing.T) {
		h := tokens.RequireAuth[struct{}](verifier, revocationNext)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, revocationRequest())
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// TestRevocationTracker pins the account-cutoff tracker that bridges the revocation bus to
// access-token rejection.
func TestRevocationTracker(t *testing.T) {
	ctx := context.Background()
	subject := uuid.Must(uuid.NewV7())
	before := time.Unix(1_700_000_000, 0)
	cutoff := before.Add(30 * time.Second)
	after := cutoff.Add(30 * time.Second)

	bus := revocation.NewMemBus()
	tracker := tokens.NewRevocationTracker(bus)

	require.NoError(t, bus.Publish(ctx, revocation.Revocation{
		TenantID:   "t1",
		TargetType: revocation.TargetUser,
		TargetID:   subject.String(),
		CutoffTime: cutoff,
	}))

	revoked, err := tracker.IsAccessTokenRevoked(ctx, "t1", subject, before)
	require.NoError(t, err)
	assert.True(t, revoked, "a token issued before the account cutoff must be revoked")

	revoked, err = tracker.IsAccessTokenRevoked(ctx, "t1", subject, after)
	require.NoError(t, err)
	assert.False(t, revoked, "a token issued after the account cutoff must stay valid")

	otherUser := uuid.Must(uuid.NewV7())
	revoked, err = tracker.IsAccessTokenRevoked(ctx, "t1", otherUser, before)
	require.NoError(t, err)
	assert.False(t, revoked, "revocation is scoped to the revoked user")
}

// TestRevocationEvent_RevokesRefreshAndAccessTogether pins the acceptance criterion that a
// single revocation event drives both refresh-family revocation and access-token rejection.
func TestRevocationEvent_RevokesRefreshAndAccessTogether(t *testing.T) {
	ctx := context.Background()
	svc, store := newRotator(t)
	subject := uuid.Must(uuid.NewV7())

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: subject, TenantID: "t1"})
	require.NoError(t, err)

	bus := revocation.NewMemBus()
	tracker := tokens.NewRevocationTracker(bus)
	bus.Subscribe(revocation.TargetUser, revocation.HandlerFunc(func(ctx context.Context, rev revocation.Revocation) error {
		userID, err := uuid.Parse(rev.TargetID)
		if err != nil {
			return err
		}
		return store.RevokeAllRefreshTokensForUser(ctx, rev.TenantID, userID)
	}))

	require.NoError(t, bus.Publish(ctx, revocation.Revocation{
		TenantID:   "t1",
		TargetType: revocation.TargetUser,
		TargetID:   subject.String(),
		CutoffTime: time.Now().Add(time.Second),
	}))

	_, err = store.FindRefreshToken(ctx, "t1", pair.RefreshTokenHash)
	assert.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound, "the same event must revoke the refresh token")

	revoked, err := tracker.IsAccessTokenRevoked(ctx, "t1", subject, pair.Claims.IssuedAt)
	require.NoError(t, err)
	assert.True(t, revoked, "the same event must reject the already-issued access token")
}
