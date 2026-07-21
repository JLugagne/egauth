package jwt_test

import (
	"context"
	"testing"
	"time"

	egauth "github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyAPIKeyActor proves the verify -> Actor seam: a verified PAT yields a human Actor
// anchored on the owning user, a verified Service token yields a machine Actor anchored on the
// key's own ID, and an expired key fails closed with ErrTokenExpired regardless of its type.
func TestVerifyAPIKeyActor(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-abc"

	t.Run("PAT maps to a human Actor anchored on the user", func(t *testing.T) {
		svc, _ := newIssueKeyService(t)
		userID := uuid.Must(uuid.NewV7())

		// A PAT acts as its creator; Subject defaults to createdBy (the user).
		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, userID, tokens.Claims[MyCustomClaims]{
			TenantID: tenant,
			Scopes:   []string{"repo:read", "repo:write"},
		})
		require.NoError(t, err)

		actor, claims, err := svc.VerifyAPIKeyActor(ctx, tenant, key.Token)
		require.NoError(t, err)
		require.NotNil(t, claims)

		assert.Equal(t, egauth.PAT, actor.Kind)
		assert.True(t, actor.IsHuman(), "a PAT is a human action")
		assert.False(t, actor.IsMachine())
		assert.Equal(t, userID, actor.UserID, "a PAT's subject is the owning user")
		assert.Equal(t, key.ID, actor.KeyID, "the Actor carries the key's own ID")
		assert.Equal(t, tenant, actor.TenantID)
		assert.Equal(t, []string{"repo:read", "repo:write"}, actor.Scopes, "scopes come verbatim from the key")

		// The claims return value still matches VerifyAPIKey.
		assert.Equal(t, userID, claims.Subject)
		assert.Equal(t, tenant, claims.TenantID)
	})

	t.Run("Service maps to a machine Actor anchored on the key's own ID", func(t *testing.T) {
		svc, _ := newIssueKeyService(t)
		creatorID := uuid.Must(uuid.NewV7())

		key, err := svc.IssueAPIKey(ctx, "sk_svc_", tokens.KeyTypeService, creatorID, tokens.Claims[MyCustomClaims]{
			TenantID: tenant,
			Scopes:   []string{"ingest:write"},
		})
		require.NoError(t, err)

		actor, claims, err := svc.VerifyAPIKeyActor(ctx, tenant, key.Token)
		require.NoError(t, err)
		require.NotNil(t, claims)

		assert.Equal(t, egauth.Service, actor.Kind)
		assert.True(t, actor.IsMachine(), "a Service token is a machine action")
		assert.False(t, actor.IsHuman())
		assert.Equal(t, uuid.UUID{}, actor.UserID, "a Service token has no owning user on the Actor")
		assert.Equal(t, key.ID, actor.KeyID, "a Service token's subject is its own key ID, carried in KeyID")
		assert.Equal(t, key.ID, claims.Subject, "the underlying subject is the key's own ID")
		assert.Equal(t, tenant, actor.TenantID)
		assert.Equal(t, []string{"ingest:write"}, actor.Scopes)
	})

	t.Run("expired key fails closed with ErrTokenExpired", func(t *testing.T) {
		svc, _ := newIssueKeyService(t)
		creatorID := uuid.Must(uuid.NewV7())

		// Issue a key whose ExpiresAt is already in the past, so verification must reject it.
		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[MyCustomClaims]{
			TenantID:  tenant,
			ExpiresAt: time.Now().Add(-time.Hour),
		})
		require.NoError(t, err)

		actor, claims, err := svc.VerifyAPIKeyActor(ctx, tenant, key.Token)
		assert.ErrorIs(t, err, tokens.ErrTokenExpired)
		assert.Nil(t, claims, "no claims are returned on an expired key")
		assert.Equal(t, egauth.Actor{}, actor, "no Actor is built for an expired key")

		// The plain VerifyAPIKey path enforces expiry identically.
		_, err = svc.VerifyAPIKey(ctx, tenant, key.Token)
		assert.ErrorIs(t, err, tokens.ErrTokenExpired)
	})

	t.Run("a not-found key yields no Actor", func(t *testing.T) {
		svc, _ := newIssueKeyService(t)

		actor, claims, err := svc.VerifyAPIKeyActor(ctx, tenant, "sk_pat_does-not-exist")
		assert.ErrorIs(t, err, tokens.ErrAPIKeyNotFound)
		assert.Nil(t, claims)
		assert.Equal(t, egauth.Actor{}, actor)
	})
}

// TestActorFromAPIKey covers the pure mapper independently of the store/verify path: the
// per-type classification, the safe default for an unclassified key, and the nil guard.
func TestActorFromAPIKey(t *testing.T) {
	userID := uuid.Must(uuid.NewV7())
	keyID := uuid.Must(uuid.NewV7())

	t.Run("PAT", func(t *testing.T) {
		a := tokens.ActorFromAPIKey(&tokens.APIKey[struct{}]{
			ID:       keyID,
			TenantID: "t1",
			Type:     tokens.KeyTypePAT,
			Claims:   tokens.Claims[struct{}]{Subject: userID, Scopes: []string{"s1"}},
		})
		assert.Equal(t, egauth.PAT, a.Kind)
		assert.Equal(t, userID, a.UserID)
		assert.Equal(t, keyID, a.KeyID)
		assert.Equal(t, "t1", a.TenantID)
		assert.Equal(t, []string{"s1"}, a.Scopes)
	})

	t.Run("Service leaves UserID zero and anchors on the key ID", func(t *testing.T) {
		a := tokens.ActorFromAPIKey(&tokens.APIKey[struct{}]{
			ID:       keyID,
			TenantID: "t1",
			Type:     tokens.KeyTypeService,
			Claims:   tokens.Claims[struct{}]{Subject: keyID},
		})
		assert.Equal(t, egauth.Service, a.Kind)
		assert.Equal(t, uuid.UUID{}, a.UserID)
		assert.Equal(t, keyID, a.KeyID)
		assert.True(t, a.IsMachine())
	})

	t.Run("unclassified key defaults to a human User, never a machine", func(t *testing.T) {
		a := tokens.ActorFromAPIKey(&tokens.APIKey[struct{}]{
			ID:     keyID,
			Type:   "", // zero value
			Claims: tokens.Claims[struct{}]{Subject: userID},
		})
		assert.Equal(t, egauth.User, a.Kind)
		assert.Equal(t, userID, a.UserID)
		assert.True(t, a.IsHuman())
		assert.False(t, a.IsMachine())
	})

	t.Run("nil key yields a zero Actor", func(t *testing.T) {
		assert.Equal(t, egauth.Actor{}, tokens.ActorFromAPIKey[struct{}](nil))
	})
}
