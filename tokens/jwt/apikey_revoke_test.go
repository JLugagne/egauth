package jwt_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// revokeTestStore is an in-memory store that backs Save/Find/Revoke/List so the revoked state
// round-trips through the verify layer (FindAPIKeyByHash keeps returning a revoked key with its
// RevokedAt populated, exactly as the real adapters do). It is the minimum store needed to exercise
// the issuer's revoke/list passthrough and the verify-layer rejection.
type revokeTestStore struct {
	mu       sync.Mutex
	byHash   map[string]*tokens.APIKey[MyCustomClaims]
	byID     map[uuid.UUID]*tokens.APIKey[MyCustomClaims]
	now      func() time.Time
}

func newRevokeTestStore(now func() time.Time) *revokeTestStore {
	return &revokeTestStore{
		byHash: make(map[string]*tokens.APIKey[MyCustomClaims]),
		byID:   make(map[uuid.UUID]*tokens.APIKey[MyCustomClaims]),
		now:    now,
	}
}

// asMockStore wires the in-memory backing into a storetest.MockStore so it satisfies tokens.Store.
func (s *revokeTestStore) asMockStore() *storetest.MockStore[MyCustomClaims] {
	return &storetest.MockStore[MyCustomClaims]{
		SaveAPIKeyFunc: func(_ context.Context, _ string, key *tokens.APIKey[MyCustomClaims]) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			cp := *key
			s.byHash[key.Hash] = &cp
			s.byID[key.ID] = &cp
			return nil
		},
		FindAPIKeyByHashFunc: func(_ context.Context, _ string, hash string) (*tokens.APIKey[MyCustomClaims], error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			key, ok := s.byHash[hash]
			if !ok {
				return nil, tokens.ErrAPIKeyNotFound
			}
			cp := *key
			return &cp, nil
		},
		RevokeAPIKeyFunc: func(_ context.Context, _ string, keyID uuid.UUID) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			key, ok := s.byID[keyID]
			if !ok {
				return tokens.ErrAPIKeyNotFound
			}
			if key.RevokedAt != nil {
				// Already revoked: no-op, do not advance RevokedAt.
				return nil
			}
			t := s.now()
			key.RevokedAt = &t
			return nil
		},
		ListAPIKeysByCreatorFunc: func(_ context.Context, _ string, createdBy uuid.UUID) ([]*tokens.APIKey[MyCustomClaims], error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			out := make([]*tokens.APIKey[MyCustomClaims], 0)
			for _, key := range s.byID {
				if key.CreatedBy == createdBy {
					cp := *key
					cp.Token = "" // clear-text exists only at creation
					out = append(out, &cp)
				}
			}
			return out, nil
		},
	}
}

// capturingSink records every emitted event for assertions.
type capturingSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (c *capturingSink) EmitEvent(_ context.Context, e event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *capturingSink) typed(t event.Type) []event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []event.Event
	for _, e := range c.events {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

// newRevokeService builds a Service over a revoke-capable in-memory store with a frozen clock and a
// capturing event sink, so a test can both drive the lifecycle and inspect the emitted audit trail.
func newRevokeService(t *testing.T, now time.Time) (*jwt.Service[MyCustomClaims], *revokeTestStore, *capturingSink) {
	t.Helper()
	sink := &capturingSink{}
	store := newRevokeTestStore(func() time.Time { return now })
	cfg := jwt.Config[MyCustomClaims]{
		Store:      store.asMockStore(),
		SecretKey:  "super-secret-key-for-testing----", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		EventSink:  sink,
		Clock:      func() time.Time { return now },
	}
	return jwt.New[MyCustomClaims](cfg), store, sink
}

// TestVerifyAPIKeyRejectsRevoked is the core lifecycle proof: a revoked key is rejected with the
// distinct ErrAPIKeyRevoked on every verify path, while an active key still verifies.
func TestVerifyAPIKeyRejectsRevoked(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-abc"
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

	t.Run("revoked key -> ErrAPIKeyRevoked (VerifyAPIKey)", func(t *testing.T) {
		svc, _, _ := newRevokeService(t, now)
		creatorID := uuid.Must(uuid.NewV7())

		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[MyCustomClaims]{
			Subject:  uuid.Must(uuid.NewV7()),
			TenantID: tenant,
			Scopes:   []string{"repo:read"},
		})
		require.NoError(t, err)

		// Active key verifies before revocation.
		_, err = svc.VerifyAPIKey(ctx, tenant, key.Token)
		require.NoError(t, err)

		require.NoError(t, svc.RevokeAPIKey(ctx, tenant, key.ID))

		_, err = svc.VerifyAPIKey(ctx, tenant, key.Token)
		require.ErrorIs(t, err, tokens.ErrAPIKeyRevoked, "a revoked key must fail with ErrAPIKeyRevoked")
	})

	t.Run("revoked key -> ErrAPIKeyRevoked (VerifyAPIKeyActor)", func(t *testing.T) {
		svc, _, _ := newRevokeService(t, now)
		creatorID := uuid.Must(uuid.NewV7())

		key, err := svc.IssueAPIKey(ctx, "sk_svc_", tokens.KeyTypeService, creatorID, tokens.Claims[MyCustomClaims]{
			TenantID: tenant,
			Scopes:   []string{"ingest:write"},
		})
		require.NoError(t, err)
		require.NoError(t, svc.RevokeAPIKey(ctx, tenant, key.ID))

		_, _, err = svc.VerifyAPIKeyActor(ctx, tenant, key.Token)
		require.ErrorIs(t, err, tokens.ErrAPIKeyRevoked, "VerifyAPIKeyActor must also reject a revoked key")
	})

	t.Run("active key still verifies after an unrelated key is revoked", func(t *testing.T) {
		svc, _, _ := newRevokeService(t, now)
		creatorID := uuid.Must(uuid.NewV7())

		toRevoke, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[MyCustomClaims]{
			Subject: uuid.Must(uuid.NewV7()), TenantID: tenant, Scopes: []string{"repo:read"},
		})
		require.NoError(t, err)
		active, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[MyCustomClaims]{
			Subject: uuid.Must(uuid.NewV7()), TenantID: tenant, Scopes: []string{"repo:read"},
		})
		require.NoError(t, err)

		require.NoError(t, svc.RevokeAPIKey(ctx, tenant, toRevoke.ID))

		_, err = svc.VerifyAPIKey(ctx, tenant, active.Token)
		require.NoError(t, err, "revoking one key must not affect another active key")
	})
}

// TestRevokedVsExpiredAreDistinct proves the two failure modes return different errors and that the
// revoked check is evaluated before expiry (a key that is both revoked and expired reports revoked).
func TestRevokedVsExpiredAreDistinct(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-abc"
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

	t.Run("expired (not revoked) -> ErrTokenExpired", func(t *testing.T) {
		svc, _, _ := newRevokeService(t, now)
		creatorID := uuid.Must(uuid.NewV7())

		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[MyCustomClaims]{
			Subject:   uuid.Must(uuid.NewV7()),
			TenantID:  tenant,
			Scopes:    []string{"repo:read"},
			ExpiresAt: now.Add(-time.Hour), // already expired against the frozen clock
		})
		require.NoError(t, err)

		_, err = svc.VerifyAPIKey(ctx, tenant, key.Token)
		require.ErrorIs(t, err, tokens.ErrTokenExpired)
		require.NotErrorIs(t, err, tokens.ErrAPIKeyRevoked, "an expired-only key must not report as revoked")
	})

	t.Run("revoked (not expired) -> ErrAPIKeyRevoked", func(t *testing.T) {
		svc, _, _ := newRevokeService(t, now)
		creatorID := uuid.Must(uuid.NewV7())

		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[MyCustomClaims]{
			Subject:   uuid.Must(uuid.NewV7()),
			TenantID:  tenant,
			Scopes:    []string{"repo:read"},
			ExpiresAt: now.Add(time.Hour), // still valid
		})
		require.NoError(t, err)
		require.NoError(t, svc.RevokeAPIKey(ctx, tenant, key.ID))

		_, err = svc.VerifyAPIKey(ctx, tenant, key.Token)
		require.ErrorIs(t, err, tokens.ErrAPIKeyRevoked)
		require.NotErrorIs(t, err, tokens.ErrTokenExpired, "a revoked-but-unexpired key must not report as expired")
	})

	t.Run("both revoked and expired -> ErrAPIKeyRevoked (revoked checked first)", func(t *testing.T) {
		svc, _, _ := newRevokeService(t, now)
		creatorID := uuid.Must(uuid.NewV7())

		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[MyCustomClaims]{
			Subject:   uuid.Must(uuid.NewV7()),
			TenantID:  tenant,
			Scopes:    []string{"repo:read"},
			ExpiresAt: now.Add(-time.Hour), // expired
		})
		require.NoError(t, err)
		require.NoError(t, svc.RevokeAPIKey(ctx, tenant, key.ID))

		_, err = svc.VerifyAPIKey(ctx, tenant, key.Token)
		require.ErrorIs(t, err, tokens.ErrAPIKeyRevoked, "revocation takes precedence over expiry")
	})
}

// TestRevokeAPIKeyEmitsAuditEvent proves RevokeAPIKey emits a single api_key.revoked event carrying
// the key_id and no secret, and that a failed store revoke emits nothing.
func TestRevokeAPIKeyEmitsAuditEvent(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-abc"
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

	t.Run("successful revoke emits api_key.revoked with key_id and no secret", func(t *testing.T) {
		svc, _, sink := newRevokeService(t, now)
		creatorID := uuid.Must(uuid.NewV7())

		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[MyCustomClaims]{
			Subject: uuid.Must(uuid.NewV7()), TenantID: tenant, Scopes: []string{"repo:read"},
		})
		require.NoError(t, err)

		require.NoError(t, svc.RevokeAPIKey(ctx, tenant, key.ID))

		revoked := sink.typed(event.APIKeyRevoked)
		require.Len(t, revoked, 1, "exactly one api_key.revoked event must be emitted")
		e := revoked[0]
		assert.Equal(t, tenant, e.TenantID)
		assert.Equal(t, key.ID.String(), e.Attrs["key_id"])
		// No secret leaks: neither the clear-text token nor its hash appear anywhere in Attrs.
		for k, v := range e.Attrs {
			assert.NotEqual(t, key.Token, v, "Attrs[%s] must not carry the clear-text token", k)
			assert.NotEqual(t, key.Hash, v, "Attrs[%s] must not carry the token hash", k)
		}
	})

	t.Run("missing key returns ErrAPIKeyNotFound and emits no event", func(t *testing.T) {
		svc, _, sink := newRevokeService(t, now)

		err := svc.RevokeAPIKey(ctx, tenant, uuid.Must(uuid.NewV7()))
		require.ErrorIs(t, err, tokens.ErrAPIKeyNotFound)
		assert.Empty(t, sink.typed(event.APIKeyRevoked), "no event must be emitted when the store revoke fails")
	})
}

// TestListAPIKeysByCreator proves the issuer's list passthrough returns the issued keys and surfaces
// revocation state (RevokedAt populated) while never carrying the clear-text token.
func TestListAPIKeysByCreator(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-abc"
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

	svc, _, _ := newRevokeService(t, now)
	creatorID := uuid.Must(uuid.NewV7())
	otherCreator := uuid.Must(uuid.NewV7())

	k1, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[MyCustomClaims]{
		Subject: uuid.Must(uuid.NewV7()), TenantID: tenant, Scopes: []string{"repo:read"},
	})
	require.NoError(t, err)
	k2, err := svc.IssueAPIKey(ctx, "sk_svc_", tokens.KeyTypeService, creatorID, tokens.Claims[MyCustomClaims]{
		TenantID: tenant, Scopes: []string{"ingest:write"},
	})
	require.NoError(t, err)
	// A key from a different creator must not appear in creatorID's listing.
	_, err = svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, otherCreator, tokens.Claims[MyCustomClaims]{
		Subject: uuid.Must(uuid.NewV7()), TenantID: tenant, Scopes: []string{"repo:read"},
	})
	require.NoError(t, err)

	require.NoError(t, svc.RevokeAPIKey(ctx, tenant, k2.ID))

	list, err := svc.ListAPIKeysByCreator(ctx, tenant, creatorID)
	require.NoError(t, err)
	require.Len(t, list, 2, "the creator's two keys must be listed, excluding other creators")

	byID := make(map[uuid.UUID]*tokens.APIKey[MyCustomClaims], len(list))
	for _, k := range list {
		assert.Empty(t, k.Token, "listed keys must never carry the clear-text token")
		byID[k.ID] = k
	}
	require.Contains(t, byID, k1.ID)
	require.Contains(t, byID, k2.ID)
	assert.Nil(t, byID[k1.ID].RevokedAt, "the un-revoked key must report a nil RevokedAt")
	assert.NotNil(t, byID[k2.ID].RevokedAt, "the revoked key must surface its RevokedAt to management tooling")

	t.Run("creator with no keys returns an empty non-nil slice", func(t *testing.T) {
		empty, err := svc.ListAPIKeysByCreator(ctx, tenant, uuid.Must(uuid.NewV7()))
		require.NoError(t, err)
		require.NotNil(t, empty)
		assert.Empty(t, empty)
	})
}

// TestSingleTenantRevokeAndList proves the SingleTenant wrapper binds the empty tenant for both new
// methods: a key issued and revoked through the wrapper is rejected, and listing returns it.
func TestSingleTenantRevokeAndList(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

	svc, _, _ := newRevokeService(t, now)
	st := jwt.NewSingleTenant(svc)
	creatorID := uuid.Must(uuid.NewV7())

	// Empty TenantID on claims => the single-tenant default partition.
	key, err := st.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[MyCustomClaims]{
		Subject: uuid.Must(uuid.NewV7()), Scopes: []string{"repo:read"},
	})
	require.NoError(t, err)

	_, err = st.VerifyAPIKey(ctx, key.Token)
	require.NoError(t, err)

	require.NoError(t, st.RevokeAPIKey(ctx, key.ID))

	_, err = st.VerifyAPIKey(ctx, key.Token)
	require.ErrorIs(t, err, tokens.ErrAPIKeyRevoked, "wrapper revoke must bind the empty tenant and reject the key")

	list, err := st.ListAPIKeysByCreator(ctx, creatorID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, key.ID, list[0].ID)
	assert.NotNil(t, list[0].RevokedAt)
}
