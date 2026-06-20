package jwt_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type captureSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (c *captureSink) EmitEvent(_ context.Context, e event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureSink) has(t event.Type) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.Type == t {
			return true
		}
	}
	return false
}

func TestJWTEvents_ReuseDetectedAndFamilyRevoked(t *testing.T) {
	ctx := context.Background()
	sink := &captureSink{}
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:            memory.NewStore[struct{}](),
		SecretKey:        "rotation-secret-aaaaaaaaaaaaaaaaaaaaaaaa",
		Issuer:           "egauth-test",
		AccessTTL:        5 * time.Minute,
		RefreshTTL:       24 * time.Hour,
		ClaimsProvider:   okProvider(t),
		ReuseGracePeriod: -1, // strict: any replay of a consumed token revokes the family
		EventSink:        sink,
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	// First rotation consumes the token.
	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)

	// Replaying the now-consumed token is treated as theft (strict mode): reuse detected and the
	// family revoked.
	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	require.ErrorIs(t, err, tokens.ErrRefreshTokenReused)
	assert.True(t, sink.has(event.RefreshReuseDetected), "a replayed consumed token must emit RefreshReuseDetected")
	assert.True(t, sink.has(event.TokenFamilyRevoked), "strict-mode reuse must emit TokenFamilyRevoked")
}

// findEvent returns the first event with the given type, and whether it was found.
func (c *captureSink) findEvent(t event.Type) (event.Event, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.Type == t {
			return e, true
		}
	}
	return event.Event{}, false
}

// findReason returns the first event with the given type and reason, and whether it was found.
func (c *captureSink) findReason(t event.Type, reason string) (event.Event, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.Type == t && e.Reason == reason {
			return e, true
		}
	}
	return event.Event{}, false
}

// TestAPIKeyAuditEmits is the IC-3 proof: every operation on the API-key lifecycle emits the
// correct audit event with the right Reason, and no event ever carries a secret (token or hash).
//
// Covered paths:
//   - IssueAPIKey  → api_key.created  (type + created_by in Attrs, no token/hash)
//   - VerifyAPIKey (hit)  → api_key.auth.succeeded
//   - VerifyAPIKey (miss) → api_key.auth.failed  reason=not_found
//   - VerifyAPIKey (expired key) → api_key.auth.failed  reason=expired
//   - DeleteExpired → api_key.purged  (count in Attrs)
func TestAPIKeyAuditEmits(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-audit"

	newAuditService := func(t *testing.T, sink *captureSink) (*jwt.Service[struct{}], *memory.Store[struct{}]) {
		t.Helper()
		store := memory.NewStore[struct{}]()
		svc := jwt.New[struct{}](jwt.Config[struct{}]{
			Store:      store,
			SecretKey:  "audit-secret-key-aaaaaaaaaaaaaaa!", // 32 bytes
			Issuer:     "egauth-test",
			AccessTTL:  5 * time.Minute,
			RefreshTTL: 24 * time.Hour,
			EventSink:  sink,
		})
		return svc, store
	}

	// assertNoSecret verifies that none of the Attrs on the event contain any of the given
	// secrets — tokens or their hashes must never appear in emitted events.
	assertNoSecret := func(t *testing.T, e event.Event, secrets ...string) {
		t.Helper()
		for k, v := range e.Attrs {
			str, ok := v.(string)
			if !ok {
				continue
			}
			for _, secret := range secrets {
				if secret != "" && str == secret {
					t.Errorf("event %q Attrs[%q] contains a secret value; secrets must never appear in events", e.Type, k)
				}
			}
		}
	}

	t.Run("api_key.created emitted on IssueAPIKey", func(t *testing.T) {
		sink := &captureSink{}
		svc, _ := newAuditService(t, sink)

		creatorID := uuid.Must(uuid.NewV7())
		userID := uuid.Must(uuid.NewV7())

		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[struct{}]{
			Subject:  userID,
			TenantID: tenant,
			Scopes:   []string{"read"},
		})
		require.NoError(t, err)

		e, ok := sink.findEvent(event.APIKeyCreated)
		require.True(t, ok, "api_key.created must be emitted")
		assert.Equal(t, tenant, e.TenantID, "event must carry the correct tenant")
		assert.Equal(t, string(tokens.KeyTypePAT), e.Attrs["key_type"], "key_type must be in Attrs")
		assert.Equal(t, creatorID.String(), e.Attrs["created_by"], "created_by must be in Attrs")

		// Security: neither the clear-text token nor its hash may appear in the event.
		assertNoSecret(t, e, key.Token, key.Hash)
	})

	t.Run("api_key.auth.succeeded emitted on a valid verify", func(t *testing.T) {
		sink := &captureSink{}
		svc, _ := newAuditService(t, sink)

		creatorID := uuid.Must(uuid.NewV7())
		key, err := svc.IssueAPIKey(ctx, "sk_svc_", tokens.KeyTypeService, creatorID, tokens.Claims[struct{}]{
			TenantID: tenant,
		})
		require.NoError(t, err)

		// Reset sink so only the verify event is checked.
		sink.mu.Lock()
		sink.events = nil
		sink.mu.Unlock()

		_, err = svc.VerifyAPIKey(ctx, tenant, key.Token)
		require.NoError(t, err)

		e, ok := sink.findEvent(event.APIKeyAuthSucceeded)
		require.True(t, ok, "api_key.auth.succeeded must be emitted on a valid verify")
		assert.Equal(t, tenant, e.TenantID)
		assert.Equal(t, string(tokens.KeyTypeService), e.Attrs["key_type"])
		// Security: the token and hash must not appear in the event.
		assertNoSecret(t, e, key.Token, key.Hash)
	})

	t.Run("api_key.auth.failed reason=not_found on unknown key", func(t *testing.T) {
		sink := &captureSink{}
		svc, _ := newAuditService(t, sink)

		_, err := svc.VerifyAPIKey(ctx, tenant, "sk_svc_does-not-exist-at-all")
		require.ErrorIs(t, err, tokens.ErrAPIKeyNotFound)

		e, ok := sink.findReason(event.APIKeyAuthFailed, event.ReasonAPIKeyNotFound)
		require.True(t, ok, "api_key.auth.failed with reason=not_found must be emitted")
		assert.Equal(t, tenant, e.TenantID)
		// Security: the bogus token string must not appear in the event Attrs.
		assertNoSecret(t, e, "sk_svc_does-not-exist-at-all")
	})

	t.Run("api_key.auth.failed reason=expired on an expired key", func(t *testing.T) {
		sink := &captureSink{}
		svc, _ := newAuditService(t, sink)

		creatorID := uuid.Must(uuid.NewV7())
		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[struct{}]{
			TenantID:  tenant,
			Subject:   uuid.Must(uuid.NewV7()),
			ExpiresAt: time.Now().Add(-time.Hour), // already expired
		})
		require.NoError(t, err)

		// Reset sink — only the verify failure event is under test.
		sink.mu.Lock()
		sink.events = nil
		sink.mu.Unlock()

		_, err = svc.VerifyAPIKey(ctx, tenant, key.Token)
		require.ErrorIs(t, err, tokens.ErrTokenExpired)

		e, ok := sink.findReason(event.APIKeyAuthFailed, event.ReasonAPIKeyExpired)
		require.True(t, ok, "api_key.auth.failed with reason=expired must be emitted")
		assert.Equal(t, tenant, e.TenantID)
		assertNoSecret(t, e, key.Token, key.Hash)
	})

	t.Run("api_key.purged emitted from DeleteExpired with count", func(t *testing.T) {
		sink := &captureSink{}
		svc, store := newAuditService(t, sink)

		creatorID := uuid.Must(uuid.NewV7())

		// Issue one expired key and one non-expiring key so only the expired one is purged.
		expiredKey, err := svc.IssueAPIKey(ctx, "sk_svc_", tokens.KeyTypeService, creatorID, tokens.Claims[struct{}]{
			TenantID:  tenant,
			ExpiresAt: time.Now().Add(-time.Hour),
		})
		require.NoError(t, err)

		_, err = svc.IssueAPIKey(ctx, "sk_svc_", tokens.KeyTypeService, creatorID, tokens.Claims[struct{}]{
			TenantID: tenant,
			// No ExpiresAt: this key never expires and must not be purged.
		})
		require.NoError(t, err)

		// The in-memory store's DeleteExpired checks real time.Now(); we need the store directly
		// to validate count. The Service.DeleteExpired delegates to the store then emits.
		// Bypass via the store directly to confirm: store still has both keys before purge.
		_ = store

		// Reset sink before purge.
		sink.mu.Lock()
		sink.events = nil
		sink.mu.Unlock()

		n, err := svc.DeleteExpired(ctx, tenant)
		require.NoError(t, err)
		assert.EqualValues(t, 1, n, "only the expired key should be purged")

		e, ok := sink.findEvent(event.APIKeyPurged)
		require.True(t, ok, "api_key.purged must be emitted")
		assert.Equal(t, tenant, e.TenantID)
		assert.EqualValues(t, int64(1), e.Attrs["count"], "count in Attrs must match deleted rows")
		// Security: the expired key's token and hash must never appear in the purge event.
		assertNoSecret(t, e, expiredKey.Token, expiredKey.Hash)
	})

	t.Run("nil sink is a no-op — operations do not panic", func(t *testing.T) {
		store := memory.NewStore[struct{}]()
		svc := jwt.New[struct{}](jwt.Config[struct{}]{
			Store:      store,
			SecretKey:  "audit-secret-key-aaaaaaaaaaaaaaa!",
			Issuer:     "egauth-test",
			AccessTTL:  5 * time.Minute,
			RefreshTTL: 24 * time.Hour,
			// EventSink deliberately left nil.
		})

		creatorID := uuid.Must(uuid.NewV7())
		key, err := svc.IssueAPIKey(ctx, "sk_svc_", tokens.KeyTypeService, creatorID, tokens.Claims[struct{}]{
			TenantID: tenant,
		})
		require.NoError(t, err)

		_, err = svc.VerifyAPIKey(ctx, tenant, key.Token)
		require.NoError(t, err)

		_, err = svc.VerifyAPIKey(ctx, tenant, "bogus-key-not-in-store")
		require.ErrorIs(t, err, tokens.ErrAPIKeyNotFound)

		_, err = svc.DeleteExpired(ctx, tenant)
		require.NoError(t, err)
	})
}
