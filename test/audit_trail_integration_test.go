// TestAuditTrail is the IC-3 / IC-4 integration proof for milestone M8.
//
// IC-3 (key-lifecycle audit): a capturing Sink receives the correct event Types with the correct
// Attrs across the full API-key lifecycle — create → auth-ok → auth-fail(each reason) → purge —
// and none of those events ever carry a secret (token value or hash).
//
// IC-4 (login IP): a successful login with a RequestContext lands the client IP in
// Event.Attrs["ip"] on the login.succeeded event.
//
// Both sub-tests share the same capturing Sink helper defined here, which duplicates a tiny local
// implementation rather than pulling in the per-package helpers, so this file has no hidden
// coupling to the internal test packages.
package internal_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	tokensmemory "github.com/JLugagne/egauth/tokens/memory"
	"github.com/JLugagne/egauth/tokens/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditSink is a thread-safe capturing Sink used across all audit-trail sub-tests.
type auditSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (s *auditSink) EmitEvent(_ context.Context, e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

// reset clears captured events so only the next operation is asserted.
func (s *auditSink) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = nil
}

// find returns the first event with the given type, and whether it was found.
func (s *auditSink) find(t event.Type) (event.Event, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if e.Type == t {
			return e, true
		}
	}
	return event.Event{}, false
}

// findReason returns the first event with the given type and reason, and whether it was found.
func (s *auditSink) findReason(t event.Type, reason string) (event.Event, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if e.Type == t && e.Reason == reason {
			return e, true
		}
	}
	return event.Event{}, false
}

// assertNoSecrets checks that none of the string Attr values in any captured event equal any of
// the supplied secret strings. Token values and their hashes are opaque, unique strings that must
// never appear verbatim in emitted audit events — an exact-equality check is the correct guard.
// (A substring check would produce false positives for trivially short mock values used in tests.)
func assertNoSecrets(t *testing.T, sink *auditSink, secrets ...string) {
	t.Helper()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, e := range sink.events {
		for k, v := range e.Attrs {
			str, ok := v.(string)
			if !ok {
				continue
			}
			for _, secret := range secrets {
				if secret != "" && str == secret {
					t.Errorf(
						"event %q Attrs[%q] = %q is a secret value; "+
							"secrets (tokens, hashes) must never appear verbatim in audit events",
						e.Type, k, str,
					)
				}
			}
		}
	}
}

// newAuditJWTService returns a jwt.Service wired with the given sink and an in-memory store.
// The secret key is exactly 32 bytes so it passes the minimum-strength check.
func newAuditJWTService(sink event.Sink) *jwt.Service[struct{}] {
	return jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      tokensmemory.NewStore[struct{}](),
		SecretKey:  "audit-trail-secret-key----------", // 32 bytes
		Issuer:     "egauth-audit-trail-test",
		AccessTTL:  5 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		EventSink:  sink,
	})
}

// TestAuditTrail is the IC-3 and IC-4 integration proof for M8.
//
// It uses only in-memory stores and real egauth services so it needs no external dependencies.
func TestAuditTrail(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-audit-trail"

	// -------------------------------------------------------------------------
	// IC-3: full API-key lifecycle audit
	// -------------------------------------------------------------------------

	t.Run("IC-3 api_key.created carries type and created_by, no secrets", func(t *testing.T) {
		sink := &auditSink{}
		svc := newAuditJWTService(sink)

		creatorID := uuid.Must(uuid.NewV7())
		userID := uuid.Must(uuid.NewV7())

		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[struct{}]{
			Subject:  userID,
			TenantID: tenant,
			Scopes:   []string{"read"},
		})
		require.NoError(t, err)

		e, ok := sink.find(event.APIKeyCreated)
		require.True(t, ok, "api_key.created must be emitted after IssueAPIKey")
		assert.Equal(t, tenant, e.TenantID, "event must carry the issuing tenant")
		assert.Equal(t, string(tokens.KeyTypePAT), e.Attrs["key_type"],
			"key_type must be present in Attrs")
		assert.Equal(t, creatorID.String(), e.Attrs["created_by"],
			"created_by must be the creator UUID string")
		// The raw token and its hash are secrets and must never appear in any event.
		assertNoSecrets(t, sink, key.Token, key.Hash)
	})

	t.Run("IC-3 api_key.auth.succeeded carries key_type, no secrets", func(t *testing.T) {
		sink := &auditSink{}
		svc := newAuditJWTService(sink)

		creatorID := uuid.Must(uuid.NewV7())
		key, err := svc.IssueAPIKey(ctx, "sk_svc_", tokens.KeyTypeService, creatorID, tokens.Claims[struct{}]{
			TenantID: tenant,
		})
		require.NoError(t, err)

		// Reset: assert only the verify event.
		sink.reset()

		_, err = svc.VerifyAPIKey(ctx, tenant, key.Token)
		require.NoError(t, err)

		e, ok := sink.find(event.APIKeyAuthSucceeded)
		require.True(t, ok, "api_key.auth.succeeded must be emitted on a valid verify")
		assert.Equal(t, tenant, e.TenantID)
		assert.Equal(t, string(tokens.KeyTypeService), e.Attrs["key_type"],
			"key_type must be present in the success event")
		assertNoSecrets(t, sink, key.Token, key.Hash)
	})

	t.Run("IC-3 api_key.auth.failed reason=not_found on unknown token, no secrets", func(t *testing.T) {
		sink := &auditSink{}
		svc := newAuditJWTService(sink)

		bogusToken := "sk_svc_this-key-does-not-exist-in-the-store"

		_, err := svc.VerifyAPIKey(ctx, tenant, bogusToken)
		require.ErrorIs(t, err, tokens.ErrAPIKeyNotFound)

		e, ok := sink.findReason(event.APIKeyAuthFailed, event.ReasonAPIKeyNotFound)
		require.True(t, ok, "api_key.auth.failed with reason=not_found must be emitted")
		assert.Equal(t, tenant, e.TenantID)
		// The bogus token string must not appear verbatim in any Attr.
		assertNoSecrets(t, sink, bogusToken)
	})

	t.Run("IC-3 api_key.auth.failed reason=expired on an expired key, no secrets", func(t *testing.T) {
		sink := &auditSink{}
		svc := newAuditJWTService(sink)

		creatorID := uuid.Must(uuid.NewV7())
		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[struct{}]{
			TenantID:  tenant,
			Subject:   uuid.Must(uuid.NewV7()),
			ExpiresAt: time.Now().Add(-time.Hour), // already expired at issuance
		})
		require.NoError(t, err)

		sink.reset()

		_, err = svc.VerifyAPIKey(ctx, tenant, key.Token)
		require.ErrorIs(t, err, tokens.ErrTokenExpired)

		e, ok := sink.findReason(event.APIKeyAuthFailed, event.ReasonAPIKeyExpired)
		require.True(t, ok, "api_key.auth.failed with reason=expired must be emitted")
		assert.Equal(t, tenant, e.TenantID)
		assertNoSecrets(t, sink, key.Token, key.Hash)
	})

	t.Run("IC-3 api_key.auth.failed reason=tenant_mismatch when store signals mismatch", func(t *testing.T) {
		// The memory store returns ErrAPIKeyNotFound for cross-tenant lookups (tenant-scoped WHERE
		// clause), not ErrTenantMismatch. Use a mock store to exercise the tenant_mismatch branch
		// in verifyAPIKey, which maps ErrTenantMismatch → ReasonAPIKeyTenantMismatch.
		sink := &auditSink{}

		mockStore := &storetest.MockStore[struct{}]{
			SaveAPIKeyFunc: func(_ context.Context, _ string, _ *tokens.APIKey[struct{}]) error {
				return nil
			},
			FindAPIKeyByHashFunc: func(_ context.Context, _ string, _ string) (*tokens.APIKey[struct{}], error) {
				return nil, tokens.ErrTenantMismatch
			},
			DeleteExpiredFunc: func(_ context.Context, _ string) (int64, error) {
				return 0, nil
			},
		}

		svc := jwt.New[struct{}](jwt.Config[struct{}]{
			Store:      mockStore,
			SecretKey:  "audit-trail-secret-key----------",
			Issuer:     "egauth-audit-trail-test",
			AccessTTL:  5 * time.Minute,
			RefreshTTL: 24 * time.Hour,
			EventSink:  sink,
		})

		_, err := svc.VerifyAPIKey(ctx, tenant, "sk_svc_any-token")
		require.ErrorIs(t, err, tokens.ErrTenantMismatch)

		e, ok := sink.findReason(event.APIKeyAuthFailed, event.ReasonAPIKeyTenantMismatch)
		require.True(t, ok, "api_key.auth.failed with reason=tenant_mismatch must be emitted when the store returns ErrTenantMismatch")
		assert.Equal(t, tenant, e.TenantID)
		assertNoSecrets(t, sink, "sk_svc_any-token")
	})

	t.Run("IC-3 api_key.purged carries count, no secrets", func(t *testing.T) {
		sink := &auditSink{}
		svc := newAuditJWTService(sink)

		creatorID := uuid.Must(uuid.NewV7())

		// Issue one key that is already expired.
		expiredKey, err := svc.IssueAPIKey(ctx, "sk_svc_", tokens.KeyTypeService, creatorID, tokens.Claims[struct{}]{
			TenantID:  tenant,
			ExpiresAt: time.Now().Add(-time.Hour),
		})
		require.NoError(t, err)

		// Issue one non-expiring key — it must survive the purge.
		_, err = svc.IssueAPIKey(ctx, "sk_svc_", tokens.KeyTypeService, creatorID, tokens.Claims[struct{}]{
			TenantID: tenant,
		})
		require.NoError(t, err)

		sink.reset()

		n, err := svc.DeleteExpired(ctx, tenant)
		require.NoError(t, err)
		assert.EqualValues(t, 1, n, "only the expired key must be purged")

		e, ok := sink.find(event.APIKeyPurged)
		require.True(t, ok, "api_key.purged must be emitted")
		assert.Equal(t, tenant, e.TenantID)
		assert.EqualValues(t, int64(1), e.Attrs["count"],
			"count in Attrs must match the number of deleted rows")
		// The expired key's token and hash must not appear in the purge event.
		assertNoSecrets(t, sink, expiredKey.Token, expiredKey.Hash)
	})

	// -------------------------------------------------------------------------
	// IC-4: login with RequestContext lands client IP in login.succeeded
	// -------------------------------------------------------------------------

	t.Run("IC-4 login.succeeded carries client IP from RequestContext", func(t *testing.T) {
		const clientIP = "203.0.113.55"
		const userAgent = "egauth-integration-test/1.0"

		sink := &auditSink{}

		hasher := &hashertest.MockHasher{
			HashFunc:    func(_ context.Context, _ string) (string, error) { return "h", nil },
			CompareFunc: func(_ context.Context, _, _ string) error { return nil }, // password always matches
		}
		idSvc := identity.NewService(
			identitymemory.NewStore(),
			hasher,
			&auditTrailPolicy{},
			identity.WithEventSink(sink),
		)

		_, err := idSvc.Register(ctx, tenant, "user@audit-trail.example", "pw")
		require.NoError(t, err)

		sink.reset()

		_, err = idSvc.Authenticate(ctx, tenant, "password", "user@audit-trail.example", "pw",
			event.RequestContext{IP: clientIP, UserAgent: userAgent},
		)
		require.NoError(t, err)

		e, ok := sink.find(event.LoginSucceeded)
		require.True(t, ok, "login.succeeded must be emitted on successful authentication")
		assert.Equal(t, clientIP, e.Attrs[event.AttrIP],
			"client IP must be present in login.succeeded Attrs")
		assert.Equal(t, userAgent, e.Attrs[event.AttrUserAgent],
			"User-Agent must be present in login.succeeded Attrs")
		// The plain-text password must never appear in any event Attr. The mock hasher
		// returns "h" which is a single-char stub, not a real credential — only the
		// plaintext is checked here; real deployments use long argon2 hashes which
		// would trivially not match any IP/UA string in Attrs.
		assertNoSecrets(t, sink, "pw")
	})

	t.Run("IC-4 login.succeeded omits IP when no RequestContext supplied", func(t *testing.T) {
		sink := &auditSink{}

		hasher := &hashertest.MockHasher{
			HashFunc:    func(_ context.Context, _ string) (string, error) { return "h", nil },
			CompareFunc: func(_ context.Context, _, _ string) error { return nil },
		}
		idSvc := identity.NewService(
			identitymemory.NewStore(),
			hasher,
			&auditTrailPolicy{},
			identity.WithEventSink(sink),
		)

		_, err := idSvc.Register(ctx, tenant, "user2@audit-trail.example", "pw")
		require.NoError(t, err)

		sink.reset()

		_, err = idSvc.Authenticate(ctx, tenant, "password", "user2@audit-trail.example", "pw")
		require.NoError(t, err)

		e, ok := sink.find(event.LoginSucceeded)
		require.True(t, ok, "login.succeeded must be emitted")
		_, hasIP := e.Attrs[event.AttrIP]
		assert.False(t, hasIP, "absent RequestContext must omit the IP attribute")
	})
}

// auditTrailPolicy is a permissive password policy for integration tests: the audit behaviour,
// not password strength, is the subject of TestAuditTrail.
type auditTrailPolicy struct{}

func (auditTrailPolicy) Verify(_ context.Context, _ string) error { return nil }
