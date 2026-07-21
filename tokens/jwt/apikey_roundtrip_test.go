package jwt_test

import (
	"context"
	"testing"

	egauth "github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIKeyRoundTrip is the IC-1 / IC-2 integration proof: issuing then verifying each key
// type via VerifyAPIKeyActor yields the correct Actor classification, subject, scopes, and
// attribution — with no external dependencies.
//
// IC-1 (PAT round-trip):   issue PAT  → verify → Actor.Kind==PAT, IsHuman(), Subject==user,
//
//	Scopes==exactly those issued (no silent role copy).
//
// IC-2 (Service round-trip): issue Service → verify → Actor.Kind==Service, IsMachine(),
//
//	Subject==keyID (machine identity), CreatedBy==creator (human attribution).
func TestAPIKeyRoundTrip(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-abc"

	// IC-1: PAT round-trip.
	t.Run("IC-1 PAT: Actor.Kind==PAT, IsHuman, Subject==user, Scopes==issued", func(t *testing.T) {
		svc, _ := newIssueKeyService(t)
		userID := uuid.Must(uuid.NewV7())
		issuedScopes := []string{"repo:read", "repo:write"}

		// A PAT acts as its creator; Subject defaults to createdBy (the user).
		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, userID, tokens.Claims[MyCustomClaims]{
			TenantID: tenant,
			Scopes:   issuedScopes,
			// Even if the caller inadvertently passes broader roles, only Scopes drive
			// the Actor; the issuer does not widen the key's authority.
			Roles: []string{"viewer"},
		})
		require.NoError(t, err)
		require.NotNil(t, key)

		actor, claims, err := svc.VerifyAPIKeyActor(ctx, tenant, key.Token)
		require.NoError(t, err)
		require.NotNil(t, claims)

		// Kind and human/machine classification.
		assert.Equal(t, egauth.PAT, actor.Kind, "a PAT must be classified as PAT")
		assert.True(t, actor.IsHuman(), "IsHuman() must be true for a PAT")
		assert.False(t, actor.IsMachine(), "IsMachine() must be false for a PAT")

		// Subject identity: the PAT acts on behalf of the user.
		assert.Equal(t, userID, actor.UserID, "Actor.UserID must be the owning user for a PAT")
		assert.Equal(t, userID, claims.Subject, "claims.Subject must be the owning user for a PAT")

		// Key identity and tenant.
		assert.Equal(t, key.ID, actor.KeyID, "Actor.KeyID must be the key's own UUID")
		assert.Equal(t, tenant, actor.TenantID)

		// Scopes come verbatim from issuance — no widening, no implicit role copy.
		assert.Equal(t, issuedScopes, actor.Scopes, "Actor.Scopes must equal exactly the issued scopes")
		assert.Equal(t, issuedScopes, claims.Scopes, "claims.Scopes must equal exactly the issued scopes")
	})

	// IC-2: Service token round-trip.
	t.Run("IC-2 Service: Actor.Kind==Service, IsMachine, Subject==keyID, CreatedBy==creator", func(t *testing.T) {
		svc, _ := newIssueKeyService(t)
		creatorID := uuid.Must(uuid.NewV7())
		issuedScopes := []string{"ingest:write", "metrics:read"}

		key, err := svc.IssueAPIKey(ctx, "sk_svc_", tokens.KeyTypeService, creatorID, tokens.Claims[MyCustomClaims]{
			// A caller may pass a Subject for a Service token but the issuer must override
			// it with the key's own ID so the service identity is always self-anchored.
			Subject:  uuid.Must(uuid.NewV7()),
			TenantID: tenant,
			Scopes:   issuedScopes,
		})
		require.NoError(t, err)
		require.NotNil(t, key)

		actor, claims, err := svc.VerifyAPIKeyActor(ctx, tenant, key.Token)
		require.NoError(t, err)
		require.NotNil(t, claims)

		// Kind and human/machine classification.
		assert.Equal(t, egauth.Service, actor.Kind, "a Service token must be classified as Service")
		assert.True(t, actor.IsMachine(), "IsMachine() must be true for a Service token")
		assert.False(t, actor.IsHuman(), "IsHuman() must be false for a Service token")

		// Subject identity: a Service token's identity is the key itself, not its creator.
		assert.Equal(t, uuid.UUID{}, actor.UserID, "Actor.UserID must be zero for a Service token (no owning user)")
		assert.Equal(t, key.ID, actor.KeyID, "Actor.KeyID must be the key's own UUID")
		assert.Equal(t, key.ID, claims.Subject, "claims.Subject must be the key's own ID for a Service token")

		// Attribution: the human who created the key is recorded on the key itself.
		assert.Equal(t, creatorID, key.CreatedBy, "CreatedBy must record the human creator for attribution")
		assert.NotEqual(t, creatorID, actor.UserID, "the creator must not appear as the Actor's user identity")

		// Tenant and scopes.
		assert.Equal(t, tenant, actor.TenantID)
		assert.Equal(t, issuedScopes, actor.Scopes, "Actor.Scopes must equal exactly the issued scopes")
	})

	// IC-1 supplemental: a PAT issued with a narrow scope set keeps only those scopes —
	// the issuer never silently copies the user's live roles or any broader authority.
	t.Run("IC-1 PAT: narrow scope set is preserved exactly (no silent role copy)", func(t *testing.T) {
		svc, _ := newIssueKeyService(t)
		userID := uuid.Must(uuid.NewV7())

		narrowScopes := []string{"repo:read"}

		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, userID, tokens.Claims[MyCustomClaims]{
			TenantID: tenant,
			Scopes:   narrowScopes,
			// Simulate a user with wider privileges: the issuer must not propagate these
			// roles onto the key's effective authority.
			Roles: []string{"admin", "owner"},
		})
		require.NoError(t, err)
		require.NotNil(t, key)

		actor, claims, err := svc.VerifyAPIKeyActor(ctx, tenant, key.Token)
		require.NoError(t, err)
		require.NotNil(t, claims)

		assert.Equal(t, narrowScopes, actor.Scopes,
			"Actor.Scopes must be exactly the issued scopes — the user's broader roles must not be copied")
		assert.Equal(t, narrowScopes, claims.Scopes,
			"claims.Scopes must be exactly the issued scopes")
		assert.NotContains(t, actor.Scopes, "admin",
			"the user's admin role must never appear as a scope on the issued key")

		// Sanity: the issued roles round-trip unchanged (SC-3 only forbids silent copying;
		// explicitly issued roles are carried verbatim).
		assert.Equal(t, []string{"admin", "owner"}, claims.Roles,
			"roles explicitly set at issuance must round-trip unchanged")
	})
}
