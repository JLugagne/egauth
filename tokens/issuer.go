package tokens

import (
	"context"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/google/uuid"
)

// Issuer is responsible for generating tokens and API keys.
type Issuer[C any] interface {
	// IssueTokenPair generates a new Access and Refresh token pair for the given claims.
	IssueTokenPair(ctx context.Context, claims Claims[C]) (*TokenPair[C], error)

	// IssueAPIKey generates a new API key of the given type, attributed to the human user
	// createdBy, with the authority (scopes/roles/audiences) carried verbatim on claims. The
	// issuer never copies the creating user's stored roles. For KeyTypeService the resulting
	// Claims.Subject is the key's own ID (a machine identity); for KeyTypePAT it is the user
	// supplied on claims.Subject.
	IssueAPIKey(ctx context.Context, prefix string, keyType KeyType, createdBy uuid.UUID, claims Claims[C]) (*APIKey[C], error)
}

// AccessTokenIssuer is the OPTIONAL extension of Issuer that mints a STANDALONE access token: no
// refresh token is generated and NO refresh-token family is persisted. It exists for credentials
// that must not be renewable — notably the PRE-STEP-UP interim credential of an MFA-gated login
// (see Claims.Interim and Claims.AsInterim), where minting a full pair would persist a
// full-RefreshTTL refresh row for a token that is deliberately discarded.
//
// Implementing it is optional and backward-compatible: egauth type-asserts for it and falls back to
// IssueTokenPair (discarding the refresh half) when an Issuer does not implement it.
// jwt.Service implements it.
type AccessTokenIssuer[C any] interface {
	// IssueAccessToken signs a standalone access token for claims and returns it with its expiry.
	// Claims.ExpiresAt, when non-zero, overrides the issuer's configured access TTL.
	IssueAccessToken(ctx context.Context, claims Claims[C]) (token string, expiresAt time.Time, err error)
}

// Verifier is responsible for validating tokens and extracting their claims.
type Verifier[C any] interface {
	// VerifyAccessTokenForTenant parses and validates an access token and binds it to
	// tenantID, failing closed with ErrTenantMismatch unless the token's signed tenant_id
	// claim equals tenantID. This is the tenant-aware entry point multi-tenant callers
	// (and the HTTP middleware, once a tenant resolver is configured) MUST use so a token
	// minted for one tenant cannot be replayed in another under a shared signing key.
	// Single-tenant callers pass "" (the default partition), which is equivalent to
	// VerifyAccessToken for tokens issued under the empty tenant.
	VerifyAccessTokenForTenant(ctx context.Context, tenantID string, token string) (*Claims[C], error)
	// VerifyRefreshToken validates a refresh token against the store and returns its claims.
	// tenantID scopes the store lookup: the token is resolved only within that tenant's
	// partition, so a token saved under a real tenant must be verified with the matching
	// tenantID. Single-tenant callers pass "" (the default partition).
	VerifyRefreshToken(ctx context.Context, tenantID string, token string) (*Claims[C], error)
	// VerifyAPIKey validates an API key against the store and returns its claims.
	// tenantID scopes the store lookup: the key is resolved only within that tenant's
	// partition, so a key saved under a real tenant must be verified with the matching
	// tenantID. Single-tenant callers pass "" (the default partition).
	//
	// An optional event.RequestContext supplies the client IP / User-Agent that egauth then
	// records in Event.Attrs on the resulting api_key.auth.succeeded / api_key.auth.failed
	// events; omitting it omits those attributes. Only the last supplied context is used.
	VerifyAPIKey(ctx context.Context, tenantID string, key string, rc ...event.RequestContext) (*Claims[C], error)
}
