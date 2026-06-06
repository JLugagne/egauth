package tokens

import (
	"context"

	"github.com/google/uuid"
)

// Store defines the persistence interface for Refresh Tokens and API Keys.
//
// STABILITY: Store is intentionally monolithic for v0.x — it will NOT be split into a
// core+capability set of interfaces before v1. Methods MAY be added in minor releases
// without a major version bump. External implementers MUST run the conformance suite at
// github.com/JLugagne/egauth/tokens/storetest on every upgrade to catch newly-required
// methods before they silently break an auth flow. (A core+capability split is deferred
// to v1, when the surface has stabilised and external adoption makes the churn cost worth
// weighing.)
//
// It stores ONLY the hash of the tokens to ensure security at rest.
//
// Every operation is scoped to a tenant via a mandatory tenantID argument. An empty
// string is a legal tenant key (the single-tenant default partition); it must still be
// passed explicitly.
type Store[C any] interface {
	// SaveRefreshToken persists a refresh token record (storing only its hash). If the
	// record already carries a non-empty TenantID that differs from tenantID, it returns
	// ErrTenantMismatch.
	SaveRefreshToken(ctx context.Context, tenantID string, rt *RefreshToken) error

	// FindRefreshToken retrieves a refresh token by its hash, including its ConsumedAt state.
	FindRefreshToken(ctx context.Context, tenantID string, tokenHash string) (*RefreshToken, error)

	// ConsumeRefreshToken atomically marks a refresh token as consumed (single-use).
	// It returns ErrRefreshTokenNotFound if the token does not exist (in the tenant),
	// and ErrRefreshTokenReused if it exists but was already consumed (replay detection).
	ConsumeRefreshToken(ctx context.Context, tenantID string, tokenHash string) error

	// RevokeRefreshToken deletes/revokes a single refresh token by its hash.
	RevokeRefreshToken(ctx context.Context, tenantID string, tokenHash string) error

	// RevokeFamily revokes ALL refresh tokens sharing the given family ID.
	RevokeFamily(ctx context.Context, tenantID string, familyID uuid.UUID) error

	// SaveAPIKey persists an API key. If the key already carries a non-empty TenantID that
	// differs from tenantID, it returns ErrTenantMismatch.
	SaveAPIKey(ctx context.Context, tenantID string, key *APIKey[C]) error

	// FindAPIKeyByHash retrieves an API key by its hash.
	FindAPIKeyByHash(ctx context.Context, tenantID string, tokenHash string) (*APIKey[C], error)

	// DeleteExpired purges expired records (refresh tokens and any API keys past their expiry)
	// within the given tenant, returning the number deleted. It is the schedulable GC reaper:
	// refresh-token rows are retained past consumption for reuse/theft detection, so they
	// accumulate and must be swept once expired. API keys with no expiry are never touched.
	// It scopes to a single tenant; a background job sweeping every tenant must loop over them.
	// Run it periodically (e.g. hourly) from a background job.
	//
	// Reaping only removes rows past their expiry, so an expired token can no longer be validated
	// or rotated and a replay WITHIN a token's validity is still detected as reuse (the family is
	// revoked). The one thing given up is the late alarm: a replay of an ALREADY-EXPIRED consumed
	// token reports not-found rather than revoking the family — acceptable, since by then the
	// token grants no access. Keeping consumed rows until their whole family expired would defeat
	// the GC for long-lived, continuously-rotating sessions, so the reaper trades that late
	// signal for bounded growth.
	DeleteExpired(ctx context.Context, tenantID string) (int64, error)
}
