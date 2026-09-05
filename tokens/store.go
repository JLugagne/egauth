package tokens

import (
	"context"

	"github.com/google/uuid"
)

// Store defines the persistence interface for Refresh Tokens and API Keys.
//
// It is the composition of the RefreshTokenStore (rotating refresh tokens and their families),
// the APIKeyStore[C] (long-lived API keys, generic over the custom-claims type C) and the optional
// TokenReaper (the schedulable expired-record sweep that only a background job calls). Segmenting
// the contract this way means a future v1.x capability can ship as a NEW optional interface —
// implementers type-assert for it — rather than as a method on this interface, which would break
// every external Store. Both the in-memory and pgx stores implement the whole Store.
//
// It stores ONLY the hash of the tokens to ensure security at rest.
//
// Every operation is scoped to a tenant via a mandatory tenantID argument. An empty
// string is a legal tenant key (the single-tenant default partition); it must still be
// passed explicitly.
type Store[C any] interface {
	RefreshTokenStore
	APIKeyStore[C]
	TokenReaper
}

// RefreshTokenStore is the refresh-token capability of a tokens backend: persisting, looking up,
// single-use-consuming and revoking the rotating refresh tokens (and their families) that back
// long-lived sessions. It is independent of the custom-claims type C.
type RefreshTokenStore interface {
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

	// RevokeAllRefreshTokensForUser revokes EVERY refresh token belonging to userID within
	// tenantID, across all families — the "kill every session this user holds" primitive used
	// when an account is disabled. It is idempotent: a user with no live refresh tokens is a
	// no-op that returns nil (never ErrRefreshTokenNotFound).
	RevokeAllRefreshTokensForUser(ctx context.Context, tenantID string, userID uuid.UUID) error
}

// AtomicRefreshTokenRotator is an optional capability interface for stores that support
// atomically consuming an old refresh token and persisting its successor in a single transaction.
type AtomicRefreshTokenRotator interface {
	RotateRefreshToken(ctx context.Context, tenantID string, oldTokenHash string, newRT *RefreshToken) error
}

// APIKeyStore is the API-key capability of a tokens backend, generic over the custom-claims type C
// carried by each key.
type APIKeyStore[C any] interface {
	// SaveAPIKey persists an API key. If the key already carries a non-empty TenantID that
	// differs from tenantID, it returns ErrTenantMismatch.
	SaveAPIKey(ctx context.Context, tenantID string, key *APIKey[C]) error

	// FindAPIKeyByHash retrieves an API key by its hash. A soft-revoked key is STILL returned,
	// with its RevokedAt populated; the verify layer decides whether to reject it.
	FindAPIKeyByHash(ctx context.Context, tenantID string, tokenHash string) (*APIKey[C], error)

	// RevokeAPIKey soft-revokes the API key identified by keyID within tenantID by stamping its
	// RevokedAt. A missing key returns ErrAPIKeyNotFound; a key that belongs to a different
	// tenant is treated as missing and also returns ErrAPIKeyNotFound. Revoking an
	// already-revoked key is a no-op and returns nil (RevokedAt is not advanced). Revocation is
	// by ID, never by hash, because the clear-text token is unrecoverable by design. The store
	// stays policy-free: it only stamps RevokedAt and FindAPIKeyByHash continues to return the
	// revoked key with RevokedAt set.
	RevokeAPIKey(ctx context.Context, tenantID string, keyID uuid.UUID) error

	// ListAPIKeysByCreator returns every API key — active and revoked — created by createdBy
	// within tenantID. The Token field is always blank because the clear-text value exists only
	// at creation. It returns an empty (non-nil) slice when the creator has no keys, never
	// ErrAPIKeyNotFound.
	ListAPIKeysByCreator(ctx context.Context, tenantID string, createdBy uuid.UUID) ([]*APIKey[C], error)

	// RevokeAllAPIKeysForUser soft-revokes EVERY API key created by userID within tenantID by
	// stamping RevokedAt on each still-active key, mirroring RevokeAPIKey's soft-revoke semantics
	// (revoked keys remain visible to ListAPIKeysByCreator with RevokedAt set). It is the
	// "kill every key this user issued" primitive used when an account is disabled. It is
	// idempotent: a user with no keys, or whose keys are already revoked, is a no-op returning nil
	// (never ErrAPIKeyNotFound). Already-revoked keys keep their original RevokedAt.
	RevokeAllAPIKeysForUser(ctx context.Context, tenantID string, userID uuid.UUID) error
}

// TokenReaper is the optional GC capability of a tokens backend: the schedulable sweep that purges
// expired refresh tokens and API keys. It is separated from the core stores because the request
// path never calls it — only a background job does. The full Store composes RefreshTokenStore +
// APIKeyStore + TokenReaper; both the in-memory and pgx stores implement the whole Store.
type TokenReaper interface {
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
