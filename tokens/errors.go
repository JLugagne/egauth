package tokens

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidToken is returned when a token is malformed, missing, or cryptographically invalid.
	ErrInvalidToken = errors.New("tokens: invalid token")

	// ErrTokenExpired is returned when a token is valid but its expiration time has passed.
	ErrTokenExpired = errors.New("tokens: token expired")

	// ErrInvalidClaims is returned when a token's claims do not meet the expected structure or rules.
	ErrInvalidClaims = errors.New("tokens: invalid claims")

	// ErrAPIKeyNotFound is returned when an API key cannot be found by its hash.
	ErrAPIKeyNotFound = errors.New("tokens: api key not found")

	// ErrAPIKeyRevoked is returned by the verify layer when an API key has been soft-revoked
	// (its RevokedAt is set). The store itself does not return this error: it returns the
	// revoked key with RevokedAt populated and leaves the policy decision to the verify layer.
	ErrAPIKeyRevoked = errors.New("tokens: api key revoked")

	// ErrRefreshTokenNotFound is returned when a refresh token cannot be found by its hash.
	ErrRefreshTokenNotFound = errors.New("tokens: refresh token not found")

	// ErrRefreshTokenReused is returned when an already-consumed refresh token is presented again,
	// which indicates a possible token theft (replay) and should trigger family revocation.
	ErrRefreshTokenReused = errors.New("tokens: refresh token reused")

	// ErrRefreshConcurrent is returned by Rotate for the benign concurrency cases — a replay of a
	// just-consumed token within the reuse grace window, or losing the atomic consume race to a
	// parallel in-flight rotation of the same not-yet-consumed token (parallel tabs, prefetch,
	// concurrent sub-resource loads racing the same cookie). The rotation family is explicitly NOT
	// poisoned in these cases: the winning request already minted a fresh, valid cookie pair. It
	// wraps ErrRefreshTokenReused so existing errors.Is(err, ErrRefreshTokenReused) checks (e.g.
	// error-code mapping) keep working, while letting cookie-clearing callers (RequireAuth,
	// RefreshHandler) preserve the winner's freshly issued refresh cookie instead of logging the
	// user out — the very lockout the grace period exists to prevent.
	ErrRefreshConcurrent = fmt.Errorf("%w: concurrent rotation within grace", ErrRefreshTokenReused)

	// ErrNoClaimsProvider is returned by Rotate when the issuer was constructed without a
	// ClaimsProvider, which is required to resolve fresh claims during refresh-token rotation.
	ErrNoClaimsProvider = errors.New("tokens: no claims provider configured for rotation")

	// ErrTenantMismatch is returned by a Save* operation when the record already carries a
	// non-empty TenantID that differs from the tenantID argument passed to the call.
	ErrTenantMismatch = errors.New("tokens: tenant ID mismatch")

	// ErrInvalidPrincipalType is returned when an API key is issued with an empty or unsupported principal type.
	ErrInvalidPrincipalType = errors.New("tokens: invalid principal type")
)
