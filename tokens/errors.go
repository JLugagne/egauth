package tokens

import "errors"

var (
	// ErrInvalidToken is returned when a token is malformed, missing, or cryptographically invalid.
	ErrInvalidToken = errors.New("tokens: invalid token")

	// ErrTokenExpired is returned when a token is valid but its expiration time has passed.
	ErrTokenExpired = errors.New("tokens: token expired")

	// ErrInvalidClaims is returned when a token's claims do not meet the expected structure or rules.
	ErrInvalidClaims = errors.New("tokens: invalid claims")

	// ErrAPIKeyNotFound is returned when an API key cannot be found by its hash.
	ErrAPIKeyNotFound = errors.New("tokens: api key not found")

	// ErrRefreshTokenNotFound is returned when a refresh token cannot be found by its hash.
	ErrRefreshTokenNotFound = errors.New("tokens: refresh token not found")

	// ErrRefreshTokenReused is returned when an already-consumed refresh token is presented again,
	// which indicates a possible token theft (replay) and should trigger family revocation.
	ErrRefreshTokenReused = errors.New("tokens: refresh token reused")

	// ErrNoClaimsProvider is returned by Rotate when the issuer was constructed without a
	// ClaimsProvider, which is required to resolve fresh claims during refresh-token rotation.
	ErrNoClaimsProvider = errors.New("tokens: no claims provider configured for rotation")

	// ErrTenantMismatch is returned by a Save* operation when the record already carries a
	// non-empty TenantID that differs from the tenantID argument passed to the call.
	ErrTenantMismatch = errors.New("tokens: tenant ID mismatch")
)
