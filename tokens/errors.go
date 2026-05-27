package tokens

import "errors"

var (
	// ErrInvalidToken is returned when a token is malformed, missing, or cryptographically invalid.
	ErrInvalidToken = errors.New("invalid token")

	// ErrTokenExpired is returned when a token is valid but its expiration time has passed.
	ErrTokenExpired = errors.New("token expired")

	// ErrInvalidClaims is returned when a token's claims do not meet the expected structure or rules.
	ErrInvalidClaims = errors.New("invalid claims")
)
