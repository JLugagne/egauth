package tokens

import "errors"

var (
	// ErrInvalidRecord reports a record or request that NewRefreshRecord, RestoreRefreshRecord or
	// APIKey.Validate refuses; stores return it instead of persisting a malformed record.
	ErrInvalidRecord = errors.New("tokens: invalid record")
	// ErrLifetimeExceeded reports a refresh token that would be issued at or after the absolute end
	// of its lineage (CreatedAt + MaxLifetime).
	ErrLifetimeExceeded = errors.New("tokens: lineage lifetime exceeded")
	// ErrReused reports a consumed refresh token presented again outside the benign race of
	// ReuseGrace; the store has already revoked the whole family.
	ErrReused = errors.New("tokens: refresh token reused, family revoked")
	// ErrConcurrent reports a consumed refresh token presented again within ReuseGrace by the
	// client that consumed it: nothing is issued and the family stays live.
	ErrConcurrent = errors.New("tokens: refresh token already rotated by this client")
	// ErrRevoked reports a refresh token whose family is revoked or past its absolute expiry.
	ErrRevoked = errors.New("tokens: family revoked")
)
