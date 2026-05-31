package pgx_test

import (
	"github.com/JLugagne/libauth/health"
	"github.com/JLugagne/libauth/tokens/pgx"
)

// Compile-time assertion that the pgx Store satisfies the optional health.Pinger seam (N11).
// Runtime connectivity behavior is covered by sessions/pgx (the behavior is identical here).
var _ health.Pinger = (*pgx.Store[struct{}])(nil)
