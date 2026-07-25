package pgx_test

import (
	pgx "github.com/JLugagne/egauth/adapters/pgx/mfa"
	"github.com/JLugagne/egauth/health"
)

// Compile-time assertion that the pgx Store satisfies the optional health.Pinger seam (N11).
// Runtime connectivity behavior is covered by sessions/pgx (the behavior is identical here).
var _ health.Pinger = (*pgx.Store)(nil)
