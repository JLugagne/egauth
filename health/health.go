// Package health defines the optional health-check seam implemented by egauth's pgx-backed
// stores, so readiness/liveness probes can be written against any store without depending on a
// specific backend or holding a separate handle to the underlying connection pool.
//
// # Stability
//
// Stability class: frozen-v1 candidate. The exported API is intended to remain
// backward-compatible for the life of v1; breaking changes require a new major version. Until v1
// is tagged the API remains pre-1.0. See docs/adr/0001-v1-scope-and-stability-classes.md.
package health

import "context"

// Pinger is implemented by stores that can report backend connectivity. The pgx Store in each
// module satisfies it (via a lightweight round-trip query); the in-memory stores do not, since
// they have no external dependency that can be unhealthy. Probe a store with a type assertion:
//
//	if p, ok := store.(health.Pinger); ok {
//		if err := p.Ping(ctx); err != nil { /* report not-ready */ }
//	}
type Pinger interface {
	// Ping verifies the store can reach its backend, returning a non-nil error when it cannot.
	// It honors ctx for cancellation/deadline.
	Ping(ctx context.Context) error
}
